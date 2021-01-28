package dock

import (
	"context"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/manifoldco/promptui"
	"net"
	"strings"
	"wirerat/cmd/internal/device"
)

const ContainersIpv4Mask = "/16"

type Container struct {
	Names     []string
	Gateway   string
	Interface *net.Interface
}

func SelectContainer(ctx context.Context) (container *Container, err error) {
	containers, err := FindContainers(ctx)
	if err != nil {
		return
	}

	containersNames := make([]string, 0, len(containers))
	for _, cont := range containers {
		containersNames = append(containersNames, strings.Join(cont.Names, ","))
	}

	prompt := promptui.Select{
		Label: "Choose container by name",
		Items: containersNames,
		Size: 10,
	}

	index, _, err := prompt.Run()

	if err != nil {
		return
	}

	if index > len(containers) {
		err = errors.New("container not found")
		return
	}

	container = containers[index]

	return
}

func FindContainers(ctx context.Context) (containers []*Container, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		err = fmt.Errorf("localAddresses: %+v\n", err.Error())
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return
	}

	availableContainers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return
	}

	containers = make([]*Container, 0, len(availableContainers))

	for _, container := range availableContainers {
		nets := container.NetworkSettings.Networks[container.HostConfig.NetworkMode]

		if nets != nil && nets.Gateway != "" {
			iface, err := device.FindIfaceByIPV4(&ifaces, nets.Gateway + ContainersIpv4Mask)
			if err != nil {
				return nil, err
			}

			containers = append(containers, &Container{
				Names: container.Names,
				Gateway: nets.Gateway,
				Interface: &iface,
			})
		}
	}

	return containers, nil
}