package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/manifoldco/promptui"
	"log"
	"net"
	"os"
	"strings"
)

const ContainersIpv4Mask string = "/16"

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}

	dockerContainers := getDockerContainers()
	containersNames := make([]string, 0, len(dockerContainers))

	for i, container := range dockerContainers {
		iface, err := findIfaceByIPV4(&ifaces, container.Gateway + ContainersIpv4Mask)
		if err != nil {
			panic(err)
		}

		dockerContainers[i].Interface = &iface
		containersNames = append(containersNames, strings.Join(container.Names, ","))
	}

	prompt := promptui.Select{
		Label: "Choose container by name",
		Items: containersNames,
		Size: 10,
	}

	index, _, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	if index > len(dockerContainers) {
		panic("Container not found")
	}

	selectedContainer := dockerContainers[int64(index)]

	fmt.Printf("Names: %s\n", strings.Join(selectedContainer.Names, ","))
	fmt.Printf("Gateway: %v\n", selectedContainer.Gateway)
	fmt.Printf("LISTEN...\n\n")

	sniff(selectedContainer.Interface)
}

func findIfaceByIPV4(ifaces *[]net.Interface, ipV4 string) (iface net.Interface, err error) {
	for _, i := range *ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}

		for _, a := range addrs {
			if a.String() == ipV4 {
				return i, nil
			}
		}
	}

	return iface, fmt.Errorf("interface not found")
}

type Container struct {
	Names     []string
	Gateway   string
	Interface *net.Interface
}

func getDockerContainers() []Container {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		panic(err)
	}

	containerNets := make([]Container, 0, len(containers))

	for _, container := range containers {
		nets := container.NetworkSettings.Networks[container.HostConfig.NetworkMode]

		if nets != nil && nets.Gateway != "" {
			containerNets = append(containerNets, Container{Names: container.Names, Gateway: nets.Gateway})
		}
	}

	return containerNets
}

var dist = make(map[string]map[string]int64)

func sniff(iface *net.Interface) {
	var (
		buffer = int32(1600)
		filter string
		//filter = "tcp and port 8080"
		//filter = "dst port 5432"
	)

	reader := bufio.NewReader(os.Stdin)
	// see https://www.tcpdump.org/manpages/pcap-filter.7.html
	fmt.Println("Type pcap filter:")
	filter, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	if !deviceExists(iface.Name) {
		log.Fatal("Unable to open device ", iface)
	}

	handler, err := pcap.OpenLive(iface.Name, buffer, false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		harvestTCPCreds(packet)
	}

	fmt.Println("Done...")
}

func harvestTCPCreds(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		dst := packet.NetworkLayer().NetworkFlow().Dst()
		port := packet.TransportLayer().TransportFlow().Dst()
		src := packet.NetworkLayer().NetworkFlow().Src()
		sport := packet.TransportLayer().TransportFlow().Src()

		fmt.Printf("%s\n", payload)

		//// TODO add grep
		//if !bytes.Contains(payload, []byte("SELECT")) {
		//	return
		//}

		// TODO group by src AND dst
		ds := fmt.Sprintf("%v:%v", dst, port)
		sr := fmt.Sprintf("%v:%v", src, sport)

		if _, ok := dist[ds]; ok {
			dist[ds][sr] = dist[ds][sr] + 1
		} else {
			dist[ds] = map[string]int64{
				sr: 1,
			}
		}

		fmt.Printf("%+v\n\n", dist)
	}
}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}
