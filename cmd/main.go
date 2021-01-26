package main

import (
	"context"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/manifoldco/promptui"
	"log"
	"net"
	"strings"
)

const ContainersIpv4Mask string = "/16"

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}

	containerNets := containers()
	containersNames := make([]string, 0, len(containerNets))

	for i, container := range containerNets {
		//fmt.Printf("%+v\n", container.Names)
		iface, err := findIfaceByIPV4(&ifaces, container.Gateway + ContainersIpv4Mask)
		if err != nil {
			panic(err)
		}

		containerNets[i].Interface = &iface
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

	if index > len(containerNets) {
		panic("Container not found")
	}

	selectedContainer := containerNets[int64(index)]

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

func containers() []Container {
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
		//filter = "tcp and port 8880"
	)

	if !deviceExists(iface.Name) {
		log.Fatal("Unable to open device ", iface)
	}

	// TODO read about buffer
	handler, err := pcap.OpenLive(iface.Name, buffer, false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	//if err := handler.SetBPFFilter(filter); err != nil {
	//	log.Fatal(err)
	//}

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		harvestFTPCreds(packet)
	}

	fmt.Println("Done...")
}

func harvestFTPCreds(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		dst := packet.NetworkLayer().NetworkFlow().Dst()
		port := packet.TransportLayer().TransportFlow().Dst()
		src := packet.NetworkLayer().NetworkFlow().Src()
		sport := packet.TransportLayer().TransportFlow().Src()

		spew.Dump(string(payload))

		// TODO add filters
		//if dst.String() != "127.0.0.1" {
		//	return
		//}

		//// TODO add filters
		//if !bytes.Contains(payload, []byte("SELECT")) {
		//	return
		//}

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
