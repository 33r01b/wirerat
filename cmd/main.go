package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var containerNets []Container

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}

	containerNets = containers()

	for i, container := range containerNets {
		if container.Gateway == "" {
			continue
		}
		//fmt.Printf("%+v\n", container.Names)
		iface, err := findIfaceByIPV4(&ifaces, container.Gateway + "/16")
		if err != nil {
			panic(err)
		}

		containerNets[i].Interface = &iface

		fmt.Printf("[%d] \n name: %+v\n iface: %#v\n", i, container.Names, iface)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Choose container by name: ")
	index, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	containerIdx, err := strconv.ParseInt(strings.TrimSpace(index), 10, 64)
	if err != nil {
		panic(err)
	}

	// TODO use only filtered containers
	if containerIdx > int64(len(containerNets)) {
		panic("Container not found")
	}

	selectedContainer := containerNets[containerIdx]

	fmt.Print("\n\n")
	fmt.Printf("DONE!\n %#v", selectedContainer)


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

	containerNets := make([]Container, len(containers))

	for _, container := range containers {
		nets := container.NetworkSettings.Networks[container.HostConfig.NetworkMode]
		if nets != nil {
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
