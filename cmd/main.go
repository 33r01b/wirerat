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
	"math"
	"net"
	"os"
	"strings"
)

const ContainersIpv4Mask = "/16"
const colorReset = "\033[0m"
const colorRed = "\033[31m"
const colorGreen = "\033[32m"
const colorYellow = "\033[33m"
const colorBlue = "\033[34m"
const colorPurple = "\033[35m"
const colorCyan = "\033[36m"
const colorWhite = "\033[37m"

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

func sniff(iface *net.Interface) {
	var (
		//buffer = int32(65536)
		filter string
		//filter = "tcp and port 8080"
		//filter = "dst port 5432"
	)

	reader := bufio.NewReader(os.Stdin)
	// see https://www.tcpdump.org/manpages/pcap-filter.7.html
	fmt.Println(string(colorBlue),"Type pcap filter:", string(colorReset))
	filter, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	if !deviceExists(iface.Name) {
		log.Fatal("Unable to open device ", iface)
	}

	handler, err := pcap.OpenLive(iface.Name, math.MaxInt32, false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(colorRed), "LISTEN...", string(colorReset))
	fmt.Println()

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		harvestTCPCreds(packet)
	}

	fmt.Println("Done...")
}

func harvestTCPCreds(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app != nil {
		pack := Packet{
			Src:   Address{
				host: packet.NetworkLayer().NetworkFlow().Src(),
				port: packet.TransportLayer().TransportFlow().Src(),
			},
			Dst:   Address{
				host: packet.NetworkLayer().NetworkFlow().Dst(),
				port: packet.TransportLayer().TransportFlow().Dst(),
			},
			Count: 1,
			Body:  app.Payload(),
		}

		route := fmt.Sprintf(
			"%s%s:%s%s => %s%s:%s%s",
			colorCyan,
			pack.Src.Host(),
			pack.Src.Port(),
			colorReset,
			colorPurple,
			pack.Dst.Host(),
			pack.Dst.Port(),
			colorReset,
		)

		fmt.Printf("%v\n", route)
		fmt.Println(colorGreen)
		fmt.Printf("Len: %d\n", len(pack.Body))
		//fmt.Printf("Src: %s\n", pack.Src)
		//fmt.Printf("Dst: %s\n", pack.Dst)
		fmt.Println("Body:\n",colorReset)
		fmt.Printf("%s\n\n", string(pack.Body))
	}
}

type Address struct {
	host gopacket.Endpoint
	port gopacket.Endpoint
}

func (a Address) String() string {
	return fmt.Sprintf("%s:%s", a.host, a.port)
}

func (a *Address) Host() gopacket.Endpoint {
	return a.host
}

func (a *Address) Port() gopacket.Endpoint {
	return a.port
}

type Packet struct {
	Src   Address
	Dst   Address
	Count int64
	Body  []byte
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
