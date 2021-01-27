package sniffer

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"wirerat/cmd/internal/device"
)

func Sniff(iface *net.Interface) error {
	var (
		buffer = int32(65536)
		filter string
		//filter = "tcp and port 8080"
		//filter = "dst port 5432"
	)

	reader := bufio.NewReader(os.Stdin)
	// see https://www.tcpdump.org/manpages/pcap-filter.7.html
	fmt.Println(colorBlue, "Type pcap filter:", colorReset)
	filter, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	if !device.Exists(iface.Name) {
		return fmt.Errorf("unable to open device: %#v", iface)
	}

	handler, err := pcap.OpenLive(iface.Name, buffer, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handler.Close()

	if err = handler.SetBPFFilter(filter); err != nil {
		return err
	}

	fmt.Println(colorRed, "LISTEN...", colorReset)
	fmt.Println()

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		harvestTCPCreds(packet)
	}

	fmt.Println("Done...")

	return nil
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
