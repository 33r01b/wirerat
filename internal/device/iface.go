package device

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

func FindIfaceByIPV4(ifaces *[]net.Interface, ipV4 string) (iface net.Interface, err error) {
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

func Exists(name string) bool {
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
