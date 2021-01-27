package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
)

type Packet struct {
	Src   Address
	Dst   Address
	Count int64
	Body  []byte
}

type Address struct {
	host gopacket.Endpoint
	port gopacket.Endpoint
}

func (a *Address) Host() gopacket.Endpoint {
	return a.host
}

func (a *Address) Port() gopacket.Endpoint {
	return a.port
}

func (a Address) String() string {
	return fmt.Sprintf("%s:%s", a.host, a.port)
}
