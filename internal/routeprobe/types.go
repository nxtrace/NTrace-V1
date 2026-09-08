package routeprobe

import (
	"errors"
	"net"
)

var ErrNoRoute = errors.New("system reported no usable route")

type Request struct {
	Method                string
	DstIP                 net.IP
	SrcAddr, SourceDevice string
	SrcPort, DstPort, TOS int
	FWMark                uint32
	FWMarkSet             bool
	// HeaderIncluded selects the Linux IPv4 IP_HDRINCL route lookup, whose
	// kernel protocol is IPPROTO_RAW regardless of the serialized IP header.
	HeaderIncluded bool
}

type Route struct {
	Interface, Gateway, Source, Limitations, Incomplete string
	OnLink                                              bool
}
