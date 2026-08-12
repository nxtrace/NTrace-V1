package internal

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/nxtrace/NTrace-core/util"
)

type ICMPResponseKind uint8

const (
	ICMPResponseUnknown ICMPResponseKind = iota
	ICMPResponseTransit
	ICMPResponseEchoReply
	ICMPResponsePortUnreachable
	ICMPResponseUnreachable
)

type ICMPResponse struct {
	Kind   ICMPResponseKind
	Marker string
}

func parseSocketICMPMessage(ipVersion int, raw []byte) (*icmp.Message, bool) {
	protocol := 1
	if ipVersion == 6 {
		protocol = 58
	}
	rm, err := icmp.ParseMessage(protocol, raw)
	if err != nil {
		return nil, false
	}
	return rm, true
}

func matchSocketICMPEchoReply(ipVersion int, rm *icmp.Message, echoID int) (int, bool) {
	if !isSocketICMPEchoReply(ipVersion, rm) {
		return 0, false
	}
	echo, ok := rm.Body.(*icmp.Echo)
	if !ok || echo == nil || echo.ID != echoID {
		return 0, false
	}
	return echo.Seq, true
}

func classifySocketICMPResponse(ipVersion int, rm *icmp.Message, raw []byte) ICMPResponse {
	if rm == nil {
		return ICMPResponse{}
	}

	typeID, ok := icmpTypeID(rm.Type)
	if !ok {
		return ICMPResponse{}
	}

	info := 0
	if ipVersion == 4 && typeID == 3 && rm.Code == 4 && len(raw) >= 8 {
		info = int(binary.BigEndian.Uint16(raw[6:8]))
	}
	if body, ok := rm.Body.(*icmp.PacketTooBig); ok && body != nil {
		info = body.MTU
	}
	return classifyICMPResponse(ipVersion, typeID, rm.Code, info)
}

func classifyICMPResponse(ipVersion, typeID, code, info int) ICMPResponse {
	response := ICMPResponse{}
	switch ipVersion {
	case 4:
		switch {
		case typeID == 0:
			response.Kind = ICMPResponseEchoReply
		case typeID == 11 && code == 0:
			response.Kind = ICMPResponseTransit
		case typeID == 3 && code == 3:
			response.Kind = ICMPResponsePortUnreachable
		case typeID == 3:
			response.Kind = ICMPResponseUnreachable
			response.Marker = ipv4UnreachableMarker(code, info)
		default:
			response.Kind = ICMPResponseUnreachable
			response.Marker = fmt.Sprintf("!<%d-%d>", typeID, code)
		}
	case 6:
		switch {
		case typeID == 129:
			response.Kind = ICMPResponseEchoReply
		case typeID == 3 && code == 0:
			response.Kind = ICMPResponseTransit
		case typeID == 1 && code == 4:
			response.Kind = ICMPResponsePortUnreachable
		case typeID == 1:
			response.Kind = ICMPResponseUnreachable
			response.Marker = ipv6UnreachableMarker(code)
		case typeID == 2:
			response.Kind = ICMPResponseUnreachable
			response.Marker = fragmentationMarker(info)
		default:
			response.Kind = ICMPResponseUnreachable
			response.Marker = fmt.Sprintf("!<%d-%d>", typeID, code)
		}
	}
	return response
}

func icmpTypeID(messageType icmp.Type) (int, bool) {
	switch value := messageType.(type) {
	case ipv4.ICMPType:
		return int(value), true
	case ipv6.ICMPType:
		return int(value), true
	default:
		return 0, false
	}
}

func ipv4UnreachableMarker(code, info int) string {
	switch code {
	case 0, 6, 8, 11:
		return "!N"
	case 1, 7, 12:
		return "!H"
	case 2:
		return "!P"
	case 4:
		return fragmentationMarker(info)
	case 5:
		return "!S"
	case 9, 10, 13:
		return "!X"
	case 14:
		return "!V"
	case 15:
		return "!C"
	default:
		return fmt.Sprintf("!<%d>", code)
	}
}

func ipv6UnreachableMarker(code int) string {
	switch code {
	case 0:
		return "!N"
	case 1:
		return "!X"
	case 2, 3:
		return "!H"
	default:
		return fmt.Sprintf("!<%d>", code)
	}
}

func fragmentationMarker(mtu int) string {
	return fmt.Sprintf("!F-%d", mtu)
}

func isSocketICMPEchoReply(ipVersion int, rm *icmp.Message) bool {
	switch ipVersion {
	case 4:
		return rm.Type == ipv4.ICMPTypeEchoReply
	case 6:
		return rm.Type == ipv6.ICMPTypeEchoReply
	default:
		return false
	}
}

func extractSocketICMPPayload(ipVersion int, rm *icmp.Message, dstIP net.IP) ([]byte, bool) {
	data, ok := extractSocketICMPErrorBody(ipVersion, rm)
	if !ok || !matchesEmbeddedDstIP(ipVersion, data, dstIP) {
		return nil, false
	}
	return data, true
}

func extractSocketICMPErrorBody(ipVersion int, rm *icmp.Message) ([]byte, bool) {
	switch ipVersion {
	case 4:
		return extractSocketICMPv4Body(rm)
	case 6:
		return extractSocketICMPv6Body(rm)
	default:
		return nil, false
	}
}

func extractSocketICMPv4Body(rm *icmp.Message) ([]byte, bool) {
	switch rm.Type {
	case ipv4.ICMPTypeTimeExceeded:
		body, ok := rm.Body.(*icmp.TimeExceeded)
		return icmpTimeExceededData(body, ok)
	case ipv4.ICMPTypeDestinationUnreachable:
		body, ok := rm.Body.(*icmp.DstUnreach)
		return icmpDstUnreachData(body, ok)
	case ipv4.ICMPTypeParameterProblem:
		body, ok := rm.Body.(*icmp.ParamProb)
		return icmpParamProbData(body, ok)
	default:
		return nil, false
	}
}

func extractSocketICMPv6Body(rm *icmp.Message) ([]byte, bool) {
	switch rm.Type {
	case ipv6.ICMPTypeTimeExceeded:
		body, ok := rm.Body.(*icmp.TimeExceeded)
		return icmpTimeExceededData(body, ok)
	case ipv6.ICMPTypePacketTooBig:
		body, ok := rm.Body.(*icmp.PacketTooBig)
		return icmpPacketTooBigData(body, ok)
	case ipv6.ICMPTypeDestinationUnreachable:
		body, ok := rm.Body.(*icmp.DstUnreach)
		return icmpDstUnreachData(body, ok)
	case ipv6.ICMPTypeParameterProblem:
		body, ok := rm.Body.(*icmp.ParamProb)
		return icmpParamProbData(body, ok)
	default:
		return nil, false
	}
}

func icmpTimeExceededData(body *icmp.TimeExceeded, ok bool) ([]byte, bool) {
	if !ok || body == nil {
		return nil, false
	}
	return body.Data, true
}

func icmpDstUnreachData(body *icmp.DstUnreach, ok bool) ([]byte, bool) {
	if !ok || body == nil {
		return nil, false
	}
	return body.Data, true
}

func icmpPacketTooBigData(body *icmp.PacketTooBig, ok bool) ([]byte, bool) {
	if !ok || body == nil {
		return nil, false
	}
	return body.Data, true
}

func icmpParamProbData(body *icmp.ParamProb, ok bool) ([]byte, bool) {
	if !ok || body == nil {
		return nil, false
	}
	return body.Data, true
}

func matchesEmbeddedDstIP(ipVersion int, data []byte, dstIP net.IP) bool {
	embeddedDstIP, ok := extractEmbeddedDstIP(ipVersion, data)
	if !ok {
		return false
	}
	return embeddedDstIP.Equal(dstIP)
}

func extractEmbeddedDstIP(ipVersion int, data []byte) (net.IP, bool) {
	switch ipVersion {
	case 4:
		if len(data) < 20 || data[0]>>4 != 4 {
			return nil, false
		}
		return net.IP(data[16:20]), true
	case 6:
		if len(data) < 40 || data[0]>>4 != 6 {
			return nil, false
		}
		return net.IP(data[24:40]), true
	default:
		return nil, false
	}
}

func extractEmbeddedICMPSeq(data []byte, echoID int) (int, bool) {
	header, err := util.GetICMPResponsePayload(data)
	if err != nil {
		return 0, false
	}
	id, err := util.GetICMPID(header)
	if err != nil || id != echoID {
		return 0, false
	}
	seq, err := util.GetICMPSeq(header)
	if err != nil {
		return 0, false
	}
	return seq, true
}
