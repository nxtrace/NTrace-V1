//go:build windows && amd64

package internal

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	wd "github.com/xjasonlyu/windivert-go"

	"github.com/nxtrace/NTrace-core/util"
)

type TCPSpec struct {
	IPVersion int
	ICMPMode  int
	SrcIP     net.IP
	DstIP     net.IP
	DstPort   int
	SrcDev    string
	icmp      net.PacketConn
	PktSize   int
	addr      wd.Address
	handle    wd.Handle
}

func (s *TCPSpec) InitTCP() {
	handle, err := wd.Open("false", wd.LayerNetwork, 0, 0)
	if err != nil {
		if util.EnvDevMode {
			panic(fmt.Errorf("(InitTCP) WinDivert open failed: %v", err))
		}
		log.Fatalf("(InitTCP) WinDivert open failed: %v", err)
	}
	s.handle = handle

	// 设置出站 Address
	s.addr.SetLayer(wd.LayerNetwork)
	s.addr.SetEvent(wd.EventNetworkPacket)
	s.addr.SetOutbound()
}

func (s *TCPSpec) Close() {
	_ = s.icmp.Close()
	_ = s.handle.Close()
}

// resolveICMPMode 进行最终模式判定
func (s *TCPSpec) resolveICMPMode() int {
	icmpMode := s.ICMPMode
	if icmpMode != 1 && icmpMode != 2 {
		icmpMode = 0 // 统一成 Auto
	}

	// 指定 1=Socket：直接返回
	if icmpMode == 1 {
		return 1
	}

	// Auto(0) 或强制 PCAP(2) → 尝试 PCAP
	ok, err := pcapAvailable()
	if !ok {
		if icmpMode == 2 {
			log.Printf("PCAP mode requested, but Npcap is not available: %v; falling back to Socket mode.", err)
		}
		return 1
	}
	return 2
}

func (s *TCPSpec) ListenICMP(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, data []byte)) {
	switch s.resolveICMPMode() {
	case 1:
		s.listenICMPSock(ctx, ready, onICMP)
	case 2:
		s.listenICMPPcap(ctx, ready, onICMP)
	}
}

func (s *TCPSpec) listenICMPPcap(ctx context.Context, ready chan struct{}, onICMP func(msg ReceivedMessage, finish time.Time, data []byte)) {
	// 选择捕获设备与本地接口
	dev, err := util.PcapDeviceByIP(s.SrcIP)
	if err != nil {
		return
	}

	ipPrefix := "ip"
	proto := "icmp"
	if s.IPVersion == 6 {
		ipPrefix = "ip6"
		proto = "icmp6"
	}

	// 以“立即模式”打开 pcap，降低首包丢失概率
	handle, err := util.OpenLiveImmediate(dev, 65535, true, 4<<20)
	if err != nil {
		if util.EnvDevMode {
			panic(fmt.Errorf("(ListenICMP) pcap open failed on %s: %v", dev, err))
		}
		log.Fatalf("(ListenICMP) pcap open failed on %s: %v", dev, err)
	}
	defer handle.Close()

	// 过滤：只抓 {ip/ip6} + {icmp/icmp6}，且目标为本机 s.SrcIP
	filter := fmt.Sprintf("%s and %s and dst host %s",
		ipPrefix, proto, s.SrcIP.String())

	if err := handle.SetBPFFilter(filter); err != nil {
		if util.EnvDevMode {
			panic(fmt.Errorf("(ListenICMP) set BPF failed: %v (filter=%q)", err, filter))
		}
		log.Fatalf("(ListenICMP) set BPF failed: %v (filter=%q)", err, filter)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	pktCh := src.Packets()
	close(ready)

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-pktCh:
			if !ok {
				return
			}

			// 解包
			packet := pkt.NetworkLayer()
			if packet == nil {
				continue
			}
			finish := pkt.Metadata().Timestamp

			// outer = IP 头 + 负载
			outer := make([]byte, 0, len(packet.LayerContents())+len(packet.LayerPayload()))
			outer = append(outer, packet.LayerContents()...)
			outer = append(outer, packet.LayerPayload()...)

			var peerIP net.IP // 提取对端 IP（按族别）
			var data []byte   // 提取 ICMP 的负载
			if s.IPVersion == 4 {
				// 从包中获取 IPv4 层信息
				ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if !ok || ip4 == nil {
					continue
				}
				peerIP = ip4.SrcIP

				// 从包中获取 ICMPv4 层信息
				ic4, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				if !ok || ic4 == nil {
					continue
				}
				data = ic4.Payload

				switch ic4.TypeCode.Type() {
				case layers.ICMPv4TypeTimeExceeded:
				case layers.ICMPv4TypeDestinationUnreachable:
				default:
					//log.Println("received icmp message of unknown type", ic4.TypeCode.Type())
					continue
				}

				if len(data) < 20 || data[0]>>4 != 4 {
					continue
				}

				dstIP := net.IP(data[16:20])
				if !dstIP.Equal(s.DstIP) {
					continue
				}
			} else {
				// 从包中获取 IPv6 层信息
				ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if !ok || ip6 == nil {
					continue
				}
				peerIP = ip6.SrcIP

				// 从包中获取 ICMPv6 层信息
				ic6, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
				if !ok || ic6 == nil {
					continue
				}
				data = ic6.Payload[4:]

				switch ic6.TypeCode.Type() {
				case layers.ICMPv6TypeTimeExceeded:
				case layers.ICMPv6TypePacketTooBig:
				case layers.ICMPv6TypeDestinationUnreachable:
				default:
					//log.Println("received icmp message of unknown type", ic6.TypeCode.Type())
					continue
				}

				if len(data) < 40 || data[0]>>4 != 6 {
					continue
				}

				dstIP := net.IP(data[24:40])
				if !dstIP.Equal(s.DstIP) {
					continue
				}
			}
			peer := &net.IPAddr{IP: peerIP}

			// outer：外层 IP 报文字节；data：ICMP 引用的内层 IP 片段
			msg := ReceivedMessage{
				Peer: peer,
				Msg:  outer,
			}
			onICMP(msg, finish, data)
		}
	}
}

func (s *TCPSpec) ListenTCP(ctx context.Context, ready chan struct{}, onTCP func(srcPort, seq int, peer net.Addr, finish time.Time)) {
	// 选择捕获设备与本地接口
	dev, err := util.PcapDeviceByIP(s.SrcIP)
	if err != nil {
		return
	}

	ipPrefix := "ip"
	if s.IPVersion == 6 {
		ipPrefix = "ip6"
	}

	// 以“立即模式”打开 pcap，降低首包丢失概率
	handle, err := util.OpenLiveImmediate(dev, 65535, true, 4<<20)
	if err != nil {
		if util.EnvDevMode {
			panic(fmt.Errorf("(ListenTCP) pcap open failed on %s: %v", dev, err))
		}
		log.Fatalf("(ListenTCP) pcap open failed on %s: %v", dev, err)
	}
	defer handle.Close()

	// 过滤：只抓 {ip/ip6} + tcp，来自目标 s.DstIP → 本机 s.SrcIP，且源端口为 s.DstPort
	filter := fmt.Sprintf(
		"%s and tcp and src host %s and dst host %s and src port %d",
		ipPrefix, s.DstIP.String(), s.SrcIP.String(), s.DstPort,
	)

	if err := handle.SetBPFFilter(filter); err != nil {
		if util.EnvDevMode {
			panic(fmt.Errorf("(ListenTCP) set BPF failed: %v (filter=%q)", err, filter))
		}
		log.Fatalf("(ListenTCP) set BPF failed: %v (filter=%q)", err, filter)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	pktCh := src.Packets()
	close(ready)

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-pktCh:
			if !ok {
				return
			}

			// 解包
			packet := pkt.NetworkLayer()
			if packet == nil {
				continue
			}
			finish := pkt.Metadata().Timestamp

			// 从包中获取 TCP 层信息
			tl, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !ok || tl == nil {
				continue
			}

			if int(tl.SrcPort) != s.DstPort {
				continue
			}

			// 依据报文类型还原原始探测 seq：1=RST+ACK => ack-1-s.PktSize；2=SYN+ACK => ack-1
			var seq int
			if tl.ACK && tl.RST {
				seq = int(tl.Ack) - 1 - s.PktSize
			} else if tl.ACK && tl.SYN {
				seq = int(tl.Ack) - 1
			} else {
				continue
			}

			var peerIP net.IP // 提取对端 IP（按族别）
			if s.IPVersion == 4 {
				// 从包中获取 IPv4 层信息
				ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				if !ok || ip4 == nil {
					continue
				}
				peerIP = ip4.SrcIP
			} else {
				// 从包中获取 IPv6 层信息
				ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				if !ok || ip6 == nil {
					continue
				}
				peerIP = ip6.SrcIP
			}
			peer := &net.IPAddr{IP: peerIP}
			srcPort := int(tl.DstPort)
			onTCP(srcPort, seq, peer, finish)
		}
	}
}

func (s *TCPSpec) SendTCP(ctx context.Context, ipHdr ipLayer, tcpHdr *layers.TCP, payload []byte) (time.Time, error) {
	select {
	case <-ctx.Done():
		return time.Time{}, context.Canceled
	default:
	}

	_ = tcpHdr.SetNetworkLayerForChecksum(ipHdr)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// 序列化 IP 与 TCP 头以及 payload 到缓冲区
	if err := gopacket.SerializeLayers(buf, opts, ipHdr, tcpHdr, gopacket.Payload(payload)); err != nil {
		return time.Time{}, err
	}

	start := time.Now()

	// 复用预置的出站 Address
	if _, err := s.handle.Send(buf.Bytes(), &s.addr); err != nil {
		return time.Time{}, err
	}
	return start, nil
}
