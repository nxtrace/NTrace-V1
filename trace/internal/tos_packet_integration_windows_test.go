//go:build windows && amd64

package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

var windowsTOSValues = []int{0, 1, 2, 3, 16, 46, 184, 255, 0}

// TestTOSWindowsNativeICMPv4 records what Winsock actually emits. This witness
// remains independent of the production sender selection so a backend change
// cannot turn evidence about native IP_TOS support into a circular assertion.
func TestTOSWindowsNativeICMPv4(t *testing.T) {
	requireWindowsTOSFixture(t)
	src := net.IPv4(127, 0, 0, 1)
	s := NewICMPSpec(4, 1, 0x746f, src, src)
	if err := s.InitICMP(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for index, tos := range windowsTOSValues {
		t.Run(fmt.Sprintf("%02d_tos%d", index, tos), func(t *testing.T) {
			filter := "outbound and ip.DstAddr == 127.0.0.1 and icmp.Type == 8 and icmp.Body >= 0x746f0000 and icmp.Body < 0x74700000"
			captureWindowsTOS(t, filter, tos, 2, func() error {
				if err := s.icmp4.SetTOS(tos); err != nil {
					return fmt.Errorf("native IP_TOS=%d: %w", tos, err)
				}
				for seq := 0; seq < 2; seq++ {
					buf := gopacket.NewSerializeBuffer()
					icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 0x746f, Seq: uint16(index*2 + seq)}
					if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, icmp, gopacket.Payload("nexttrace-native-tos-witness")); err != nil {
						return err
					}
					if _, err := s.icmp.WriteTo(buf.Bytes(), &net.IPAddr{IP: src}); err != nil {
						return err
					}
				}
				return nil
			})
		})
	}
}

// This opt-in test runs in an elevated CI process beside WinDivert.dll and its
// driver. Missing prerequisites fail once enabled; there are no per-case skips.
func TestTOSWindowsPacketCapture(t *testing.T) {
	requireWindowsTOSFixture(t)
	bin := os.Getenv("NEXTTRACE_TOS_BINARY")
	if bin == "" {
		t.Fatal("NEXTTRACE_TOS_BINARY is required")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{4, 6} {
		target, ipFilter, icmpFilter := "127.0.0.1", "ip.DstAddr == 127.0.0.1", "icmp.Type == 8"
		if version == 6 {
			target, ipFilter, icmpFilter = "::1", "ipv6.DstAddr == ::1", "icmpv6.Type == 128"
		}
		for _, protocol := range []string{"icmp", "tcp", "udp"} {
			filter := "outbound and " + ipFilter + " and "
			switch protocol {
			case "tcp":
				filter += "tcp.DstPort == 33494 and tcp.Syn and not tcp.Ack"
			case "udp":
				filter += "udp.DstPort == 33494"
			default:
				filter += icmpFilter
			}
			for _, mode := range []string{"traceroute", "report"} {
				for index, tos := range windowsTOSValues {
					name := fmt.Sprintf("ipv%d/%s/%s/%02d_tos%d", version, protocol, mode, index, tos)
					t.Run(name, func(t *testing.T) {
						args := []string{"--" + mode, "--json", "-q", "2", "-m", "1", "--timeout", "500", "-i", "20", "-z", "20", "--data-provider", "disable-geoip", "--no-rdns", "--icmp-mode", "1", "-s", target, "-Q", strconv.Itoa(tos)}
						if protocol != "icmp" {
							args = append(args, "--"+protocol, "-p", "33494")
						}
						args = append(args, target)
						captureWindowsTOS(t, filter, tos, 2, func() error {
							ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
							defer cancel()
							cmd := exec.CommandContext(ctx, bin, args...)
							output, err := cmd.CombinedOutput()
							if writeErr := os.WriteFile(windowsTOSArtifact(t, ".txt"), append([]byte(strings.Join(args, " ")+"\n"), output...), 0600); writeErr != nil {
								return writeErr
							}
							if err != nil {
								return fmt.Errorf("CLI: %w\n%s", err, output)
							}
							return nil
						})
					})
				}
			}
		}
	}
}

func requireWindowsTOSFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("NEXTTRACE_TOS_PACKET_INTEGRATION") != "1" {
		t.Skip("opt-in elevated Windows packet fixture")
	}
	if !hasWindowsAdminPrivileges() {
		t.Fatal("TOS packet fixture requires an elevated process")
	}
	if err := checkWinDivertDLL(); err != nil {
		t.Fatal(err)
	}
}

func windowsTOSArtifact(t *testing.T, suffix string) string {
	t.Helper()
	dir := os.Getenv("NEXTTRACE_TOS_ARTIFACTS")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+suffix)
}

type windowsTOSCapture struct {
	packets [][]byte
	times   []time.Time
	err     error
}

func captureWindowsTOS(t *testing.T, filter string, want, minPackets int, emit func() error) {
	t.Helper()
	// Production injection handles use priority 0. A lower-priority independent
	// SNIFF handle observes their injected packets as well as native socket sends.
	handle, err := wd.Open(filter, wd.LayerNetwork, -1000, wd.FlagSniff|wd.FlagRecvOnly)
	if err != nil {
		t.Fatalf("open independent packet observer: %v", err)
	}
	defer func() { _ = handle.Close() }()
	done := make(chan windowsTOSCapture, 1)
	arrived := make(chan struct{})
	go func() {
		var capture windowsTOSCapture
		buf := make([]byte, 65535)
		var addr wd.Address
		for {
			n, err := handle.Recv(buf, &addr)
			if err != nil {
				capture.err = err
				done <- capture
				return
			}
			capture.packets = append(capture.packets, append([]byte(nil), buf[:n]...))
			capture.times = append(capture.times, time.Now())
			if len(capture.packets) == minPackets {
				close(arrived)
			}
		}
	}()
	if err := emit(); err != nil {
		t.Errorf("emit probes: %v", err)
	} else {
		select {
		case <-arrived:
		case <-time.After(3 * time.Second):
		}
	}
	// ShutdownRecv stops new arrivals and lets Recv drain every queued packet.
	if err := handle.Shutdown(wd.ShutdownRecv); err != nil {
		t.Errorf("stop observer: %v", err)
		_ = handle.Close()
	}
	var capture windowsTOSCapture
	select {
	case capture = <-done:
	case <-time.After(5 * time.Second):
		_ = handle.Close()
		t.Fatal("observer did not stop after shutdown")
	}
	if !errors.Is(capture.err, wd.Error(windows.ERROR_NO_DATA)) {
		t.Errorf("observer receive ended unexpectedly: %v", capture.err)
	}
	f, err := os.Create(windowsTOSArtifact(t, ".pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		t.Fatal(err)
	}
	distinct := make(map[string]struct{})
	for i, packet := range capture.packets {
		distinct[string(packet)] = struct{}{}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: capture.times[i], CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
			t.Fatal(err)
		}
		got := -1
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			got = int(packet[1])
		} else if len(packet) >= 40 && packet[0]>>4 == 6 {
			got = int(packet[0]&15)<<4 | int(packet[1]>>4)
		}
		if got != want {
			t.Errorf("packet %d: complete TOS/Traffic Class byte = %d (0x%02x), want %d (0x%02x)", i, got, got, want, want)
		}
	}
	if len(distinct) < minPackets {
		t.Errorf("captured %d distinct matching probes (%d observations), want at least %d", len(distinct), len(capture.packets), minPackets)
	}
	t.Logf("TOS=%d (0x%02x), captured=%d, distinct=%d, filter=%s", want, want, len(capture.packets), len(distinct), filter)
}
