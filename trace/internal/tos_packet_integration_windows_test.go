//go:build windows && amd64

package internal

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

var windowsTOSValues = []int{0, 1, 2, 3, 16, 46, 184, 255, 0}

// The pinned windivert-go binding incorrectly defines ShutdownRecv as zero.
// WinDivert 2.x uses a bitmask: RECV=1, SEND=2, BOTH=3. Passing zero returns
// ERROR_INVALID_PARAMETER rather than cancelling the blocked observer.
// https://github.com/basil00/WinDivert/blob/v2.2.2/include/windivert.h#L204
const windowsTOSShutdownRecv wd.Shutdown = 0x1

// TestTOSWindowsNativeICMPv4 records what Winsock actually emits. This witness
// remains independent of the production sender selection so a backend change
// cannot turn evidence about native IP_TOS support into a circular assertion.
// It is a capability diagnostic: the production CLI matrix remains strict.
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
			t.Logf("native IP_TOS request=%d", tos)
			captureWindowsTOS(t, filter, -1, 2, func() error {
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
						captureWindowsTOS(t, filter, tos, 2, func() error {
							runs := 1
							if mode == "report" && protocol != "icmp" {
								// Fallback MTR can emit identical packets in successive
								// rounds. Distinct source ports give independent report
								// sessions distinguishable identities in the capture.
								runs = 2
							}
							for run := 0; run < runs; run++ {
								runArgs := append([]string(nil), args...)
								if runs == 2 {
									runArgs = append(runArgs, "--source-port", strconv.Itoa(47464+run))
								}
								runArgs = append(runArgs, target)
								if err := runWindowsTOSCLI(t, bin, runArgs, mode, tos, run); err != nil {
									return err
								}
							}
							return nil
						})
					})
				}
			}
		}
	}
}

// This observes four probes across the persistent MTR ICMP engine's real
// sequence rollover. The child fixture records the expected echo IDs/sequences;
// the independent observer must see every one with its requested Traffic Class.
func TestTOSWindowsMTRRebuildCapture(t *testing.T) {
	requireWindowsTOSFixture(t)
	bin := os.Getenv("NEXTTRACE_TOS_REBUILD_BINARY")
	if bin == "" {
		t.Fatal("NEXTTRACE_TOS_REBUILD_BINARY is required")
	}
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprintf("ipv%d", version), func(t *testing.T) {
			filter := "outbound and ip.DstAddr == 127.0.0.1 and icmp.Type == 8"
			if version == 6 {
				filter = "outbound and ipv6.DstAddr == ::1 and icmpv6.Type == 128"
			}
			expected := make(map[[2]int]bool)
			expectedIDs := make(map[int]bool)
			packets := captureWindowsTOS(t, filter, 184, 4, func() error {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				args := []string{"-test.v", fmt.Sprintf("-test.run=^TestMTRTOSRebuildIntegration$/^ipv%d$", version), "-test.timeout=25s"}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = append(os.Environ(), "NEXTTRACE_TOS_REBUILD_INTEGRATION=1")
				output, err := cmd.CombinedOutput()
				if writeErr := os.WriteFile(windowsTOSArtifact(t, ".txt"), output, 0600); writeErr != nil {
					return writeErr
				}
				if err != nil {
					return fmt.Errorf("MTR rebuild fixture: %w\n%s", err, output)
				}
				for _, line := range strings.Split(string(output), "\n") {
					_, event, found := strings.Cut(line, "TOS_REBUILD ")
					if !found {
						continue
					}
					var probe struct {
						EchoID   int `json:"echo_id"`
						Sequence int `json:"sequence"`
						TOS      int `json:"tos"`
					}
					if err := json.Unmarshal([]byte(strings.TrimSpace(event)), &probe); err != nil {
						return err
					}
					if probe.TOS != 184 || probe.EchoID < 0 || probe.EchoID > 65535 || probe.Sequence < 0 || probe.Sequence > 65535 {
						return fmt.Errorf("invalid expected rebuild probe: %s", event)
					}
					expected[[2]int{probe.EchoID, probe.Sequence}] = true
					expectedIDs[probe.EchoID] = true
				}
				if len(expected) != 4 || len(expectedIDs) != 2 {
					return fmt.Errorf("fixture recorded %d probes across %d echo IDs, want 4 across 2", len(expected), len(expectedIDs))
				}
				return nil
			})
			observed := make(map[[2]int]bool)
			for _, packet := range packets {
				if len(packet) == 0 {
					t.Fatal("empty captured packet")
				}
				offset := 40
				if version == 4 {
					offset = int(packet[0]&15) * 4
				}
				if len(packet) < offset+8 {
					t.Fatalf("truncated ICMP probe: %x", packet)
				}
				id := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
				sequence := int(binary.BigEndian.Uint16(packet[offset+6 : offset+8]))
				observed[[2]int{id, sequence}] = true
			}
			for probe := range expected {
				if !observed[probe] {
					t.Errorf("missing captured rebuild probe echo_id=%d sequence=%d", probe[0], probe[1])
				}
			}
		})
	}
}

func runWindowsTOSCLI(t *testing.T, bin string, args []string, mode string, tos, run int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	log := strings.Join(args, " ") + "\nstdout:\n" + stdout.String() + "\nstderr:\n" + stderr.String()
	if writeErr := os.WriteFile(windowsTOSArtifact(t, fmt.Sprintf("_run%d.txt", run)), []byte(log), 0600); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return fmt.Errorf("CLI: %w\n%s", err, log)
	}
	if !json.Valid(stdout.Bytes()) {
		return fmt.Errorf("CLI stdout is not one valid JSON document: %s", stdout.String())
	}
	if mode != "report" {
		return nil
	}
	var report struct {
		EndReason  string `json:"end_reason"`
		Parameters struct {
			TOS *int `json:"tos"`
		} `json:"effective_parameters"`
		Stats []struct {
			TTL int `json:"ttl"`
			Snt int `json:"snt"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return err
	}
	sent := 0
	for _, stat := range report.Stats {
		if stat.TTL == 1 {
			sent += stat.Snt
		}
	}
	if report.EndReason != "completed" || report.Parameters.TOS == nil || *report.Parameters.TOS != tos || sent != 2 {
		return fmt.Errorf("MTR report did not complete two probes with TOS=%d: %s", tos, stdout.String())
	}
	return nil
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
	packets           [][]byte
	times             []time.Time
	err               error
	shutdownRequested bool
}

// A negative want records native capability only; production cases always
// pass their nonnegative requested TOS and require every captured byte to match.
func captureWindowsTOS(t *testing.T, filter string, want, minPackets int, emit func() error) [][]byte {
	t.Helper()
	// Production injection handles use priority 0. A lower-priority independent
	// SNIFF handle observes their injected packets as well as native socket sends.
	handle, err := wd.Open(filter, wd.LayerNetwork, -1000, wd.FlagSniff|wd.FlagRecvOnly)
	if err != nil {
		t.Fatalf("open independent packet observer: %v", err)
	}
	// Close may also be needed after a shutdown failure or a receive timeout.
	// A Windows HANDLE can be reused immediately, so no path may close it twice.
	closeObserver := sync.OnceValue(handle.Close)
	defer func() {
		if err := closeObserver(); err != nil {
			t.Errorf("close observer: %v", err)
		}
	}()
	done := make(chan windowsTOSCapture, 1)
	arrived := make(chan struct{})
	var shutdownRequested atomic.Bool
	go func() {
		var capture windowsTOSCapture
		buf := make([]byte, 65535)
		var addr wd.Address
		for {
			n, err := handle.Recv(buf, &addr)
			if err != nil {
				capture.err = err
				capture.shutdownRequested = shutdownRequested.Load()
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
	shutdownRequested.Store(true)
	if err := handle.Shutdown(windowsTOSShutdownRecv); err != nil {
		t.Errorf("stop observer: %v", err)
		_ = closeObserver()
	}
	var capture windowsTOSCapture
	select {
	case capture = <-done:
	case <-time.After(5 * time.Second):
		_ = closeObserver()
		t.Fatal("observer did not stop after shutdown")
	}
	if !capture.shutdownRequested || (!errors.Is(capture.err, wd.Error(windows.ERROR_NO_DATA)) && !errors.Is(capture.err, wd.Error(windows.ERROR_OPERATION_ABORTED))) {
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
	observed := make(map[int]int)
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
		observed[got]++
		if got < 0 || (want >= 0 && got != want) {
			t.Errorf("packet %d: complete TOS/Traffic Class byte = %d (0x%02x), want %d (0x%02x)", i, got, got, want, want)
		}
	}
	if len(distinct) < minPackets {
		t.Errorf("captured %d distinct matching probes (%d observations), want at least %d", len(distinct), len(capture.packets), minPackets)
	}
	t.Logf("observed TOS byte counts=%v, captured=%d, distinct=%d, filter=%s", observed, len(capture.packets), len(distinct), filter)
	return capture.packets
}
