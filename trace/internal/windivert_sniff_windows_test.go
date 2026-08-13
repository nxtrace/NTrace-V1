//go:build windows && amd64

package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

func TestWinDivertTCPFilterAllowsAlternateRemoteSource(t *testing.T) {
	tests := []struct {
		name      string
		ipVersion int
		srcIP     net.IP
		port      int
		want      string
	}{
		{
			name:      "IPv4",
			ipVersion: 4,
			srcIP:     net.ParseIP("192.0.2.10"),
			port:      443,
			want:      "inbound and tcp and ip.DstAddr == 192.0.2.10 and tcp.SrcPort == 443",
		},
		{
			name:      "IPv6",
			ipVersion: 6,
			srcIP:     net.ParseIP("2001:db8::10"),
			port:      8443,
			want:      "inbound and tcp and ipv6.DstAddr == 2001:db8::10 and tcp.SrcPort == 8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := winDivertTCPFilter(tt.ipVersion, tt.srcIP, tt.port); got != tt.want {
				t.Fatalf("winDivertTCPFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWinDivertEchoReplyRequiresDestinationSource(t *testing.T) {
	dstIP := net.ParseIP("2001:db8::1")
	packet := &winDivertICMPPacket{
		peerIP:    dstIP,
		echoReply: true,
		echoID:    7,
		echoSeq:   11,
	}
	if seq, ok := packet.echoReplyFor(7, dstIP); !ok || seq != 11 {
		t.Fatalf("echoReplyFor() = (%d, %v), want (11, true)", seq, ok)
	}

	packet.peerIP = net.ParseIP("2001:db8::2")
	if _, ok := packet.echoReplyFor(7, dstIP); ok {
		t.Fatal("echoReplyFor() ok = true, want false for non-destination source")
	}
}

func TestWinDivertICMPErrorAllowsAlternateOuterSource(t *testing.T) {
	dstIP := net.ParseIP("192.0.2.1")
	packet := &winDivertICMPPacket{
		ipVersion: 4,
		peerIP:    net.ParseIP("198.51.100.1"),
		errorData: buildIPv4InnerPacket(dstIP, 7, 11),
	}
	data, ok := packet.errorPayloadFor(dstIP)
	if !ok {
		t.Fatal("errorPayloadFor() ok = false, want true for alternate outer source")
	}
	if seq, ok := extractEmbeddedICMPSeq(data, 7); !ok || seq != 11 {
		t.Fatalf("extractEmbeddedICMPSeq() = (%d, %v), want (11, true)", seq, ok)
	}
}

func TestOpenWinDivertSniffHandlePanicsInDevMode(t *testing.T) {
	oldOpen := openWinDivertSniffCall
	oldFatal := winDivertSniffFatal
	oldDevMode := winDivertSniffDevMode
	openWinDivertSniffCall = func(string, uint64) (wd.Handle, error) {
		return 0, wd.Error(windows.ERROR_FILE_NOT_FOUND)
	}
	var gotFatal string
	winDivertSniffFatal = func(msg string) {
		gotFatal = msg
	}
	winDivertSniffDevMode = func() bool { return true }
	defer func() {
		openWinDivertSniffCall = oldOpen
		winDivertSniffFatal = oldFatal
		winDivertSniffDevMode = oldDevMode
	}()
	defer func() {
		if gotFatal != "" {
			t.Fatalf("fatal should not be called in dev mode: %s", gotFatal)
		}
	}()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("openWinDivertSniffHandle() did not panic in dev mode")
		} else if msg := fmt.Sprintf("%v", r); !strings.Contains(msg, "WinDivert") || !strings.Contains(msg, `filter="false"`) {
			t.Fatalf("panic = %q, want WinDivert context and filter", msg)
		}
	}()

	openWinDivertSniffHandle(context.Background(), "false", "test")
}

func TestOpenWinDivertSniffHandleCallsFatalOutsideDevModeThenPanics(t *testing.T) {
	oldOpen := openWinDivertSniffCall
	oldFatal := winDivertSniffFatal
	oldDevMode := winDivertSniffDevMode
	openWinDivertSniffCall = func(string, uint64) (wd.Handle, error) {
		return 0, errors.New("boom")
	}
	var gotFatal string
	winDivertSniffFatal = func(msg string) {
		gotFatal = msg
	}
	winDivertSniffDevMode = func() bool { return false }
	defer func() {
		openWinDivertSniffCall = oldOpen
		winDivertSniffFatal = oldFatal
		winDivertSniffDevMode = oldDevMode
	}()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("openWinDivertSniffHandle() did not panic after fatal hook")
		} else if msg := fmt.Sprintf("%v", r); !strings.Contains(msg, "Windows WinDivert 嗅探 (test") || !strings.Contains(msg, `filter="false"`) {
			t.Fatalf("panic = %q, want action context and filter", msg)
		}
		if gotFatal == "" {
			t.Fatal("fatal hook was not called")
		}
		if !strings.Contains(gotFatal, "Windows WinDivert 嗅探 (test") || !strings.Contains(gotFatal, `filter="false"`) {
			t.Fatalf("fatal message = %q, want action context and filter", gotFatal)
		}
	}()

	openWinDivertSniffHandle(context.Background(), "false", "test")
}
