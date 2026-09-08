//go:build windows && amd64

package internal

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
)

func TestShouldUseICMPv6RawSend(t *testing.T) {
	if shouldUseICMPv6RawSend(nil) {
		t.Fatal("nil header should not use raw send")
	}
	if shouldUseICMPv6RawSend(&layers.IPv6{}) {
		t.Fatal("zero traffic class should keep socket send")
	}
	if !shouldUseICMPv6RawSend(&layers.IPv6{TrafficClass: 46}) {
		t.Fatal("non-zero traffic class should use raw send")
	}
}

func TestShouldUseICMPv4RawSend(t *testing.T) {
	if shouldUseICMPv4RawSend(nil) {
		t.Fatal("nil header should not use raw send")
	}
	if shouldUseICMPv4RawSend(&layers.IPv4{}) {
		t.Fatal("zero tos should keep socket send")
	}
	for _, tos := range []uint8{1, 46, 184, 255} {
		if !shouldUseICMPv4RawSend(&layers.IPv4{TOS: tos}) {
			t.Fatalf("nonzero TOS=%d must use WinDivert send on Windows ICMPv4", tos)
		}
	}
}

func TestEnsureICMPSendHandlePreservesWrappedWinDivertError(t *testing.T) {
	oldCheck := checkWinDivertDLL
	oldOpen := openWinDivertCall
	checkWinDivertDLL = func() error {
		return &winDivertError{
			Kind:  winDivertErrorDriverMissing,
			Cause: wd.Error(windows.ERROR_FILE_NOT_FOUND),
		}
	}
	openWinDivertCall = func(string, uint64) (wd.Handle, error) {
		t.Fatal("openWinDivertCall should not run when DLL check fails")
		return 0, nil
	}
	defer func() {
		checkWinDivertDLL = oldCheck
		openWinDivertCall = oldOpen
	}()

	err := (&ICMPSpec{}).ensureICMPSendHandle(true)
	if err == nil {
		t.Fatal("ensureICMPSendHandle() error = nil, want non-nil")
	}
	var wrapped *winDivertError
	if !errors.As(err, &wrapped) {
		t.Fatalf("ensureICMPSendHandle() error = %T, want wrapped *winDivertError", err)
	}
	if wrapped.Kind != winDivertErrorDriverMissing {
		t.Fatalf("wrapped.Kind = %v, want %v", wrapped.Kind, winDivertErrorDriverMissing)
	}
}

func TestICMPv4ZeroTOSFailureIsInitializationError(t *testing.T) {
	conn := closedTOSSocket(t)
	s := ICMPSpec{IPVersion: 4, icmp: conn, icmp4: ipv4.NewPacketConn(conn)}
	start, err := s.SendICMP(t.Context(), &layers.IPv4{Version: 4, TTL: 1}, &layers.ICMPv4{}, nil, nil)
	var setup *InitializationError
	if !errors.As(err, &setup) || !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "IPv4 TOS 0") || !start.IsZero() {
		t.Fatalf("start=%v error=%v, want native zero-TOS initialization failure", start, err)
	}
}

func TestICMPv4NonzeroTOSWinDivertFailureIsInitializationError(t *testing.T) {
	oldCheck := checkWinDivertDLL
	t.Cleanup(func() { checkWinDivertDLL = oldCheck })
	cause := wd.Error(windows.ERROR_FILE_NOT_FOUND)
	checkWinDivertDLL = func() error { return cause }
	s := ICMPSpec{IPVersion: 4}
	start, err := s.SendICMP(t.Context(), &layers.IPv4{Version: 4, TOS: 184, TTL: 1}, &layers.ICMPv4{}, nil, nil)
	var setup *InitializationError
	if !errors.As(err, &setup) || !errors.Is(err, cause) || !strings.Contains(err.Error(), "Windows ICMPv4 --tos") || !start.IsZero() {
		t.Fatalf("start=%v error=%v, want WinDivert dependency initialization failure", start, err)
	}
}
