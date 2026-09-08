//go:build windows && amd64

package internal

import (
	"context"
	"net"
	"testing"

	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

func TestDoctorWinDivertOpenAlwaysProhibitsInstallation(t *testing.T) {
	oldCheck, oldOpen, oldSniff := checkWinDivertDLL, openWinDivertCall, openWinDivertSniffCall
	t.Cleanup(func() { checkWinDivertDLL = oldCheck; openWinDivertCall = oldOpen; openWinDivertSniffCall = oldSniff })
	checkWinDivertDLL = func() error { return nil }
	calls := 0
	opener := func(_ string, flags uint64) (wd.Handle, error) {
		calls++
		if flags&wd.FlagNoInstall == 0 {
			t.Fatal("driver installation allowed")
		}
		return 0, wd.Error(windows.ERROR_SERVICE_DOES_NOT_EXIST)
	}
	openWinDivertCall = opener
	openWinDivertSniffCall = opener
	for _, fn := range []func() error{
		func() error { return (&TCPSpec{}).initTCP(wd.FlagNoInstall) },
		func() error { return (&UDPSpec{}).initUDP(wd.FlagNoInstall) },
		func() error { return (&ICMPSpec{}).ensureICMPSendHandleWithFlags(true, wd.FlagNoInstall) },
		func() error { _, e := winDivertAvailableWithFlags(wd.FlagNoInstall); return e },
		func() error { _, e := openWinDivertSniffWithFlags("false", "doctor", wd.FlagNoInstall); return e },
	} {
		c := doctorWinStep(context.Background(), "check", fn)
		if !c.Unknown || c.Err == nil {
			t.Fatalf("NO_INSTALL failure not marked unverified: %+v", c)
		}
	}
	if calls != 5 {
		t.Fatalf("opens=%d", calls)
	}
	// Exercise the dispatcher too: passing NO_INSTALL explicitly to helpers
	// above would not catch a future omission at a real doctor call site.
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		for _, target := range []string{"127.0.0.1", "::1"} {
			ip, family := net.ParseIP(target), 4
			if ip.To4() == nil {
				family = 6
			}
			before := calls
			CheckProbeBackend(context.Background(), BackendOptions{
				Protocol: protocol, IPVersion: family, Source: ip, Target: ip, Port: 443, TOS: 32,
			})
			// Nonzero TOS ICMP now requires a WinDivert sender for both families.
			if calls == before {
				t.Fatalf("%s/%s did not check WinDivert", protocol, target)
			}
		}
	}
	openWinDivertCall = func(_ string, flags uint64) (wd.Handle, error) {
		if flags&wd.FlagNoInstall != 0 {
			t.Fatal("normal probe policy changed")
		}
		return 0, wd.Error(windows.ERROR_FILE_NOT_FOUND)
	}
	_ = (&TCPSpec{}).InitTCP()
	_ = (&UDPSpec{}).InitUDP()
	_ = (&ICMPSpec{}).ensureICMPSendHandle(true)
	_, _ = winDivertAvailable()
}

func TestDoctorWinDivertMissingFileIsNotInstallationUncertainty(t *testing.T) {
	// WinDivertOpen documents error 2 as missing .sys files, whereas 1060
	// specifically means NO_INSTALL prevented installation. Normal opens do
	// not unpack missing driver files, so error 2 remains a definite failure.
	// https://reqrypt.org/windivert-doc.html#divert_open
	c := doctorWinStep(context.Background(), "windivert_tcp_send", func() error {
		return classifyWinDivertError(wd.Error(windows.ERROR_FILE_NOT_FOUND))
	})
	if c.Err == nil || c.Unknown || c.Optional || c.Skipped {
		t.Fatalf("missing driver file lost its failure classification: %+v", c)
	}
}
