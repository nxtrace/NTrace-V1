//go:build windows && amd64

package internal

import (
	"context"
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
