//go:build windows && amd64

package internal

import (
	"net"
	"os"
	"testing"

	wd "github.com/xjasonlyu/windivert-go"
)

// This opt-in fixture runs only in the elevated Windows regression process,
// beside the DLL/driver files already prepared by that script's --init step.
// Fixture setup intentionally uses the ordinary driver policy and keeps its
// handle alive. All subsequent doctor opens must use NO_INSTALL. No packet is
// sent or read, and the false filter captures no traffic.
func TestDoctorWindowsBackend(t *testing.T) {
	if os.Getenv("NEXTTRACE_DOCTOR_BACKEND_INTEGRATION") != "1" {
		t.Skip("opt-in Windows driver fixture")
	}
	holder, err := OpenWinDivertHandle("false", wd.FlagSniff|wd.FlagRecvOnly)
	if err != nil {
		t.Fatalf("prepare installed-driver fixture: %v", err)
	}
	defer func() { _ = holder.Close() }()
	for _, protocol := range []string{"icmp", "tcp", "udp"} {
		for _, target := range []string{"127.0.0.1", "::1"} {
			t.Run(protocol+"/"+target, func(t *testing.T) {
				ip, family := net.ParseIP(target), 4
				if ip.To4() == nil {
					family = 6
				}
				checks := CheckProbeBackend(t.Context(), BackendOptions{
					Protocol: protocol, IPVersion: family, ICMPMode: 2,
					Source: ip, Target: ip, Port: 443, TOS: 32,
				})
				for _, c := range checks {
					if c.Err != nil || c.Unknown || c.Skipped {
						t.Errorf("%s: %+v", c.Name, c)
					}
				}
			})
		}
	}
}
