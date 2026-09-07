//go:build linux || darwin

package internal

import (
	"net"
	"os"
	"runtime"
	"testing"
)

// Run in the CI runner's privileged test process. Only local sockets and
// capture filters are opened; no Send or Listen loop is started.
func TestDoctorNativeBackend(t *testing.T) {
	if os.Getenv("NEXTTRACE_DOCTOR_BACKEND_INTEGRATION") != "1" {
		t.Skip("opt-in privileged backend initialization")
	}
	dev := "lo"
	if runtime.GOOS == "darwin" {
		dev = "lo0"
	}
	for _, protocol := range []string{"icmp", "tcp", "udp"} {
		for _, target := range []string{"127.0.0.1", "::1"} {
			t.Run(protocol+"/"+target, func(t *testing.T) {
				ip := net.ParseIP(target)
				family := 4
				if ip.To4() == nil {
					family = 6
				}
				checks := CheckProbeBackend(t.Context(), BackendOptions{Protocol: protocol, IPVersion: family, ICMPMode: 1, Source: ip, Target: ip, Device: dev, Port: 443})
				for _, c := range checks {
					if c.Err != nil {
						t.Errorf("%s: %v", c.Name, c.Err)
					}
				}
			})
		}
	}
}
