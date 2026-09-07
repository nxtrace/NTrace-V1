//go:build windows

package doctor

import (
	"net"
	"testing"
)

func TestWindowsRouteAddressFamilies(t *testing.T) {
	for _, s := range []string{"192.0.2.12", "2001:db8::12", "0.0.0.0", "::"} {
		ip := net.ParseIP(s)
		a := windowsRouteAddress(ip)
		if got := windowsRouteIP(&a); !got.Equal(ip) {
			t.Fatalf("%s decoded as %s", s, got)
		}
	}
}
