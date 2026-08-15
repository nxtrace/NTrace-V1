//go:build darwin

package internal

import (
	"net"
	"testing"
)

func TestDarwinTCPCaptureFilterAllowsAlternateRemoteSource(t *testing.T) {
	tests := []struct {
		name string
		spec *TCPSpec
		want string
	}{
		{
			name: "IPv4",
			spec: &TCPSpec{
				IPVersion: 4,
				SrcIP:     net.ParseIP("192.0.2.10"),
				DstIP:     net.ParseIP("198.51.100.20"),
				DstPort:   443,
			},
			want: "ip and tcp and dst host 192.0.2.10 and src port 443",
		},
		{
			name: "IPv6",
			spec: &TCPSpec{
				IPVersion: 6,
				SrcIP:     net.ParseIP("2001:db8::10"),
				DstIP:     net.ParseIP("2001:db8::20"),
				DstPort:   8443,
			},
			want: "ip6 and tcp and dst host 2001:db8::10 and src port 8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.spec.tcpCaptureFilter(); got != tt.want {
				t.Fatalf("tcpCaptureFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}
