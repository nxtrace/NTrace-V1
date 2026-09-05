//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"net"
	"testing"
)

const fuzzDNSServerMaxBytes = 4096

func FuzzParseServer(f *testing.F) {
	f.Add("1.1.1.1")
	f.Add("https://[2001:db8::1]/dns-query")
	f.Add("tls://dns.example:853")
	f.Add("sdns://invalid")

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > fuzzDNSServerMaxBytes {
			input = input[:fuzzDNSServerMaxBytes]
		}
		parsed, err := ParseServer(input)
		if err != nil {
			return
		}
		if parsed.Original != input || parsed.Address == "" || parsed.Host == "" || parsed.TransportType == "" {
			t.Fatalf("successful DNS parse returned incomplete result: %+v", parsed)
		}
		if parsed.Port != "" {
			if _, err := net.LookupPort("tcp", parsed.Port); err != nil {
				t.Fatalf("successful DNS parse returned invalid port %q: %v", parsed.Port, err)
			}
		}
		again, err := ParseServer(input)
		if err != nil || again != parsed {
			t.Fatalf("DNS parse is not deterministic: first=%+v second=(%+v, %v)", parsed, again, err)
		}
	})
}
