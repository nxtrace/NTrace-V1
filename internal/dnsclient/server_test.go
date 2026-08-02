//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"testing"

	qlog "github.com/charmbracelet/log"
	"github.com/jedisct1/go-dnsstamps"
	qtransport "github.com/natesales/q/transport"
	"github.com/stretchr/testify/require"
)

func TestParseServerCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantType  qtransport.Type
		wantAddr  string
		wantHost  string
		wantPort  string
		wantPath  string
		wantStamp bool
	}{
		{name: "IPv4 default port", input: "1.1.1.1", wantType: qtransport.TypePlain, wantAddr: "1.1.1.1:53", wantHost: "1.1.1.1", wantPort: "53"},
		{name: "IPv4 explicit port", input: "1.1.1.1:5353", wantType: qtransport.TypePlain, wantAddr: "1.1.1.1:5353", wantHost: "1.1.1.1", wantPort: "5353"},
		{name: "IPv6 default port", input: "2a09::", wantType: qtransport.TypePlain, wantAddr: "[2a09::]:53", wantHost: "2a09::", wantPort: "53"},
		{name: "IPv6 explicit port", input: "[2a09::]:5353", wantType: qtransport.TypePlain, wantAddr: "[2a09::]:5353", wantHost: "2a09::", wantPort: "5353"},
		{name: "DoT default port", input: "tls://dns.quad9.net", wantType: qtransport.TypeTLS, wantAddr: "dns.quad9.net:853", wantHost: "dns.quad9.net", wantPort: "853"},
		{name: "DoT explicit port", input: "tls://dns.quad9.net:8530", wantType: qtransport.TypeTLS, wantAddr: "dns.quad9.net:8530", wantHost: "dns.quad9.net", wantPort: "8530"},
		{name: "DoH default endpoint", input: "https://dns.quad9.net", wantType: qtransport.TypeHTTP, wantAddr: "https://dns.quad9.net:443/dns-query", wantHost: "dns.quad9.net", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH IPv6", input: "https://2a09::", wantType: qtransport.TypeHTTP, wantAddr: "https://[2a09::]:443/dns-query", wantHost: "2a09::", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH endpoint", input: "https://dns.quad9.net/other-dns-endpoint", wantType: qtransport.TypeHTTP, wantAddr: "https://dns.quad9.net:443/other-dns-endpoint", wantHost: "dns.quad9.net", wantPort: "443", wantPath: "/other-dns-endpoint"},
		{name: "DoH HTTP", input: "http://localhost/dns-query", wantType: qtransport.TypeHTTP, wantAddr: "http://localhost:80/dns-query", wantHost: "localhost", wantPort: "80", wantPath: "/dns-query"},
		{name: "TCP", input: "tcp://dns.quad9.net", wantType: qtransport.TypeTCP, wantAddr: "dns.quad9.net:53", wantHost: "dns.quad9.net", wantPort: "53"},
		{name: "DoQ", input: "quic://dns.adguard.com", wantType: qtransport.TypeQUIC, wantAddr: "dns.adguard.com:853", wantHost: "dns.adguard.com", wantPort: "853"},
		{name: "scoped IPv6", input: "fe80::1%en0", wantType: qtransport.TypePlain, wantAddr: "[fe80::1%en0]:53", wantHost: "fe80::1%en0", wantPort: "53"},
		{name: "bare numeric scoped IPv6", input: "fe80::1%25", wantType: qtransport.TypePlain, wantAddr: "[fe80::1%25]:53", wantHost: "fe80::1%25", wantPort: "53"},
		{name: "scoped IPv6 explicit", input: "plain://[fe80::1%en0]:53", wantType: qtransport.TypePlain, wantAddr: "[fe80::1%en0]:53", wantHost: "fe80::1%en0", wantPort: "53"},
		{name: "RFC 6874 scoped IPv6", input: "plain://[fe80::1%25en0]:53", wantType: qtransport.TypePlain, wantAddr: "[fe80::1%en0]:53", wantHost: "fe80::1%en0", wantPort: "53"},
		{name: "RFC 6874 numeric scoped IPv6", input: "plain://[fe80::1%2525]:53", wantType: qtransport.TypePlain, wantAddr: "[fe80::1%25]:53", wantHost: "fe80::1%25", wantPort: "53"},
		{name: "DoH scoped IPv6", input: "https://[fe80::1%en0]/dns-query", wantType: qtransport.TypeHTTP, wantAddr: "https://[fe80::1%25en0]:443/dns-query", wantHost: "fe80::1%en0", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH RFC 6874 scoped IPv6", input: "https://[fe80::1%25en0]/dns-query", wantType: qtransport.TypeHTTP, wantAddr: "https://[fe80::1%25en0]:443/dns-query", wantHost: "fe80::1%en0", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH escaped userinfo", input: "https://user%40name:p%40ss@dns.example/dns-query", wantType: qtransport.TypeHTTP, wantAddr: "https://user%40name:p%40ss@dns.example:443/dns-query", wantHost: "dns.example", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH escaped userinfo and scoped IPv6", input: "https://user%40name:p%40ss@[fe80::1%25en0]/dns-query", wantType: qtransport.TypeHTTP, wantAddr: "https://user%40name:p%40ss@[fe80::1%25en0]:443/dns-query", wantHost: "fe80::1%en0", wantPort: "443", wantPath: "/dns-query"},
		{name: "DoH stamp", input: "sdns://AgcAAAAAAAAAAAAHOS45LjkuOQA", wantType: qtransport.TypeHTTP, wantAddr: "https://9.9.9.9:443/dns-query", wantHost: "9.9.9.9", wantPort: "443", wantPath: "/dns-query", wantStamp: true},
		{name: "encoded path", input: "https://localhost/1%3A89%3D%3D%3A64fx", wantType: qtransport.TypeHTTP, wantAddr: "https://localhost:443/1%3A89%3D%3D%3A64fx", wantHost: "localhost", wantPort: "443", wantPath: "/1%3A89%3D%3D%3A64fx"},
		{name: "literal colons in path", input: "https://localhost/1:89==:64fx", wantType: qtransport.TypeHTTP, wantAddr: "https://localhost:443/1:89==:64fx", wantHost: "localhost", wantPort: "443", wantPath: "/1:89==:64fx"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseServer(test.input)
			require.NoError(t, err)
			require.Equal(t, test.input, got.Original)
			require.Equal(t, test.wantType, got.TransportType)
			require.Equal(t, test.wantAddr, got.Address)
			require.Equal(t, test.wantHost, got.Host)
			require.Equal(t, test.wantPort, got.Port)
			require.Equal(t, test.wantPath, got.Path)
			require.Equal(t, test.wantStamp, got.FromStamp)
		})
	}
}

func TestParseServerFormatsScopedIPv6DebugLog(t *testing.T) {
	original := qlog.Default()
	var output bytes.Buffer
	logger := qlog.New(&output)
	logger.SetLevel(qlog.DebugLevel)
	qlog.SetDefault(logger)
	t.Cleanup(func() { qlog.SetDefault(original) })

	_, err := ParseServer("plain://[fe80::1%en0]:53")
	require.NoError(t, err)
	require.Contains(t, output.String(), "Removed IPv6 scope ID %en0 from server plain://[fe80::1]:53")
	require.NotContains(t, output.String(), "scope ID %s")
}

func TestParseServerDNSCryptStamp(t *testing.T) {
	t.Parallel()

	const stamp = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
	got, err := ParseServer(stamp)
	require.NoError(t, err)
	require.Equal(t, qtransport.TypeDNSCrypt, got.TransportType)
	require.Equal(t, stamp, got.Address)
	require.Equal(t, "94.140.14.14", got.Host)
	require.Equal(t, "5443", got.Port)
	require.Equal(t, "2.dnscrypt.default.ns1.adguard.com", got.ServerName)
	require.True(t, got.FromStamp)
}

func TestParseServerRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	doqStamp := (&dnsstamps.ServerStamp{
		Proto:         dnsstamps.StampProtoTypeDoQ,
		ServerAddrStr: "1.1.1.1:853",
		ProviderName:  "dns.example",
	}).String()

	for _, input := range []string{
		"",
		"https://",
		"ftp://dns.example",
		"plain://1.1.1.1/path",
		"plain://user@example.com",
		"plain://user%40name@1.1.1.1",
		"plain://[fe80::1%25]:53",
		"plain://[fe80::1%25en%ZZ]:53",
		"plain://[fe80::1%25en%0A]:53",
		"1.1.1.1:70000",
		"sdns://invalid",
		doqStamp,
	} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			_, err := ParseServer(input)
			require.Error(t, err)
		})
	}
}
