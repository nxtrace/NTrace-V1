//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
)

func TestBuildQueriesHeaderAndQuestion(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:                "example.com",
			Class:               dns.ClassCHAOS,
			ID:                  4242,
			AuthoritativeAnswer: true,
			AuthenticData:       true,
			CheckingDisabled:    true,
			RecursionDesired:    true,
			RecursionAvailable:  true,
			Zero:                true,
			Truncated:           true,
		},
		RRTypes: []uint16{dns.TypeA, dns.TypeAAAA},
	}
	queries, err := BuildQueries(config)
	if err != nil {
		t.Fatalf("BuildQueries() error = %v", err)
	}
	if len(queries) != 2 {
		t.Fatalf("len(queries) = %d, want 2", len(queries))
	}
	for index, query := range queries {
		if query.Id != 4242 {
			t.Errorf("query[%d].Id = %d", index, query.Id)
		}
		if !query.Authoritative || !query.AuthenticatedData || !query.CheckingDisabled ||
			!query.RecursionDesired || !query.RecursionAvailable || !query.Zero || !query.Truncated {
			t.Errorf("query[%d] header flags = %+v", index, query.MsgHdr)
		}
		if len(query.Question) != 1 {
			t.Fatalf("query[%d] questions = %d", index, len(query.Question))
		}
		question := query.Question[0]
		if question.Name != "example.com." || question.Qclass != dns.ClassCHAOS || question.Qtype != config.RRTypes[index] {
			t.Errorf("query[%d] question = %+v", index, question)
		}
	}
}

func TestBuildQueriesEDNSOptions(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:         "example.com",
			Class:        dns.ClassINET,
			ID:           7,
			EDNS:         true,
			DNSSEC:       true,
			NSID:         true,
			Pad:          true,
			ClientSubnet: "192.0.2.129/24",
			Cookie:       "0011223344556677",
			UDPBuffer:    1232,
		},
		RRTypes: []uint16{dns.TypeHTTPS},
	}
	queries, err := BuildQueries(config)
	if err != nil {
		t.Fatalf("BuildQueries() error = %v", err)
	}
	opt := queries[0].IsEdns0()
	if opt == nil {
		t.Fatal("missing OPT record")
	}
	if !opt.Do() || opt.UDPSize() != 1232 {
		t.Errorf("OPT DO=%t UDPSize=%d", opt.Do(), opt.UDPSize())
	}
	if len(opt.Option) != 4 {
		t.Fatalf("OPT options = %d, want 4", len(opt.Option))
	}
	if _, ok := opt.Option[0].(*dns.EDNS0_NSID); !ok {
		t.Errorf("option[0] = %T, want NSID", opt.Option[0])
	}
	padding, ok := opt.Option[1].(*dns.EDNS0_PADDING)
	if !ok || len(padding.Padding) != 57 {
		t.Errorf("option[1] = %#v, want 57-byte padding", opt.Option[1])
	}
	subnet, ok := opt.Option[2].(*dns.EDNS0_SUBNET)
	if !ok {
		t.Fatalf("option[2] = %T, want subnet", opt.Option[2])
	}
	if subnet.Family != 1 || subnet.SourceNetmask != 24 || !subnet.Address.Equal(net.ParseIP("192.0.2.129")) {
		t.Errorf("subnet = %+v", subnet)
	}
	cookie, ok := opt.Option[3].(*dns.EDNS0_COOKIE)
	if !ok || cookie.Cookie != "0011223344556677" {
		t.Errorf("option[3] = %#v, want cookie", opt.Option[3])
	}
	packed, err := queries[0].Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(packed)%128 != 0 {
		t.Fatalf("packed query length = %d, want a multiple of 128", len(packed))
	}
}

func TestBuildQueriesIPv6ClientSubnet(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:         "example.com",
			Class:        dns.ClassINET,
			ID:           1,
			EDNS:         true,
			ClientSubnet: "2001:db8::1/56",
			UDPBuffer:    1232,
		},
		RRTypes: []uint16{dns.TypeAAAA},
	}
	queries, err := BuildQueries(config)
	if err != nil {
		t.Fatal(err)
	}
	subnet := queries[0].IsEdns0().Option[0].(*dns.EDNS0_SUBNET)
	if subnet.Family != 2 || subnet.SourceNetmask != 56 || !subnet.Address.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("subnet = %+v", subnet)
	}
}

func TestBuildQueriesEDNSDisabledDropsOPT(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:      "example.com",
			Class:     dns.ClassINET,
			ID:        1,
			EDNS:      false,
			DNSSEC:    true,
			NSID:      true,
			Pad:       true,
			Cookie:    "0011223344556677",
			UDPBuffer: 1232,
		},
		RRTypes: []uint16{dns.TypeA},
	}
	queries, err := BuildQueries(config)
	if err != nil {
		t.Fatal(err)
	}
	if opt := queries[0].IsEdns0(); opt != nil {
		t.Fatalf("OPT = %+v with EDNS disabled", opt)
	}
}

func TestBuildQueriesPaddingRespectsSmallUDPBuffer(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:      "example.com",
			Class:     dns.ClassINET,
			ID:        1,
			EDNS:      true,
			Pad:       true,
			UDPBuffer: 8,
		},
		RRTypes: []uint16{dns.TypeA},
	}
	queries, err := BuildQueries(config)
	if err != nil {
		t.Fatal(err)
	}
	padding := queries[0].IsEdns0().Option[0].(*dns.EDNS0_PADDING)
	if len(padding.Padding) != 0 {
		t.Fatalf("padding = %d, want 0", len(padding.Padding))
	}
}

func TestBuildQueriesInvalidSubnetReturnsError(t *testing.T) {
	config := Config{
		Flags: cli.Flags{
			Name:         "example.com",
			Class:        dns.ClassINET,
			ID:           1,
			EDNS:         true,
			ClientSubnet: "not-a-subnet",
		},
		RRTypes: []uint16{dns.TypeA},
	}
	_, err := BuildQueries(config)
	if err == nil || !strings.Contains(err.Error(), "parsing subnet") {
		t.Fatalf("error = %v, want subnet parse error", err)
	}
}
