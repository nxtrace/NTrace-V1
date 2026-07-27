//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	qoutput "github.com/natesales/q/output"
)

func TestPostProcessRepliesConcatenatesTXTAndRoundsTTL(t *testing.T) {
	reply := new(dns.Msg)
	reply.Answer = []dns.RR{
		&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 125}, Txt: []string{"hello", "world"}},
	}
	postProcessReplies([]*dns.Msg{reply}, &cli.Flags{TXTConcat: true, RoundTTLs: true})
	txt := reply.Answer[0].(*dns.TXT)
	if len(txt.Txt) != 1 || txt.Txt[0] != "helloworld" {
		t.Fatalf("TXT = %#v", txt.Txt)
	}
	if txt.Hdr.Ttl != 120 {
		t.Fatalf("TTL = %d, want 120", txt.Hdr.Ttl)
	}
}

func TestRenderEntriesRejectsUnknownFormat(t *testing.T) {
	err := renderEntries(&bytes.Buffer{}, &cli.Flags{Format: "toml"}, []*qoutput.Entry{})
	if err == nil || !strings.Contains(err.Error(), "invalid output format") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadPTRsHonorsCancellation(t *testing.T) {
	entry := &qoutput.Entry{Replies: []*dns.Msg{{Answer: []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   []byte{192, 0, 2, 10},
	}}}}}
	txp := &blockingTransport{unblock: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := loadPTRs(ctx, entry, txp)
	close(txp.unblock)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("error = %v", err)
	}
}
