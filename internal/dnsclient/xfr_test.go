//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRunRecursiveAXFRToWalksEachZoneOnce(t *testing.T) {
	root := t.TempDir()
	calls := make(map[string]int)
	transfer := func(_ context.Context, label, _ string, _ time.Duration) ([]dns.RR, error) {
		calls[label]++
		switch label {
		case "example.com.":
			return []dns.RR{
				mustRR(t, "example.com. 60 IN NS ns.example.com."),
				mustRR(t, "child.example.com. 60 IN NS ns.example.com."),
			}, nil
		case "child.example.com.":
			return []dns.RR{mustRR(t, "child.example.com. 60 IN A 192.0.2.1")}, nil
		default:
			return nil, nil
		}
	}

	var out bytes.Buffer
	if err := runRecursiveAXFRTo(context.Background(), "example.com", "127.0.0.1:53", time.Second, root, &out, transfer); err != nil {
		t.Fatal(err)
	}
	if calls["example.com."] != 1 || calls["child.example.com."] != 1 {
		t.Fatalf("transfer calls = %#v", calls)
	}
	if !strings.Contains(out.String(), "AXFR complete, 3 records") {
		t.Fatalf("output = %q", out.String())
	}
	for _, name := range []string{"example.com.zone", "child.example.com.zone"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

func TestRecursiveAXFRRootUsesWindowsPortableTimestamp(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 34, 56, 0, time.UTC)
	got, err := recursiveAXFRRoot("example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	const want = "example.com_Mon-Jul-27-12-34-56-UTC-2026_recaxfr"
	if got != want {
		t.Fatalf("recursiveAXFRRoot() = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, `<>:"/\\|?*`) {
		t.Fatalf("recursiveAXFRRoot() = %q, contains a Windows-invalid path character", got)
	}
}

func TestRecursiveAXFRPathsAcceptPortableDNSLabels(t *testing.T) {
	now := time.Date(2026, time.July, 27, 12, 34, 56, 0, time.UTC)
	root, err := recursiveAXFRRoot("_sip.xn--fsqu00a.xn--0zwm56d.", now)
	if err != nil {
		t.Fatal(err)
	}
	const wantRoot = "_sip.xn--fsqu00a.xn--0zwm56d_Mon-Jul-27-12-34-56-UTC-2026_recaxfr"
	if root != wantRoot {
		t.Fatalf("recursiveAXFRRoot() = %q, want %q", root, wantRoot)
	}

	path, err := zoneFilePath(t.TempDir(), "_sip.xn--fsqu00a.xn--0zwm56d.")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "_sip.xn--fsqu00a.xn--0zwm56d.zone" {
		t.Fatalf("zoneFilePath() = %q", path)
	}
}

func TestRecursiveAXFRPathsRejectUnsafeLabels(t *testing.T) {
	for _, label := range []string{
		"../../outside",
		`..\outside`,
		"/absolute/path",
		`C:\outside`,
		"example.com:53",
		"example.com?query",
		"example.com\nforged",
		"CON",
		"com1.",
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := recursiveAXFRRoot(label, time.Now()); err == nil {
				t.Fatalf("recursiveAXFRRoot(%q) succeeded", label)
			}
			if _, err := zoneFilePath(t.TempDir(), label); err == nil {
				t.Fatalf("zoneFilePath(%q) succeeded", label)
			}
		})
	}
}

func TestRecursiveAXFRRejectsEscapedDNSLabelEvenWhenDNSValid(t *testing.T) {
	const label = `mi\k.nl.`
	if _, ok := dns.IsDomainName(label); !ok {
		t.Fatal("test requires a DNS-valid escaped label")
	}
	if _, err := zoneFilePath(t.TempDir(), label); err == nil {
		t.Fatalf("zoneFilePath(%q) accepted a non-portable escaped label", label)
	}
}

func TestWriteZoneFileRejectsTraversalWithoutBasenameFallback(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "zones")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rrs := []dns.RR{mustRR(t, "example.com. 60 IN A 192.0.2.1")}
	if err := writeZoneFile(root, "../outside.", rrs); err == nil {
		t.Fatal("writeZoneFile() accepted traversal label")
	}
	if _, err := os.Stat(filepath.Join(parent, "outside.zone")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside zone file stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "outside.zone")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("basename fallback zone file stat error = %v", err)
	}
}

func TestRunRecursiveAXFRToRejectsUnsafeNSOwnerBeforeTransfer(t *testing.T) {
	root := t.TempDir()
	calls := 0
	transfer := func(_ context.Context, label, _ string, _ time.Duration) ([]dns.RR, error) {
		calls++
		if label != "example.com." {
			t.Fatalf("unexpected transfer for unsafe label %q", label)
		}
		return []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: "../outside.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns.example.com.",
		}}, nil
	}

	err := runRecursiveAXFRTo(context.Background(), "example.com", "127.0.0.1:53", time.Second, root, &bytes.Buffer{}, transfer)
	if err == nil || !strings.Contains(err.Error(), "unsafe AXFR zone label") {
		t.Fatalf("runRecursiveAXFRTo() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("transfer calls = %d, want 1", calls)
	}
}

func TestRunRecursiveAXFRToHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runRecursiveAXFRTo(ctx, "example.com", "127.0.0.1:53", time.Second, t.TempDir(), &bytes.Buffer{}, func(context.Context, string, string, time.Duration) ([]dns.RR, error) {
		t.Fatal("transfer should not be called")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestRunRecursiveAXFRToReturnsWriterError(t *testing.T) {
	err := runRecursiveAXFRTo(
		context.Background(),
		"example.com",
		"127.0.0.1:53",
		time.Second,
		t.TempDir(),
		errorWriter{},
		func(context.Context, string, string, time.Duration) ([]dns.RR, error) {
			t.Fatal("transfer should not be called after status write failure")
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "forced writer failure") {
		t.Fatalf("error = %v", err)
	}
}

func TestTransferZoneCancellationClosesAndDrainsTransfer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	firstEnvelopeSent := make(chan struct{})
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = connection.Close() }()
		dnsConnection := &dns.Conn{Conn: connection}
		query, err := dnsConnection.ReadMsg()
		if err != nil {
			serverResult <- err
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Answer = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      "ns.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  60,
			Minttl:  60,
		}}
		if err := dnsConnection.WriteMsg(reply); err != nil {
			serverResult <- err
			return
		}
		close(firstEnvelopeSent)
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Read(make([]byte, 1)); err == nil {
			serverResult <- fmt.Errorf("client connection remained open")
			return
		}
		serverResult <- nil
	}()

	ctx, cancel := context.WithCancel(context.Background())
	clientResult := make(chan error, 1)
	go func() {
		_, err := transferZone(ctx, "example.com", listener.Addr().String(), 2*time.Second)
		clientResult <- err
	}()
	select {
	case <-firstEnvelopeSent:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not send the first AXFR envelope")
	}
	cancel()
	select {
	case err := <-clientResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("transfer error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transfer did not stop after cancellation")
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe the closed transfer connection")
	}
}

func TestCollectTransferEnvelopesKeepsRecordsAfterSectionError(t *testing.T) {
	envelopes := make(chan *dns.Envelope, 2)
	envelopes <- &dns.Envelope{Error: errors.New("section failed")}
	envelopes <- &dns.Envelope{RR: []dns.RR{mustRR(t, "example.com. 60 IN A 192.0.2.1")}}
	close(envelopes)

	records, err := collectTransferEnvelopes(context.Background(), "example.com", new(dns.Transfer), envelopes)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].String() != "example.com.\t60\tIN\tA\t192.0.2.1" {
		t.Fatalf("records = %v", records)
	}
}

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(value)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
