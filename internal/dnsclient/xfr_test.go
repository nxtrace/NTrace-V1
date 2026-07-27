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
	got := recursiveAXFRRoot("example.com", now)
	const want = "example.com_Mon-Jul-27-12-34-56-UTC-2026_recaxfr"
	if got != want {
		t.Fatalf("recursiveAXFRRoot() = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, `<>:"/\\|?*`) {
		t.Fatalf("recursiveAXFRRoot() = %q, contains a Windows-invalid path character", got)
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
