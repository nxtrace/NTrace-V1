package trace

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

func TestMTRAggregatorSnapshotGolden(t *testing.T) {
	agg := NewMTRAggregator()

	agg.Update(mtrGoldenResult(1,
		Hop{
			Success:  true,
			Address:  &net.IPAddr{IP: net.ParseIP("192.0.2.1")},
			Hostname: "edge.example",
			TTL:      1,
			RTT:      10 * time.Millisecond,
			MPLS: []string{
				"[MPLS: Lbl 200, TC 0, S 1, TTL 63]",
				"[MPLS: Lbl 100, TC 0, S 0, TTL 64]",
			},
		},
		Hop{TTL: 1},
	), 2)
	agg.Update(mtrGoldenResult(2, Hop{
		Success:  true,
		Address:  &net.IPAddr{IP: net.ParseIP("198.51.100.1")},
		Hostname: "core-a.example",
		TTL:      2,
		RTT:      20 * time.Millisecond,
	}), 1)
	agg.Update(mtrGoldenResult(2, Hop{
		Success:  true,
		Address:  &net.IPAddr{IP: net.ParseIP("198.51.100.2")},
		Hostname: "core-b.example",
		TTL:      2,
		RTT:      30 * time.Millisecond,
	}), 1)
	agg.Update(mtrGoldenResult(2, Hop{TTL: 2}), 1)
	agg.Update(mtrGoldenResult(3, Hop{
		Success: true,
		Address: &net.IPAddr{IP: net.ParseIP("2001:db8::3")},
		TTL:     3,
		RTT:     40 * time.Millisecond,
	}), 1)

	got, err := json.MarshalIndent(MTRSnapshot{Iteration: 3, Stats: agg.Snapshot()}, "", "  ")
	if err != nil {
		t.Fatalf("marshal MTR snapshot: %v", err)
	}
	got = append(got, '\n')

	want, err := os.ReadFile("testdata/mtr_snapshot.golden.json")
	if err != nil {
		t.Fatalf("read MTR snapshot golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MTR snapshot changed\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func mtrGoldenResult(ttl int, attempts ...Hop) *Result {
	res := &Result{Hops: make([][]Hop, ttl)}
	res.Hops[ttl-1] = attempts
	return res
}
