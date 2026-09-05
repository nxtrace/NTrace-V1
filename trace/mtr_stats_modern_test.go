package trace

import (
	"encoding/json"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

type modernTestAddr struct {
	network string
	value   string
}

func (a modernTestAddr) Network() string { return a.network }
func (a modernTestAddr) String() string  { return a.value }

func modernTestHop(ttl int, addr net.Addr, host string, rtt time.Duration) Hop {
	return Hop{
		Success:  true,
		Address:  addr,
		Hostname: host,
		TTL:      ttl,
		RTT:      rtt,
	}
}

func modernTestIPHop(ttl int, ip string, rtt time.Duration) Hop {
	return modernTestHop(ttl, &net.IPAddr{IP: net.ParseIP(ip)}, "", rtt)
}

func modernTestResult(hopsByTTL map[int][]Hop) *Result {
	maxTTL := 0
	for ttl := range hopsByTTL {
		if ttl > maxTTL {
			maxTTL = ttl
		}
	}
	res := &Result{Hops: make([][]Hop, maxTTL)}
	for ttl, hops := range hopsByTTL {
		res.Hops[ttl-1] = hops
	}
	return res
}

func modernTestSnapshotJSON(t *testing.T, stats []MTRHopStat) string {
	t.Helper()
	b, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal MTR snapshot: %v", err)
	}
	return string(b)
}

func modernTestOrder(stats []MTRHopStat) []string {
	order := make([]string, len(stats))
	for i, stat := range stats {
		order[i] = strings.Join([]string{
			strconv.Itoa(stat.TTL),
			stat.IP,
		}, "|")
	}
	return order
}

func modernTestFindIP(t *testing.T, stats []MTRHopStat, ip string) MTRHopStat {
	t.Helper()
	for _, stat := range stats {
		if stat.IP == ip {
			return stat
		}
	}
	t.Fatalf("missing MTR row for IP %q: %+v", ip, stats)
	return MTRHopStat{}
}

func modernTestFindTTLIP(t *testing.T, stats []MTRHopStat, ttl int, ip string) MTRHopStat {
	t.Helper()
	for _, stat := range stats {
		if stat.TTL == ttl && stat.IP == ip {
			return stat
		}
	}
	t.Fatalf("missing MTR row for TTL %d and IP %q: %+v", ttl, ip, stats)
	return MTRHopStat{}
}

func TestMTRAggregatorModernStableObservationOrder(t *testing.T) {
	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{
		1: {
			modernTestIPHop(1, "192.0.2.2", 12*time.Millisecond),
			modernTestIPHop(1, "192.0.2.1", 11*time.Millisecond),
		},
		2: {modernTestIPHop(2, "198.51.100.8", 20*time.Millisecond)},
		3: {
			modernTestIPHop(3, "203.0.113.4", 34*time.Millisecond),
			modernTestIPHop(3, "203.0.113.5", 35*time.Millisecond),
		},
	}), 2)

	wantInitial := []string{
		"1|192.0.2.2",
		"1|192.0.2.1",
		"2|198.51.100.8",
		"3|203.0.113.4",
		"3|203.0.113.5",
	}
	if got := modernTestOrder(agg.Snapshot()); !reflect.DeepEqual(got, wantInitial) {
		t.Fatalf("initial order = %q, want %q", got, wantInitial)
	}

	agg.Update(modernTestResult(map[int][]Hop{
		1: {
			modernTestIPHop(1, "192.0.2.1", 21*time.Millisecond),
			modernTestIPHop(1, "192.0.2.3", 23*time.Millisecond),
			modernTestIPHop(1, "192.0.2.2", 22*time.Millisecond),
		},
		3: {
			modernTestIPHop(3, "203.0.113.5", 45*time.Millisecond),
			modernTestIPHop(3, "203.0.113.4", 44*time.Millisecond),
		},
	}), 3)
	wantAfterUpdate := []string{
		"1|192.0.2.2",
		"1|192.0.2.1",
		"1|192.0.2.3",
		"2|198.51.100.8",
		"3|203.0.113.4",
		"3|203.0.113.5",
	}
	if got := modernTestOrder(agg.Snapshot()); !reflect.DeepEqual(got, wantAfterUpdate) {
		t.Fatalf("order after repeated observations = %q, want %q", got, wantAfterUpdate)
	}

	if !agg.PatchMetadataByIP("192.0.2.1", "patched.example", &ipgeo.IPGeoData{Country: "ZZ"}) {
		t.Fatal("metadata patch did not update the observed row")
	}
	if got := modernTestOrder(agg.Snapshot()); !reflect.DeepEqual(got, wantAfterUpdate) {
		t.Fatalf("metadata patch changed row order: got %q, want %q", got, wantAfterUpdate)
	}
}

func TestMTRAggregatorModernFirstAttemptMetadataWinsWithinUpdate(t *testing.T) {
	agg := NewMTRAggregator()
	first := modernTestIPHop(1, "192.0.2.6", 10*time.Millisecond)
	second := modernTestIPHop(1, "192.0.2.6", 11*time.Millisecond)
	second.Hostname = "later.example"

	row := modernTestFindIP(t, agg.Update(modernTestResult(map[int][]Hop{
		1: {first, second},
	}), 2), "192.0.2.6")
	if row.Host != "" {
		t.Fatalf("host = %q, want first observation's empty metadata", row.Host)
	}

	first.Hostname = "first.example"
	second.Hostname = "last.example"
	row = modernTestFindIP(t, agg.Update(modernTestResult(map[int][]Hop{
		1: {first, second},
	}), 2), "192.0.2.6")
	if row.Host != "first.example" {
		t.Fatalf("host = %q, want first observation metadata", row.Host)
	}
}

func TestMTRAggregatorModernComparableIdentities(t *testing.T) {
	mappedIPv4 := &net.IPAddr{IP: net.ParseIP("::ffff:192.0.2.10")}
	plainIPv4 := &net.TCPAddr{IP: net.IP{192, 0, 2, 10}, Port: 33434}
	ipv6Compressed := &net.IPAddr{IP: net.ParseIP("2001:db8::10")}
	ipv6Expanded := &net.UDPAddr{IP: net.ParseIP("2001:0db8:0:0:0:0:0:10"), Port: 33434}

	agg := NewMTRAggregator()
	stats := agg.Update(modernTestResult(map[int][]Hop{
		1: {
			modernTestHop(1, mappedIPv4, "", 1*time.Millisecond),
			modernTestHop(1, plainIPv4, "", 2*time.Millisecond),
			modernTestHop(1, ipv6Compressed, "", 3*time.Millisecond),
			modernTestHop(1, ipv6Expanded, "", 4*time.Millisecond),
			{Success: false, TTL: 1},
			{Success: false, TTL: 1},
			modernTestHop(1, nil, "Router.Local", 5*time.Millisecond),
			modernTestHop(1, nil, "router.local", 6*time.Millisecond),
			modernTestHop(1, modernTestAddr{network: "alpha", value: "edge"}, "alpha-host", 7*time.Millisecond),
			modernTestHop(1, modernTestAddr{network: "beta", value: "edge"}, "beta-host", 8*time.Millisecond),
		},
	}), 10)

	if len(stats) != 6 {
		t.Fatalf("identity rows = %d, want 6: %+v", len(stats), stats)
	}
	if row := modernTestFindIP(t, stats, "192.0.2.10"); row.Snt != 2 || row.Received != 2 {
		t.Fatalf("IPv4 mapped/plain identity was not merged: %+v", row)
	}
	if row := modernTestFindIP(t, stats, "2001:db8::10"); row.Snt != 2 || row.Received != 2 {
		t.Fatalf("equivalent IPv6 addresses were not merged: %+v", row)
	}

	unknownRows := 0
	hostOnlyRows := 0
	fallbackRows := map[string]int{}
	for _, row := range stats {
		switch {
		case row.IP == "" && row.Host == "":
			unknownRows++
			if row.Snt != 2 || row.Received != 0 {
				t.Fatalf("unknown row = %+v, want Snt=2 Received=0", row)
			}
		case row.IP == "" && strings.EqualFold(row.Host, "router.local"):
			hostOnlyRows++
			if row.Snt != 2 || row.Received != 2 {
				t.Fatalf("host-only row = %+v, want Snt=2 Received=2", row)
			}
		case row.IP == "edge":
			fallbackRows[row.Host]++
		}
	}
	if unknownRows != 1 {
		t.Fatalf("unknown rows = %d, want 1", unknownRows)
	}
	if hostOnlyRows != 1 {
		t.Fatalf("host-only rows = %d, want 1", hostOnlyRows)
	}
	if fallbackRows["alpha-host"] != 1 || fallbackRows["beta-host"] != 1 {
		t.Fatalf("non-IP fallback identities were not isolated by network: %v", fallbackRows)
	}
}

func TestMTRAggregatorModernSnapshotDeepIsolation(t *testing.T) {
	geo := &ipgeo.IPGeoData{
		Country: "US",
		Router: map[string][]string{
			"path": {"left", "right"},
		},
	}
	hop := modernTestIPHop(1, "192.0.2.20", 20*time.Millisecond)
	hop.Hostname = "original.example"
	hop.Geo = geo
	hop.MPLS = []string{"label-a", "label-b"}

	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{1: {hop}}), 1)
	first := agg.Snapshot()
	second := agg.Snapshot()
	if len(first) != 1 || len(second) != 1 || len(first[0].MPLS) != 2 || first[0].Geo == nil ||
		len(first[0].Geo.Router["path"]) != 2 {
		t.Fatalf("snapshot lost nested test data: first=%+v second=%+v", first, second)
	}
	want := modernTestSnapshotJSON(t, second)

	first[0].Host = "mutated.example"
	first[0].MPLS[0] = "mutated-label"
	first[0].Geo.Country = "XX"
	first[0].Geo.Router["path"][0] = "mutated-path"
	first[0].Geo.Router["new"] = []string{"new-value"}
	first[0].Response = &MTRProbeResponse{
		Kind:        MTRResponseDestination,
		Description: "caller-attached response",
		Marker:      "!X",
	}
	first[0].Response.Description = "mutated response"

	if got := modernTestSnapshotJSON(t, second); got != want {
		t.Fatalf("consecutive snapshots share caller-mutable state:\n got %s\nwant %s", got, want)
	}
	if got := modernTestSnapshotJSON(t, agg.Snapshot()); got != want {
		t.Fatalf("caller mutation leaked into aggregator snapshot:\n got %s\nwant %s", got, want)
	}
	if second[0].Response != nil {
		t.Fatalf("caller-attached response leaked into another snapshot: %+v", second[0].Response)
	}
}

func TestMTRSchedulerModernResponseSnapshotIsolation(t *testing.T) {
	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.21", 21*time.Millisecond)},
	}), 1)
	tracker := newMTRPathTracker(true, 3, nil)
	tracker.observe(1, mtrProbeResponseWithPeer(&MTRProbeResponse{
		Kind:        MTRResponseTransit,
		Description: "ICMP Time Exceeded",
		Marker:      "!T",
	}, &net.IPAddr{IP: net.ParseIP("192.0.2.21")}))
	runtime := &mtrSchedulerRuntime{agg: agg, pathTracker: tracker}

	first := runtime.snapshotStats()
	second := runtime.snapshotStats()
	if len(first) != 1 || first[0].Response == nil || len(second) != 1 || second[0].Response == nil {
		t.Fatalf("scheduler snapshots did not include response: first=%+v second=%+v", first, second)
	}
	want := *second[0].Response
	first[0].Response.Kind = MTRResponseDestination
	first[0].Response.Description = "mutated response"
	first[0].Response.Marker = "!X"
	if got := second[0].Response; *got != want {
		t.Fatalf("consecutive scheduler snapshots share response: got %+v, want %+v", got, want)
	}
	third := runtime.snapshotStats()
	if len(third) != 1 || third[0].Response == nil || *third[0].Response != want {
		t.Fatalf("response mutation leaked into later scheduler snapshot: got %+v, want %+v", third, want)
	}
}

func TestMTRAggregatorModernPublishedSnapshotSurvivesMutations(t *testing.T) {
	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.30", 30*time.Millisecond)},
		2: {modernTestIPHop(2, "192.0.2.31", 31*time.Millisecond)},
		3: {modernTestIPHop(3, "192.0.2.32", 32*time.Millisecond)},
	}), 1)
	published := agg.Snapshot()
	want := modernTestSnapshotJSON(t, published)
	assertPublishedUnchanged := func(stage string) {
		t.Helper()
		if got := modernTestSnapshotJSON(t, published); got != want {
			t.Fatalf("published snapshot changed after %s:\n got %s\nwant %s", stage, got, want)
		}
	}

	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.30", 40*time.Millisecond)},
	}), 1)
	assertPublishedUnchanged("Update")
	if !agg.PatchMetadataByIP("192.0.2.30", "patched.example", &ipgeo.IPGeoData{
		Country: "ZZ",
		Router:  map[string][]string{"path": {"patched"}},
	}) {
		t.Fatal("metadata patch did not change the live aggregator")
	}
	assertPublishedUnchanged("PatchMetadataByIP")
	agg.ClearAbove(2)
	assertPublishedUnchanged("ClearAbove")
	agg.ClearHop(2)
	assertPublishedUnchanged("ClearHop")
	agg.Reset()
	assertPublishedUnchanged("Reset")
	if agg.snapshot != nil {
		t.Fatalf("Reset retained %d internally cached rows", len(agg.snapshot))
	}
}

func TestMTRAggregatorModernCloneIsolationByTTL(t *testing.T) {
	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.40", 10*time.Millisecond)},
		2: {modernTestIPHop(2, "192.0.2.41", 20*time.Millisecond)},
	}), 1)
	clone := agg.Clone()
	cloneBaseline := modernTestSnapshotJSON(t, clone.Snapshot())

	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.40", 30*time.Millisecond)},
	}), 1)
	if got := modernTestSnapshotJSON(t, clone.Snapshot()); got != cloneBaseline {
		t.Fatalf("original TTL update changed clone:\n got %s\nwant %s", got, cloneBaseline)
	}

	clone.Update(modernTestResult(map[int][]Hop{
		2: {modernTestIPHop(2, "192.0.2.41", 40*time.Millisecond)},
	}), 1)
	originalStats := agg.Snapshot()
	if got := modernTestFindIP(t, originalStats, "192.0.2.40").Snt; got != 2 {
		t.Fatalf("original TTL 1 Snt = %d, want 2", got)
	}
	if got := modernTestFindIP(t, originalStats, "192.0.2.41").Snt; got != 1 {
		t.Fatalf("clone TTL 2 update changed original Snt to %d", got)
	}

	agg.ClearHop(1)
	if got := modernTestFindIP(t, clone.Snapshot(), "192.0.2.40").Snt; got != 1 {
		t.Fatalf("original ClearHop changed clone TTL 1 Snt to %d", got)
	}
	preserved := agg.Clone()
	clone.Reset()
	if got := clone.Snapshot(); len(got) != 0 {
		t.Fatalf("clone Reset left %d rows", len(got))
	}
	if got := agg.Snapshot(); len(got) != 1 || got[0].IP != "192.0.2.41" {
		t.Fatalf("clone Reset changed original: %+v", got)
	}
	agg.Reset()
	if got := preserved.Snapshot(); len(got) != 1 || got[0].IP != "192.0.2.41" {
		t.Fatalf("original Reset changed preserved clone: %+v", got)
	}
}

func TestMTRAggregatorModernCloneMetadataPatchIsolation(t *testing.T) {
	agg := NewMTRAggregator()
	agg.Update(modernTestResult(map[int][]Hop{
		1: {modernTestIPHop(1, "192.0.2.42", 10*time.Millisecond)},
	}), 1)
	clone := agg.Clone()

	geo := &ipgeo.IPGeoData{
		Country: "ZZ",
		Router:  map[string][]string{"path": {"patched"}},
	}
	if !clone.PatchMetadataByIP("192.0.2.42", "clone.example", geo) {
		t.Fatal("clone metadata patch did not update the row")
	}
	cloneRow := modernTestFindIP(t, clone.Snapshot(), "192.0.2.42")
	if cloneRow.Host != "clone.example" || cloneRow.Geo == nil || cloneRow.Geo.Country != "ZZ" {
		t.Fatalf("clone row was not patched: %+v", cloneRow)
	}
	originalRow := modernTestFindIP(t, agg.Snapshot(), "192.0.2.42")
	if originalRow.Host != "" || originalRow.Geo != nil {
		t.Fatalf("clone metadata patch changed original row: %+v", originalRow)
	}

	if !agg.PatchMetadataByIP("192.0.2.42", "original.example", &ipgeo.IPGeoData{Country: "US"}) {
		t.Fatal("original metadata patch did not update the row")
	}
	cloneRow = modernTestFindIP(t, clone.Snapshot(), "192.0.2.42")
	if cloneRow.Host != "clone.example" || cloneRow.Geo == nil || cloneRow.Geo.Country != "ZZ" {
		t.Fatalf("original metadata patch changed clone row: %+v", cloneRow)
	}
}

func TestMTRAggregatorModernCloneMigrationIsolation(t *testing.T) {
	t.Run("move into empty TTL", func(t *testing.T) {
		hop := modernTestIPHop(3, "192.0.2.43", 10*time.Millisecond)
		hop.MPLS = []string{"label-a"}
		agg := NewMTRAggregator()
		agg.Update(modernTestResult(map[int][]Hop{3: {hop}}), 1)
		clone := agg.Clone()

		clone.MigrateStats(3, 1, 0)
		clone.Update(modernTestResult(map[int][]Hop{
			1: {modernTestIPHop(1, "192.0.2.43", 20*time.Millisecond)},
		}), 1)
		moved := modernTestFindTTLIP(t, clone.Snapshot(), 1, "192.0.2.43")
		if moved.Snt != 2 || len(moved.MPLS) != 1 || moved.MPLS[0] != "label-a" {
			t.Fatalf("moved clone row = %+v, want two probes and preserved MPLS", moved)
		}
		original := agg.Snapshot()
		if len(original) != 1 || original[0].TTL != 3 || original[0].Snt != 1 {
			t.Fatalf("clone move changed original rows: %+v", original)
		}
	})

	t.Run("merge into existing TTL", func(t *testing.T) {
		base := modernTestIPHop(1, "192.0.2.44", 10*time.Millisecond)
		base.MPLS = []string{"label-a"}
		migrated := modernTestIPHop(3, "192.0.2.44", 30*time.Millisecond)
		migrated.MPLS = []string{"label-b"}
		migrated.Geo = &ipgeo.IPGeoData{
			Country: "ZZ",
			Router:  map[string][]string{"path": {"migrated"}},
		}
		agg := NewMTRAggregator()
		agg.Update(modernTestResult(map[int][]Hop{
			1: {base},
			3: {migrated},
		}), 1)
		clone := agg.Clone()

		clone.MigrateStats(3, 1, 0)
		merged := modernTestFindTTLIP(t, clone.Snapshot(), 1, "192.0.2.44")
		if merged.Snt != 2 || merged.Geo == nil || merged.Geo.Country != "ZZ" ||
			!reflect.DeepEqual(merged.MPLS, []string{"label-a", "label-b"}) {
			t.Fatalf("merged clone row = %+v", merged)
		}
		original := agg.Snapshot()
		originalBase := modernTestFindTTLIP(t, original, 1, "192.0.2.44")
		originalSource := modernTestFindTTLIP(t, original, 3, "192.0.2.44")
		if originalBase.Snt != 1 || originalBase.Geo != nil ||
			!reflect.DeepEqual(originalBase.MPLS, []string{"label-a"}) {
			t.Fatalf("clone merge changed original target: %+v", originalBase)
		}
		if originalSource.Snt != 1 || originalSource.Geo == nil ||
			!reflect.DeepEqual(originalSource.MPLS, []string{"label-b"}) {
			t.Fatalf("clone merge changed original source: %+v", originalSource)
		}
	})
}

func TestCloneMTRStatsPreservesEmptySliceShape(t *testing.T) {
	src := []MTRHopStat{{
		Geo: &ipgeo.IPGeoData{
			Router: map[string][]string{
				"empty": make([]string, 0),
				"nil":   nil,
			},
		},
		MPLS: make([]string, 0),
	}}

	got := cloneMTRStats(src)
	if got[0].MPLS == nil {
		t.Fatal("non-nil empty MPLS became nil")
	}
	if got[0].Geo.Router["empty"] == nil {
		t.Fatal("non-nil empty router path became nil")
	}
	if got[0].Geo.Router["nil"] != nil {
		t.Fatal("nil router path became non-nil")
	}
}

func TestMTRAggregatorModernSnapshotCacheInvalidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *MTRAggregator)
		verify func(*testing.T, []MTRHopStat)
	}{
		{
			name: "Update",
			mutate: func(_ *testing.T, agg *MTRAggregator) {
				agg.Update(modernTestResult(map[int][]Hop{
					1: {modernTestIPHop(1, "192.0.2.50", 50*time.Millisecond)},
				}), 1)
			},
			verify: func(t *testing.T, stats []MTRHopStat) {
				if got := modernTestFindIP(t, stats, "192.0.2.50").Snt; got != 2 {
					t.Fatalf("Snt after Update = %d, want 2", got)
				}
			},
		},
		{
			name:   "Reset",
			mutate: func(_ *testing.T, agg *MTRAggregator) { agg.Reset() },
			verify: func(t *testing.T, stats []MTRHopStat) {
				if len(stats) != 0 {
					t.Fatalf("rows after Reset = %d, want 0", len(stats))
				}
			},
		},
		{
			name:   "ClearHop",
			mutate: func(_ *testing.T, agg *MTRAggregator) { agg.ClearHop(2) },
			verify: func(t *testing.T, stats []MTRHopStat) {
				for _, stat := range stats {
					if stat.TTL == 2 {
						t.Fatalf("ClearHop left TTL 2 row: %+v", stat)
					}
				}
			},
		},
		{
			name:   "ClearAbove",
			mutate: func(_ *testing.T, agg *MTRAggregator) { agg.ClearAbove(1) },
			verify: func(t *testing.T, stats []MTRHopStat) {
				if len(stats) != 1 || stats[0].TTL != 1 {
					t.Fatalf("rows after ClearAbove = %+v, want only TTL 1", stats)
				}
			},
		},
		{
			name:   "MigrateStats",
			mutate: func(_ *testing.T, agg *MTRAggregator) { agg.MigrateStats(3, 1, 0) },
			verify: func(t *testing.T, stats []MTRHopStat) {
				if len(stats) != 3 {
					t.Fatalf("rows after MigrateStats = %d, want 3: %+v", len(stats), stats)
				}
				if row := modernTestFindIP(t, stats, "192.0.2.52"); row.TTL != 1 {
					t.Fatalf("migrated row TTL = %d, want 1", row.TTL)
				}
				for _, stat := range stats {
					if stat.TTL == 3 {
						t.Fatalf("MigrateStats left TTL 3 row: %+v", stat)
					}
				}
			},
		},
		{
			name: "PatchMetadataByIP",
			mutate: func(t *testing.T, agg *MTRAggregator) {
				t.Helper()
				if !agg.PatchMetadataByIP("192.0.2.50", "patched.example", &ipgeo.IPGeoData{Country: "ZZ"}) {
					t.Fatal("metadata patch did not change the live aggregator")
				}
			},
			verify: func(t *testing.T, stats []MTRHopStat) {
				row := modernTestFindIP(t, stats, "192.0.2.50")
				if row.Host != "patched.example" || row.Geo == nil || row.Geo.Country != "ZZ" {
					t.Fatalf("patched row = %+v", row)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			agg := NewMTRAggregator()
			agg.Update(modernTestResult(map[int][]Hop{
				1: {modernTestIPHop(1, "192.0.2.50", 10*time.Millisecond)},
				2: {modernTestIPHop(2, "192.0.2.51", 20*time.Millisecond)},
				3: {modernTestIPHop(3, "192.0.2.52", 30*time.Millisecond)},
			}), 1)
			published := agg.Snapshot()
			before := modernTestSnapshotJSON(t, published)
			if got := modernTestSnapshotJSON(t, agg.Snapshot()); got != before {
				t.Fatalf("unchanged consecutive snapshot = %s, want %s", got, before)
			}

			tc.mutate(t, agg)
			after := agg.Snapshot()
			tc.verify(t, after)
			if got := modernTestSnapshotJSON(t, after); got == before {
				t.Fatalf("%s did not invalidate published snapshot", tc.name)
			}
			if got := modernTestSnapshotJSON(t, published); got != before {
				t.Fatalf("%s mutated the previously published snapshot", tc.name)
			}
		})
	}
}

func TestMTRAggregatorModernPreviewMatchesIndependentReplay(t *testing.T) {
	baseRounds := []*Result{
		modernTestResult(map[int][]Hop{
			1: {
				modernTestIPHop(1, "192.0.2.60", 10*time.Millisecond),
				modernTestIPHop(1, "192.0.2.61", 11*time.Millisecond),
			},
			2: {modernTestIPHop(2, "192.0.2.62", 20*time.Millisecond)},
			3: {modernTestIPHop(3, "192.0.2.63", 30*time.Millisecond)},
		}),
		modernTestResult(map[int][]Hop{
			1: {
				modernTestIPHop(1, "192.0.2.61", 12*time.Millisecond),
				modernTestIPHop(1, "192.0.2.60", 13*time.Millisecond),
			},
			3: {modernTestIPHop(3, "192.0.2.63", 31*time.Millisecond)},
		}),
	}
	partial := modernTestResult(map[int][]Hop{
		2: {
			modernTestIPHop(2, "192.0.2.62", 22*time.Millisecond),
			modernTestIPHop(2, "192.0.2.64", 24*time.Millisecond),
		},
	})

	original := NewMTRAggregator()
	for _, round := range baseRounds {
		original.Update(round, 2)
	}
	originalBefore := modernTestSnapshotJSON(t, original.Snapshot())
	preview := original.Clone()
	got := preview.Update(partial, 2)

	replayed := NewMTRAggregator()
	for _, round := range baseRounds {
		replayed.Update(round, 2)
	}
	want := replayed.Update(partial, 2)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clone+partial preview differs from independent replay:\n got  %+v\nwant %+v", got, want)
	}
	if after := modernTestSnapshotJSON(t, original.Snapshot()); after != originalBefore {
		t.Fatalf("preview update changed original:\n got %s\nwant %s", after, originalBefore)
	}
}
