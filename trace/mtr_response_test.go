package trace

import (
	"net"
	"reflect"
	"testing"
)

func TestMTRPathTrackerBoundedEvidencePriority(t *testing.T) {
	var changes []*StopReason
	tracker := newMTRPathTracker(true, 30, func(reason *StopReason) {
		changes = append(changes, reason)
	})

	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "host unreachable", Marker: "!H"})
	assertMTRPathEnd(t, tracker.pathEnd(), 4, StopReasonUnreachable)

	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseTransit, Description: "time exceeded"})
	if got := tracker.pathEnd(); got != nil {
		t.Fatalf("path end after transit = %#v, want nil", got)
	}

	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "network unreachable", Marker: "!N"})
	if got := tracker.pathEnd(); got != nil {
		t.Fatalf("bounded transit evidence must remain authoritative, got %#v", got)
	}

	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseDestination, Description: "echo reply"})
	assertMTRPathEnd(t, tracker.pathEnd(), 4, StopReasonDestination)
	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseTransit})
	assertMTRPathEnd(t, tracker.pathEnd(), 4, StopReasonDestination)

	if got, want := len(changes), 3; got != want {
		t.Fatalf("path-end changes = %d, want %d (%#v)", got, want, changes)
	}
}

func TestMTRPathTrackerDestinationIsStickyAcrossTTLs(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		name := "unbounded"
		if bounded {
			name = "bounded"
		}
		t.Run(name, func(t *testing.T) {
			tracker := newMTRPathTracker(bounded, 30, nil)
			tracker.observe(5, &MTRProbeResponse{Kind: MTRResponseDestination, Description: "destination at 5"})
			tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "unreachable at 3", Marker: "!H"})
			want := &StopReason{Hop: 5, Reason: StopReasonDestination, Responses: []string{"destination at 5"}}
			if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
				t.Fatalf("pathEnd() after lower unreachable = %#v, want sticky destination %#v", got, want)
			}

			tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseDestination, Description: "destination at 4"})
			want = &StopReason{Hop: 4, Reason: StopReasonDestination, Responses: []string{"destination at 4"}}
			if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
				t.Fatalf("pathEnd() after lower destination = %#v, want %#v", got, want)
			}
		})
	}
}

func TestMTRPathTrackerBoundedAccumulatesWinningEvidence(t *testing.T) {
	var changes []*StopReason
	tracker := newMTRPathTracker(true, 30, func(reason *StopReason) {
		changes = append(changes, reason)
	})
	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "network unreachable", Marker: "!N"})
	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "host unreachable", Marker: "!H"})
	tracker.observe(4, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "network unreachable", Marker: "!N"})

	want := &StopReason{
		Hop:       4,
		Reason:    StopReasonUnreachable,
		Responses: []string{"host unreachable", "network unreachable"},
		Markers:   []string{"!H", "!N"},
	}
	if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pathEnd() = %#v, want %#v", got, want)
	}
	if got := len(changes); got != 2 {
		t.Fatalf("path-end changes = %d, want two distinct evidence states", got)
	}

	tracker = newMTRPathTracker(true, 30, nil)
	tracker.observeStopReason(&StopReason{
		Hop:       5,
		Reason:    StopReasonDestination,
		Responses: []string{"TCP RST from 192.0.2.2", "TCP SYN/ACK from 192.0.2.1", "TCP RST from 192.0.2.2"},
	})
	want = &StopReason{
		Hop:       5,
		Reason:    StopReasonDestination,
		Responses: []string{"TCP RST from 192.0.2.2", "TCP SYN/ACK from 192.0.2.1"},
	}
	if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pathEnd() from StopReason = %#v, want %#v", got, want)
	}
}

func TestMTRPathTrackerUnboundedReopensProvisionalEdge(t *testing.T) {
	var changes []*StopReason
	tracker := newMTRPathTracker(false, 30, func(reason *StopReason) {
		changes = append(changes, reason)
	})

	tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "host unreachable", Marker: "!H"})
	assertMTRPathEnd(t, tracker.pathEnd(), 3, StopReasonUnreachable)
	tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseTransit})
	if got := tracker.pathEnd(); got != nil {
		t.Fatalf("path end after transit = %#v, want nil", got)
	}
	tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "network unreachable", Marker: "!N"})
	want := &StopReason{Hop: 3, Reason: StopReasonUnreachable, Responses: []string{"network unreachable"}, Markers: []string{"!N"}}
	if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reopened path end = %#v, want latest live evidence %#v", got, want)
	}
	tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseDestination})
	assertMTRPathEnd(t, tracker.pathEnd(), 3, StopReasonDestination)
	tracker.observe(3, &MTRProbeResponse{Kind: MTRResponseTransit})
	assertMTRPathEnd(t, tracker.pathEnd(), 3, StopReasonDestination)

	tracker.reset()
	if got := tracker.pathEnd(); got != nil {
		t.Fatalf("path end after reset = %#v, want nil", got)
	}
	if changes[len(changes)-1] != nil {
		t.Fatalf("last reset callback = %#v, want nil", changes[len(changes)-1])
	}
	if got := len(changes); got != 5 {
		t.Fatalf("path-end changes = %d, want unreachable, reopen, unreachable, destination, reset", got)
	}
}

func TestMTRPathTrackerMaxHopsOnlyWithoutSemanticEdge(t *testing.T) {
	tracker := newMTRPathTracker(true, 12, nil)
	if !tracker.completeAtMaxHops() {
		t.Fatal("completeAtMaxHops() = false, want true")
	}
	assertMTRPathEnd(t, tracker.pathEnd(), 12, StopReasonMaxHops)

	tracker = newMTRPathTracker(true, 12, nil)
	tracker.observe(7, &MTRProbeResponse{Kind: MTRResponseUnreachable})
	if tracker.completeAtMaxHops() {
		t.Fatal("completeAtMaxHops() replaced semantic path edge")
	}
	assertMTRPathEnd(t, tracker.pathEnd(), 7, StopReasonUnreachable)
}

func TestMTRPathTrackerCopiesCallbackState(t *testing.T) {
	var callback *StopReason
	tracker := newMTRPathTracker(false, 30, func(reason *StopReason) {
		callback = reason
	})
	tracker.observe(2, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "blocked", Marker: "!X"})
	callback.Responses[0] = "mutated"
	callback.Markers[0] = "mutated"

	want := &StopReason{Hop: 2, Reason: StopReasonUnreachable, Responses: []string{"blocked"}, Markers: []string{"!X"}}
	if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pathEnd() = %#v, want %#v", got, want)
	}
}

func TestMTRPathTrackerPathEndReturnsCopy(t *testing.T) {
	tracker := newMTRPathTracker(false, 30, nil)
	tracker.observe(2, &MTRProbeResponse{Kind: MTRResponseUnreachable, Description: "blocked", Marker: "!X"})

	read := tracker.pathEnd()
	read.Hop = 99
	read.Responses[0] = "mutated"
	read.Markers[0] = "mutated"

	want := &StopReason{Hop: 2, Reason: StopReasonUnreachable, Responses: []string{"blocked"}, Markers: []string{"!X"}}
	if got := tracker.pathEnd(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pathEnd() after caller mutation = %#v, want %#v", got, want)
	}
}

func TestMTRProbeResponseMarkerOnlyDecoratesRespondingMultipathRow(t *testing.T) {
	tracker := newMTRPathTracker(false, 30, nil)
	transitPeer := &net.IPAddr{IP: net.ParseIP("192.0.2.21")}
	unreachablePeer := &net.IPAddr{IP: net.ParseIP("192.0.2.22")}
	tracker.observe(2, mtrProbeResponseFromProbe(responseWithPeer(probeResponse{
		kind: probeResponseTransit,
	}, transitPeer)))

	res := &Result{
		Hops: make([][]Hop, 2),
		responses: map[int][]probeResponse{
			2: {responseWithPeer(probeResponse{
				kind:   probeResponseUnreachable,
				marker: "!H",
			}, unreachablePeer)},
		},
	}
	res.Hops[1] = []Hop{
		{TTL: 2, Success: true, Address: transitPeer},
		{TTL: 2, Success: true, Address: unreachablePeer},
	}
	tracker.observe(2, bestMTRProbeResponse(res, 2))

	transit := mtrProbeResponseForStat(tracker, MTRHopStat{TTL: 2, IP: transitPeer.IP.String()})
	if transit != nil {
		t.Fatalf("transit multipath row response = %#v, want nil", transit)
	}
	matched := mtrProbeResponseForStat(tracker, MTRHopStat{TTL: 2, IP: unreachablePeer.IP.String()})
	if matched == nil || matched.Kind != MTRResponseUnreachable || matched.Marker != "!H" {
		t.Fatalf("responding multipath row response = %#v, want unreachable !H", matched)
	}
}

func assertMTRPathEnd(t *testing.T, reason *StopReason, hop int, kind string) {
	t.Helper()
	if reason == nil || reason.Hop != hop || reason.Reason != kind {
		t.Fatalf("path end = %#v, want hop=%d reason=%s", reason, hop, kind)
	}
}
