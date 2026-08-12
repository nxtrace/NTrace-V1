package trace

import (
	"net"
	"reflect"
	"sync/atomic"
	"testing"
)

func resultWithResponses(responses ...probeResponse) *Result {
	res := &Result{Hops: make([][]Hop, 1)}
	for _, response := range responses {
		res.recordResponse(1, response)
	}
	return res
}

func TestStopAfterTTLDestinationWins(t *testing.T) {
	res := resultWithResponses(
		probeResponse{kind: probeResponseTransit},
		probeResponse{kind: probeResponseDestination},
		probeResponse{kind: probeResponseUnreachable, marker: "!H"},
	)

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonDestination || got.Hop != 1 {
		t.Fatalf("StopReason = %#v, want destination at hop 1", got)
	}
}

func TestStopAfterTTLTransitContinuesDespiteUnreachable(t *testing.T) {
	res := resultWithResponses(
		probeResponse{kind: probeResponseUnreachable, marker: "!H"},
		probeResponse{kind: probeResponseTransit},
		probeResponse{kind: probeResponseUnreachable, marker: "!N"},
	)

	if res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = true, want false")
	}
	if res.StopReason != nil {
		t.Fatalf("StopReason = %#v, want nil", res.StopReason)
	}
}

func TestStopAfterTTLTargetIPTimeExceededContinues(t *testing.T) {
	target := &net.IPAddr{IP: net.ParseIP("192.0.2.1")}
	tracer := &ICMPTracer{
		Config: Config{
			DstIP:           target.IP,
			NumMeasurements: 1,
			MaxAttempts:     1,
		},
		res: Result{
			Hops:     make([][]Hop, 1),
			tailDone: make([]bool, 1),
		},
	}
	tracer.final.Store(-1)
	tracer.addHopWithIndex(target, 1, 0, 0, nil, probeResponse{kind: probeResponseTransit})

	if got := tracer.final.Load(); got != -1 {
		t.Fatalf("final = %d, want -1", got)
	}
	if tracer.res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = true, want false")
	}
}

func TestStopAfterTTLAllResponsesUnreachable(t *testing.T) {
	res := resultWithResponses(
		probeResponse{kind: probeResponseUnreachable, marker: "!N"},
		probeResponse{kind: probeResponseUnreachable, marker: "!H"},
		probeResponse{kind: probeResponseUnreachable, marker: "!N"},
	)

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	want := &StopReason{Hop: 1, Reason: StopReasonUnreachable, Details: []string{"!H", "!N"}}
	if !reflect.DeepEqual(res.StopReason, want) {
		t.Fatalf("StopReason = %#v, want %#v", res.StopReason, want)
	}
}

func TestStopAfterTTLUnreachableWithTimeoutsStops(t *testing.T) {
	res := &Result{Hops: [][]Hop{{
		{Success: true, TTL: 1},
		{TTL: 1},
		{TTL: 1},
	}}}
	res.recordResponse(1, probeResponse{kind: probeResponseUnreachable, marker: "!H"})

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonUnreachable {
		t.Fatalf("StopReason = %#v, want unreachable", got)
	}
}

func TestStopAfterTTLUsesResponsesOutsideDisplayLimit(t *testing.T) {
	res := &Result{
		Hops:     make([][]Hop, 1),
		tailDone: make([]bool, 1),
	}
	for i := range 3 {
		res.addMatchedHop(
			Hop{Success: true, TTL: 1},
			probeResponse{kind: probeResponseUnreachable, marker: "!H"},
			nil, i, 3, 4, Config{},
		)
	}
	res.addMatchedHop(
		Hop{Success: true, TTL: 1},
		probeResponse{kind: probeResponseTransit},
		nil, 3, 3, 4, Config{},
	)
	if got := len(res.Hops[0]); got != 3 {
		t.Fatalf("displayed hops = %d, want 3", got)
	}

	if res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = true, want false")
	}
	if res.StopReason != nil {
		t.Fatalf("StopReason = %#v, want nil", res.StopReason)
	}
}

func TestStopAfterTTLDestinationOutsideDisplayLimitStops(t *testing.T) {
	res := &Result{
		Hops:     make([][]Hop, 1),
		tailDone: make([]bool, 1),
	}
	for i := range 3 {
		res.addMatchedHop(
			Hop{Success: true, TTL: 1},
			probeResponse{kind: probeResponseUnreachable, marker: "!H"},
			nil, i, 3, 4, Config{},
		)
	}
	res.addMatchedHop(
		Hop{Success: true, TTL: 1},
		probeResponse{kind: probeResponseDestination},
		nil, 3, 3, 4, Config{},
	)
	if got := len(res.Hops[0]); got != 3 {
		t.Fatalf("displayed hops = %d, want 3", got)
	}

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonDestination {
		t.Fatalf("StopReason = %#v, want destination", got)
	}
}

func TestStopAfterTTLTimeoutsContinueUntilMaxHops(t *testing.T) {
	res := &Result{Hops: [][]Hop{{{TTL: 1}, {TTL: 1}, {TTL: 1}}}}
	if res.stopAfterTTL(1, 2) {
		t.Fatal("stopAfterTTL(1) = true, want false")
	}

	res.Hops = append(res.Hops, []Hop{{TTL: 2}, {TTL: 2}, {TTL: 2}})
	if !res.stopAfterTTL(2, 2) {
		t.Fatal("stopAfterTTL(2) = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonMaxHops || got.Hop != 2 {
		t.Fatalf("StopReason = %#v, want max hops at hop 2", got)
	}
}

func TestMarkDestinationFinalOnlyStopsForDestination(t *testing.T) {
	var final atomic.Int32
	final.Store(-1)
	markDestinationFinal(&final, 4, probeResponse{kind: probeResponseTransit})
	if got := final.Load(); got != -1 {
		t.Fatalf("final after transit = %d, want -1", got)
	}

	markDestinationFinal(&final, 7, probeResponse{kind: probeResponseDestination})
	markDestinationFinal(&final, 9, probeResponse{kind: probeResponseDestination})
	markDestinationFinal(&final, 5, probeResponse{kind: probeResponseDestination})
	if got := final.Load(); got != 5 {
		t.Fatalf("final after destination replies = %d, want 5", got)
	}
}
