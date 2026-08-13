package trace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace/internal"
	"github.com/nxtrace/NTrace-core/util"
)

func resultWithResponses(responses ...probeResponse) *Result {
	res := &Result{Hops: make([][]Hop, 1)}
	for _, response := range responses {
		res.recordResponse(1, response)
	}
	return res
}

func resultTTLStable(res *Result, ttl, numMeasurements int) bool {
	res.lock.RLock()
	defer res.lock.RUnlock()
	return res.ttlStableLocked(ttl, numMeasurements)
}

func TestStopAfterTTLDestinationWins(t *testing.T) {
	res := resultWithResponses(
		probeResponse{kind: probeResponseTransit, detail: "ICMP Time Exceeded"},
		probeResponse{kind: probeResponseDestination, detail: "ICMP Echo Reply"},
		probeResponse{kind: probeResponseUnreachable, detail: "ICMP Host Unreachable", marker: "!H"},
	)

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonDestination || got.Hop != 1 {
		t.Fatalf("StopReason = %#v, want destination at hop 1", got)
	}
	if !reflect.DeepEqual(res.StopReason.Responses, []string{"ICMP Echo Reply"}) {
		t.Fatalf("StopReason.Responses = %#v, want destination response only", res.StopReason.Responses)
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
		probeResponse{kind: probeResponseUnreachable, detail: "ICMP Network Unreachable", marker: "!N"},
		probeResponse{kind: probeResponseUnreachable, detail: "ICMP Host Unreachable", marker: "!H"},
		probeResponse{kind: probeResponseUnreachable, detail: "ICMP Network Unreachable", marker: "!N"},
	)

	if !res.stopAfterTTL(1, 30) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if !reflect.DeepEqual(res.StopReason.Markers, []string{"!H", "!N"}) {
		t.Fatalf("StopReason.Markers = %#v, want %#v", res.StopReason.Markers, []string{"!H", "!N"})
	}
	wantResponses := []string{"ICMP Host Unreachable (!H)", "ICMP Network Unreachable (!N)"}
	if !reflect.DeepEqual(res.StopReason.Responses, wantResponses) {
		t.Fatalf("StopReason.Responses = %#v, want %#v", res.StopReason.Responses, wantResponses)
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

func TestPortUnreachableDependsOnProbeMethod(t *testing.T) {
	for _, response := range []struct {
		name   string
		icmp   internal.ICMPResponse
		method Method
		kind   probeResponseKind
		marker string
	}{
		{name: "udp v4", icmp: internal.ICMPResponse{Kind: internal.ICMPResponsePortUnreachable, Description: "ICMP Port Unreachable", Marker: "!<3-3>"}, method: UDPTrace, kind: probeResponseDestination},
		{name: "icmp v4", icmp: internal.ICMPResponse{Kind: internal.ICMPResponsePortUnreachable, Description: "ICMP Port Unreachable", Marker: "!<3-3>"}, method: ICMPTrace, kind: probeResponseUnreachable, marker: "!<3-3>"},
		{name: "tcp v6", icmp: internal.ICMPResponse{Kind: internal.ICMPResponsePortUnreachable, Description: "ICMPv6 Port Unreachable", Marker: "!<1-4>"}, method: TCPTrace, kind: probeResponseUnreachable, marker: "!<1-4>"},
	} {
		t.Run(response.name, func(t *testing.T) {
			got := probeResponseFromICMPForMethod(response.icmp, response.method)
			if got.kind != response.kind || got.marker != response.marker {
				t.Fatalf("response = %#v, want kind=%v marker=%q", got, response.kind, response.marker)
			}
		})
	}
}

func TestTCPDestinationResponseUsesDecoderAckContract(t *testing.T) {
	if got := probeResponseFromTCPAck(0); got.detail != "TCP SYN/ACK" || got.kind != probeResponseDestination {
		t.Fatalf("ack=0 response = %#v", got)
	}
	if got := probeResponseFromTCPAck(123); got.detail != "TCP RST" || got.kind != probeResponseDestination {
		t.Fatalf("ack!=0 response = %#v", got)
	}
}

func TestStopAfterTTLTransitAtMaxHopsStops(t *testing.T) {
	res := resultWithResponses(probeResponse{kind: probeResponseTransit, detail: "ICMP Time Exceeded"})
	if !res.stopAfterTTL(1, 1) {
		t.Fatal("stopAfterTTL() = false, want true")
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonMaxHops {
		t.Fatalf("StopReason = %#v, want max hops", got)
	}
}

func TestTraceFinalOnlyDecreases(t *testing.T) {
	var final atomic.Int32
	final.Store(-1)
	lowerTraceFinal(&final, 7)
	lowerTraceFinal(&final, 9)
	lowerTraceFinal(&final, 5)
	if got := final.Load(); got != 5 {
		t.Fatalf("final = %d, want 5", got)
	}
}

func TestMatchedAndTimeoutAboveFinalAreDiscarded(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 3), tailDone: make([]bool, 3)}
	var final atomic.Int32
	final.Store(1)
	res.markAttemptLaunched(2, 0, nil)
	res.markAttemptLaunched(3, 0, nil)

	if res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP("192.0.2.2")}, TTL: 2},
		probeResponse{kind: probeResponseTransit}, &final, 0, 1, 1, Config{},
	) {
		t.Fatal("matched hop above final was admitted")
	}
	if res.addTimeout(Hop{TTL: 3, Error: errHopLimitTimeout}, &final, 0, 1, 1) {
		t.Fatal("timeout above final was admitted")
	}
	if len(res.Hops[1]) != 0 || len(res.Hops[2]) != 0 || len(res.responses[2]) != 0 {
		t.Fatalf("higher TTL state leaked: hops=%#v responses=%#v", res.Hops, res.responses)
	}
}

func TestHiddenDestinationIsVisibleAndLateFinalCanStop(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range 3 {
		if !res.markAttemptLaunched(1, i, &final) {
			t.Fatalf("attempt %d was not launched", i)
		}
	}
	res.markTTLLaunchDone(1)
	res.addTimeout(Hop{TTL: 1, Error: errHopLimitTimeout}, &final, 0, 2, 3)
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, TTL: 1},
		probeResponse{kind: probeResponseTransit, detail: "ICMP Time Exceeded"},
		&final, 1, 2, 3, Config{},
	)
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP("198.51.100.9")}, TTL: 1},
		probeResponse{kind: probeResponseDestination, detail: "ICMP Port Unreachable"},
		&final, 2, 2, 3, Config{},
	)

	if got := final.Load(); got != 1 {
		t.Fatalf("final = %d, want 1", got)
	}
	if !res.stableFinalAtOrBefore(2, 30, 2, &final) {
		t.Fatal("late final was not detected behind the print cursor")
	}
	found := false
	for _, hop := range res.Hops[0] {
		if ip := util.AddrIP(hop.Address); ip != nil && ip.Equal(net.ParseIP("198.51.100.9")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("winning responder is not visible: %#v", res.Hops[0])
	}
	if got := strings.Join(res.StopReason.Responses, ","); !strings.Contains(got, "198.51.100.9") {
		t.Fatalf("StopReason.Responses = %q, want responder IP", got)
	}
}

func TestHiddenDestinationReplacesVisibleTransitWhenNoTimeoutExists(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range 3 {
		res.markAttemptLaunched(1, i, &final)
	}
	res.markTTLLaunchDone(1)
	for i, raw := range []string{"192.0.2.1", "192.0.2.2"} {
		res.addMatchedHop(
			Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP(raw)}, TTL: 1},
			probeResponse{kind: probeResponseTransit}, &final, i, 2, 3, Config{},
		)
	}
	destination := net.ParseIP("198.51.100.9")
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: destination}, TTL: 1},
		probeResponse{kind: probeResponseDestination}, &final, 2, 2, 3, Config{},
	)

	found := false
	for _, hop := range res.Hops[0] {
		if ip := util.AddrIP(hop.Address); ip != nil && ip.Equal(destination) {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden destination is not visible: %#v", res.Hops[0])
	}
}

func TestTTLStableRequiresLaunchDoneAndEveryLaunchedAttemptSettled(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	res.markAttemptLaunched(1, 0, &final)
	res.markAttemptLaunched(1, 1, &final)
	res.addTimeout(Hop{TTL: 1, Error: errHopLimitTimeout}, &final, 0, 1, 2)
	if resultTTLStable(res, 1, 1) {
		t.Fatal("TTL became stable before launch completion")
	}
	res.markTTLLaunchDone(1)
	if resultTTLStable(res, 1, 1) {
		t.Fatal("TTL became stable before every launched attempt settled")
	}
	res.addTimeout(Hop{TTL: 1, Error: errHopLimitTimeout}, &final, 1, 1, 2)
	if !resultTTLStable(res, 1, 1) {
		t.Fatal("TTL did not become stable after launch and settlement completed")
	}
}

func TestStableTracePrintWaitsForLateHiddenUnreachable(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range 3 {
		res.markAttemptLaunched(1, i, &final)
	}
	res.markTTLLaunchDone(1)

	for i, raw := range []string{"192.0.2.1", "192.0.2.2"} {
		res.addMatchedHop(
			Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP(raw)}, TTL: 1},
			probeResponse{}, &final, i, 2, 3, Config{},
		)
	}

	prints := 0
	printer := func(snapshot *Result) { prints++ }
	if cursor, stop := advanceStableTracePrint(context.Background(), res, 0, 30, 2, &final, printer, nil); cursor != 0 || stop {
		t.Fatalf("advance before settlement = (%d, %v), want (0, false)", cursor, stop)
	}
	if prints != 0 {
		t.Fatalf("prints before settlement = %d, want 0", prints)
	}

	peer := net.ParseIP("198.51.100.9")
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: peer}, TTL: 1},
		probeResponse{kind: probeResponseUnreachable, detail: "ICMP Host Unreachable", marker: "!H"},
		&final, 2, 2, 3, Config{},
	)

	var snapshot *Result
	printer = func(got *Result) {
		prints++
		snapshot = got
	}
	cursor, stop := advanceStableTracePrint(context.Background(), res, 0, 30, 2, &final, printer, nil)
	if cursor != 1 || !stop {
		t.Fatalf("advance after settlement = (%d, %v), want (1, true)", cursor, stop)
	}
	if prints != 1 {
		t.Fatalf("stable prints = %d, want 1", prints)
	}
	if snapshot == nil || snapshot.StopReason == nil || snapshot.StopReason.Reason != StopReasonUnreachable {
		t.Fatalf("snapshot StopReason = %#v, want unreachable", snapshot)
	}
	found := false
	for _, hop := range snapshot.Hops[0] {
		if ip := util.AddrIP(hop.Address); ip != nil && ip.Equal(peer) {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden unreachable responder was not promoted: %#v", snapshot.Hops[0])
	}
}

func TestHiddenTransitReplacesProvisionalUnreachablePromotion(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range 4 {
		res.markAttemptLaunched(1, i, &final)
	}
	res.markTTLLaunchDone(1)
	for i, raw := range []string{"192.0.2.1", "192.0.2.2"} {
		res.addMatchedHop(
			Hop{Success: true, Address: &net.IPAddr{IP: net.ParseIP(raw)}, TTL: 1},
			probeResponse{}, &final, i, 2, 4, Config{},
		)
	}

	unreachableIP := net.ParseIP("198.51.100.9")
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: unreachableIP}, TTL: 1},
		probeResponse{kind: probeResponseUnreachable, marker: "!H"},
		&final, 2, 2, 4, Config{},
	)
	transitIP := net.ParseIP("203.0.113.7")
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: transitIP}, TTL: 1},
		probeResponse{kind: probeResponseTransit},
		&final, 3, 2, 4, Config{},
	)

	cursor, stop := advanceStableTracePrint(context.Background(), res, 0, 30, 2, &final, nil, nil)
	if cursor != 1 || stop {
		t.Fatalf("advance = (%d, %v), want (1, false) because transit wins", cursor, stop)
	}
	foundTransit := false
	foundUnreachable := false
	for _, hop := range res.Hops[0] {
		ip := util.AddrIP(hop.Address)
		foundTransit = foundTransit || (ip != nil && ip.Equal(transitIP))
		foundUnreachable = foundUnreachable || (ip != nil && ip.Equal(unreachableIP))
	}
	if !foundTransit || foundUnreachable {
		t.Fatalf("visible hops = %#v, want transit promotion without provisional unreachable", res.Hops[0])
	}
}

func TestLateMetadataCannotOverwritePromotedTerminalHop(t *testing.T) {
	oldIP := net.ParseIP("8.8.4.101")
	destinationIP := net.ParseIP("8.8.4.102")
	oldKey := oldIP.String()
	destinationKey := destinationIP.String()
	geoCache.Delete(oldKey)
	geoCache.Delete(destinationKey)
	t.Cleanup(func() {
		geoCache.Delete(oldKey)
		geoCache.Delete(destinationKey)
	})

	oldStarted := make(chan struct{}, 1)
	releaseOld := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseOld) }) }
	t.Cleanup(release)
	cfg := Config{
		Context:         context.Background(),
		NumMeasurements: 1,
		IPGeoSource: func(ip string, _ time.Duration, _ string, _ bool) (*ipgeo.IPGeoData, error) {
			if ip == oldKey {
				select {
				case oldStarted <- struct{}{}:
				default:
				}
				<-releaseOld
				return &ipgeo.IPGeoData{Country: "old"}, nil
			}
			return &ipgeo.IPGeoData{Country: "destination"}, nil
		},
	}
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range 2 {
		res.markAttemptLaunched(1, i, &final)
	}
	res.markTTLLaunchDone(1)
	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: oldIP}, TTL: 1},
		probeResponse{kind: probeResponseTransit}, &final, 0, 1, 2, cfg,
	)
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old metadata lookup did not start")
	}

	res.addMatchedHop(
		Hop{Success: true, Address: &net.IPAddr{IP: destinationIP}, TTL: 1},
		probeResponse{kind: probeResponseDestination}, &final, 1, 1, 2, cfg,
	)
	deadline := time.Now().Add(time.Second)
	for {
		res.lock.RLock()
		hop := res.Hops[0][0]
		ready := util.AddrIP(hop.Address).Equal(destinationIP) && hop.Geo != nil && hop.Geo.Country == "destination"
		res.lock.RUnlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("destination metadata was not applied")
		}
		time.Sleep(time.Millisecond)
	}

	release()
	res.geoWG.Wait()
	res.lock.RLock()
	defer res.lock.RUnlock()
	hop := res.Hops[0][0]
	if ip := util.AddrIP(hop.Address); ip == nil || !ip.Equal(destinationIP) {
		t.Fatalf("visible IP = %v, want %v", ip, destinationIP)
	}
	if hop.Geo == nil || hop.Geo.Country != "destination" {
		t.Fatalf("visible geo = %#v, want destination metadata", hop.Geo)
	}
}

func TestStableTracePrintDoesNotReachMaxHopsWhileLowerTTLPending(t *testing.T) {
	res := &Result{Hops: make([][]Hop, 2), tailDone: make([]bool, 2)}
	var final atomic.Int32
	final.Store(-1)
	for ttl := 1; ttl <= 2; ttl++ {
		res.markAttemptLaunched(ttl, 0, &final)
		res.markTTLLaunchDone(ttl)
	}
	res.addTimeout(Hop{TTL: 2, Error: errHopLimitTimeout}, &final, 0, 1, 1)

	prints := 0
	printer := func(*Result) { prints++ }
	if cursor, stop := advanceStableTracePrint(context.Background(), res, 0, 2, 1, &final, printer, nil); cursor != 0 || stop {
		t.Fatalf("advance with TTL 1 pending = (%d, %v), want (0, false)", cursor, stop)
	}
	if prints != 0 || res.StopReason != nil {
		t.Fatalf("premature max-hops result: prints=%d reason=%#v", prints, res.StopReason)
	}

	res.addTimeout(Hop{TTL: 1, Error: errHopLimitTimeout}, &final, 0, 1, 1)
	cursor, stop := advanceStableTracePrint(context.Background(), res, 0, 2, 1, &final, printer, nil)
	if cursor != 1 || stop {
		t.Fatalf("TTL 1 advance = (%d, %v), want (1, false)", cursor, stop)
	}
	cursor, stop = advanceStableTracePrint(context.Background(), res, cursor, 2, 1, &final, printer, nil)
	if cursor != 2 || !stop {
		t.Fatalf("TTL 2 advance = (%d, %v), want (2, true)", cursor, stop)
	}
	if got := res.StopReason; got == nil || got.Hop != 2 || got.Reason != StopReasonMaxHops {
		t.Fatalf("StopReason = %#v, want max_hops at 2", got)
	}
}

func TestAllSendFailuresFillVisibleSlotsAndReachStableMaxHops(t *testing.T) {
	const (
		numMeasurements = 3
		maxAttempts     = 6
	)
	res := &Result{Hops: make([][]Hop, 1), tailDone: make([]bool, 1)}
	var final atomic.Int32
	final.Store(-1)
	for i := range maxAttempts {
		res.markAttemptLaunched(1, i, &final)
	}
	res.markTTLLaunchDone(1)
	for i := range maxAttempts {
		res.addFailedAttempt(Hop{TTL: 1, Error: errors.New("send failed")}, &final, i, numMeasurements, maxAttempts)
	}

	if !resultTTLStable(res, 1, numMeasurements) {
		t.Fatal("all failed sends did not make the TTL stable")
	}
	if got := len(res.Hops[0]); got != numMeasurements {
		t.Fatalf("visible failures = %d, want %d", got, numMeasurements)
	}
	prints := 0
	cursor, stop := advanceStableTracePrint(
		context.Background(), res, 0, 1, numMeasurements, &final,
		func(*Result) { prints++ }, nil,
	)
	if cursor != 1 || !stop || prints != 1 {
		t.Fatalf("stable failure advance = (%d, %v, prints=%d), want (1, true, 1)", cursor, stop, prints)
	}
	if got := res.StopReason; got == nil || got.Reason != StopReasonMaxHops {
		t.Fatalf("StopReason = %#v, want max_hops", got)
	}
}

func TestStableTracePrintPassesDetachedSnapshot(t *testing.T) {
	res := &Result{
		Hops: [][]Hop{{{
			Success: true,
			Address: &net.IPAddr{IP: net.ParseIP("192.0.2.1")},
			TTL:     1,
			Geo:     &ipgeo.IPGeoData{Country: "original"},
			MPLS:    []string{"label"},
		}}},
		tailDone:    []bool{true},
		TraceMapUrl: "https://example.invalid/map",
	}
	var final atomic.Int32
	final.Store(-1)
	res.markAttemptLaunched(1, 0, &final)
	res.settleAttempt(1, 0)
	res.markTTLLaunchDone(1)

	var snapshot *Result
	cursor, stop := advanceStableTracePrint(
		context.Background(), res, 0, 1, 1, &final,
		func(got *Result) { snapshot = got }, nil,
	)
	if cursor != 1 || !stop || snapshot == nil {
		t.Fatalf("advance = (%d, %v, %#v), want stable snapshot", cursor, stop, snapshot)
	}
	if snapshot.TraceMapUrl != res.TraceMapUrl || snapshot.StopReason == nil || snapshot.StopReason.Reason != StopReasonMaxHops {
		t.Fatalf("snapshot metadata = %#v", snapshot)
	}
	snapshot.Hops[0][0].Geo.Country = "mutated"
	snapshot.Hops[0][0].MPLS[0] = "mutated"
	snapshot.StopReason.Reason = "mutated"
	if res.Hops[0][0].Geo.Country != "original" || res.Hops[0][0].MPLS[0] != "label" || res.StopReason.Reason != StopReasonMaxHops {
		t.Fatalf("printer snapshot mutated live result: hop=%#v reason=%#v", res.Hops[0][0], res.StopReason)
	}
}

func TestStopReasonJSONUsesLowercaseNestedFields(t *testing.T) {
	payload, err := json.Marshal(&Result{StopReason: &StopReason{
		Hop:       7,
		Reason:    StopReasonUnreachable,
		Responses: []string{"ICMP Host Unreachable"},
		Markers:   []string{"!H"},
	}})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got := string(payload)
	for _, want := range []string{`"StopReason"`, `"hop":7`, `"reason":"unreachable"`, `"responses"`, `"markers"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, `"Hop"`) || strings.Contains(got, `"Details"`) {
		t.Fatalf("JSON leaked legacy nested fields: %s", got)
	}
}
