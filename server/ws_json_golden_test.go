package server

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestWebSocketEnvelopeGolden(t *testing.T) {
	pathEnd := &service.TraceStopReason{
		Hop:       2,
		Reason:    trace.StopReasonUnreachable,
		Responses: []string{"ICMP Host Unreachable"},
		Markers:   []string{"!H"},
	}
	envelopes := []wsEnvelope{
		{
			Type: "start",
			Data: gin.H{
				"target":        "example.test",
				"resolved_ip":   "2001:db8::9",
				"protocol":      "UDP",
				"data_provider": "NextTrace-API",
				"language":      "en",
			},
		},
		{
			Type: "mtr_raw",
			Data: trace.MTRRawRecord{
				Iteration: 1,
				TTL:       2,
				Success:   true,
				IP:        "2001:db8::2",
				Host:      "router.example",
				RTTMs:     12.5,
				MPLS:      []string{"[MPLS: Lbl 16000, TC 0, S 1, TTL 63]"},
				Response: &trace.MTRProbeResponse{
					Kind:        trace.MTRResponseUnreachable,
					Description: "ICMP Host Unreachable",
					Marker:      "!H",
				},
			},
		},
		{Type: "path_end", Data: pathEnd},
		{Type: "complete", Data: gin.H{"iteration": 1, "path_end": pathEnd}},
	}

	gotJSON, err := json.Marshal(envelopes)
	if err != nil {
		t.Fatalf("marshal websocket envelopes: %v", err)
	}
	wantJSON, err := os.ReadFile("testdata/ws_envelopes.golden.json")
	if err != nil {
		t.Fatalf("read websocket envelope golden: %v", err)
	}

	var got any
	if err := json.Unmarshal(gotJSON, &got); err != nil {
		t.Fatalf("decode generated websocket envelopes: %v", err)
	}
	var want any
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatalf("decode websocket envelope golden: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		formatted, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("websocket envelope schema changed\n--- got ---\n%s\n--- want ---\n%s", formatted, wantJSON)
	}
}
