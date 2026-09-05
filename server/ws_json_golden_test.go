package server

import (
	"bytes"
	"encoding/json"
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

	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	for _, envelope := range envelopes {
		if err := encoder.Encode(envelope); err != nil {
			t.Fatalf("encode websocket envelope: %v", err)
		}
	}
	assertJSONGolden(t, encoded.Bytes(), "testdata/ws_envelopes.golden.jsonl")
}
