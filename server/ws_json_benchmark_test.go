package server

import (
	"encoding/json"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
)

var (
	wsJSONBytesSink   []byte
	wsJSONRequestSink traceRequest
)

func BenchmarkWebSocketJSONMarshalEnvelope(b *testing.B) {
	envelope := benchmarkWebSocketEnvelope()
	sample, err := json.Marshal(envelope)
	if err != nil {
		b.Fatalf("marshal sample envelope: %v", err)
	}
	b.SetBytes(int64(len(sample)))
	b.ReportAllocs()

	for b.Loop() {
		encoded, err := json.Marshal(envelope)
		if err != nil {
			b.Fatalf("marshal websocket envelope: %v", err)
		}
		wsJSONBytesSink = encoded
	}
}

func benchmarkWebSocketEnvelope() wsEnvelope {
	return wsEnvelope{
		Type: "mtr_raw",
		Data: trace.MTRRawRecord{
			Iteration: 8,
			TTL:       12,
			Success:   true,
			IP:        "2001:db8::12",
			Host:      "router.example",
			RTTMs:     12.75,
			ASN:       "AS64512",
			Country:   "ZZ",
			City:      "Example City",
			Owner:     "Example Network",
			Lat:       31.25,
			Lng:       121.5,
			MPLS:      []string{"[MPLS: Lbl 16000, TC 0, S 1, TTL 63]"},
			Response: &trace.MTRProbeResponse{
				Kind:        trace.MTRResponseTransit,
				Description: "ICMP Time Exceeded",
			},
		},
	}
}

func BenchmarkWebSocketJSONUnmarshalRequest(b *testing.B) {
	payload := benchmarkWebSocketRequestPayload()
	var sample traceRequest
	if err := json.Unmarshal(payload, &sample); err != nil {
		b.Fatalf("unmarshal sample websocket request: %v", err)
	}
	if sample.Target != "example.test" {
		b.Fatalf("sample Target = %q, want example.test", sample.Target)
	}
	if sample.PacketSize == nil || *sample.PacketSize != 84 {
		b.Fatalf("sample PacketSize = %v, want 84", sample.PacketSize)
	}
	if sample.TOS == nil || *sample.TOS != 32 {
		b.Fatalf("sample TOS = %v, want 32", sample.TOS)
	}
	if sample.Mode != "mtr" {
		b.Fatalf("sample Mode = %q, want mtr", sample.Mode)
	}
	if sample.HopIntervalMs != 1000 {
		b.Fatalf("sample HopIntervalMs = %d, want 1000", sample.HopIntervalMs)
	}
	if sample.Protocol != "udp" || !sample.IPv6Only || sample.MaxRounds != 10 {
		b.Fatalf(
			"sample representative fields = (protocol=%q, ipv6_only=%v, max_rounds=%d), want (udp, true, 10)",
			sample.Protocol,
			sample.IPv6Only,
			sample.MaxRounds,
		)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		var request traceRequest
		if err := json.Unmarshal(payload, &request); err != nil {
			b.Fatalf("unmarshal websocket request: %v", err)
		}
		wsJSONRequestSink = request
	}
}

func benchmarkWebSocketRequestPayload() []byte {
	return []byte(`{"target":"example.test","protocol":"udp","port":33494,"queries":3,"max_hops":64,"timeout_ms":2000,"packet_size":84,"tos":32,"parallel_requests":16,"begin_hop":1,"ipv6_only":true,"data_provider":"NextTrace-API","dot_server":"dns.example:853","always_rdns":true,"disable_maptrace":true,"language":"en","source_address":"2001:db8::10","source_device":"en0","packet_interval":50,"ttl_interval":300,"mode":"mtr","hop_interval_ms":1000,"max_rounds":10}`)
}

func BenchmarkPGOWebSocketJSONWorkload(b *testing.B) {
	envelope := benchmarkWebSocketEnvelope()
	payload := benchmarkWebSocketRequestPayload()
	encodedSample, err := json.Marshal(envelope)
	if err != nil {
		b.Fatalf("marshal sample envelope: %v", err)
	}
	var sample traceRequest
	if err := json.Unmarshal(payload, &sample); err != nil {
		b.Fatalf("unmarshal sample request: %v", err)
	}
	b.SetBytes(int64(len(payload) + len(encodedSample)))
	b.ReportAllocs()

	for b.Loop() {
		encoded, err := json.Marshal(envelope)
		if err != nil {
			b.Fatalf("marshal websocket envelope: %v", err)
		}
		var request traceRequest
		if err := json.Unmarshal(payload, &request); err != nil {
			b.Fatalf("unmarshal websocket request: %v", err)
		}
		wsJSONBytesSink = encoded
		wsJSONRequestSink = request
	}
}
