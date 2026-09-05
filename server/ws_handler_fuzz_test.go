package server

import (
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzDecodeWSInitRequest(f *testing.F) {
	f.Add([]byte(`{"target":"example.com","protocol":"icmp","queries":3}`))
	f.Add([]byte(`{"target":"2001:db8::1","packet_size":64,"tos":0,"mode":"mtr"}`))
	f.Add([]byte(`{"target":`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxWSInitMessageBytes {
			data = data[:maxWSInitMessageBytes]
		}
		request, err := decodeWSInitRequest(data)
		if err != nil {
			return
		}
		if !json.Valid(data) {
			t.Fatal("successful WebSocket init decode accepted invalid JSON")
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal decoded WebSocket init request: %v", err)
		}
		roundTrip, err := decodeWSInitRequest(encoded)
		if err != nil || !reflect.DeepEqual(roundTrip, request) {
			t.Fatalf("WebSocket init round-trip = (%+v, %v), want %+v", roundTrip, err, request)
		}
	})
}
