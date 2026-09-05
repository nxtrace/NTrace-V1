package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestRESTTraceResponseGolden(t *testing.T) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.JSON(http.StatusOK, traceResponse{
		Target:       "escape <&>\u2028 target",
		ResolvedIP:   "2001:db8::9",
		Protocol:     "UDP",
		DataProvider: ipgeo.NextTraceAPIProvider,
		Language:     "en",
		Hops: []hopResponse{{
			TTL: 1,
			Attempts: []hopAttempt{
				{Success: true, IP: "2001:db8::1", Hostname: "edge.example", RTT: 12.5},
				{Success: false, Error: "timeout\nretry"},
			},
		}},
		DurationMs: 250,
		StopReason: &service.TraceStopReason{
			Hop:       3,
			Reason:    trace.StopReasonUnreachable,
			Responses: []string{"ICMP Host Unreachable"},
		},
	})

	if got := recorder.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	body := recorder.Body.Bytes()
	if bytes.HasSuffix(body, []byte{'\n'}) {
		t.Fatal("REST JSON response unexpectedly ends with a newline")
	}
	got := append(append([]byte(nil), body...), '\n')
	assertJSONGolden(t, got, "testdata/rest_trace_response.golden.json")
}

func assertJSONGolden(t *testing.T, got []byte, path string) {
	t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON golden: %v", err)
	}
	if !reflect.DeepEqual(decodeJSONSequence(t, got), decodeJSONSequence(t, want)) {
		t.Fatalf("JSON semantics changed\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("JSON bytes changed while semantics remain equal\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func decodeJSONSequence(t *testing.T, data []byte) []any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	values := make([]any, 0, 1)
	for {
		var value any
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				return values
			}
			t.Fatalf("decode JSON contract: %v", err)
		}
		values = append(values, value)
	}
}
