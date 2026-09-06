package printer

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestTraditionalRawKeepsHistoricalRows(t *testing.T) {
	res := &trace.Result{
		Hops: [][]trace.Hop{{
			{TTL: 1, Address: &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, Hostname: "router.example", RTT: 1250 * time.Microsecond, Geo: &ipgeo.IPGeoData{Asnumber: "64500", Country: "Testland"}},
			{TTL: 1},
		}},
		StopReason: &trace.StopReason{Hop: 1, Reason: trace.StopReasonDestination},
	}
	got := captureStdout(t, func() { EasyPrinter(res, 0) })
	want := "1|192.0.2.1|router.example|1.25|64500|Testland|||||0.0000|0.0000\n1|*||||||\n"
	if got != want {
		t.Fatalf("raw output = %q, want %q", got, want)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(strings.Split(lines[0], "|")) != 12 || len(strings.Split(lines[1], "|")) != 8 {
		t.Fatalf("historical column counts changed: %q", got)
	}
}
