package printer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestPrintTraceStopReason(t *testing.T) {
	previousOutput := color.Output
	previousNoColor := color.NoColor
	defer func() {
		color.Output = previousOutput
		color.NoColor = previousNoColor
	}()

	tests := []struct {
		name   string
		reason *trace.StopReason
		want   string
	}{
		{name: "nil"},
		{
			name:   "destination",
			reason: &trace.StopReason{Hop: 5, Reason: trace.StopReasonDestination},
			want:   "Trace Stopped: Destination Reached at Hop 5",
		},
		{
			name: "unreachable",
			reason: &trace.StopReason{
				Hop:     7,
				Reason:  trace.StopReasonUnreachable,
				Details: []string{"!H", "!N"},
			},
			want: "Trace Stopped: No Continuing Route Observed at Hop 7 (!H, !N)",
		},
		{
			name:   "max hops",
			reason: &trace.StopReason{Hop: 30, Reason: trace.StopReasonMaxHops},
			want:   "Trace Stopped: Maximum Hops Reached at Hop 30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			color.Output = &output
			color.NoColor = true
			PrintTraceStopReason(tt.reason)

			if got := strings.TrimSpace(output.String()); got != tt.want {
				t.Fatalf("PrintTraceStopReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

// func TestPrintTraceRouteNav(t *testing.T) {
// 	PrintTraceRouteNav(util.DomainLookUp("1.1.1.1", false), "1.1.1.1", "dataOrigin")
// }

// var testGeo = &ipgeo.IPGeoData{
// 	Asnumber: "TestAsnumber",
// 	Country:  "TestCountry",
// 	Prov:     "TestProv",
// 	City:     "TestCity",
// 	District: "TestDistrict",
// 	Owner:    "TestOwner",
// 	Isp:      "TestIsp",
// }

// var testResult = &trace.Result{
// 	Hops: [][]trace.Hop{
// 		{
// 			{
// 				Success:  true,
// 				Address:  &net.IPAddr{IP: net.ParseIP("192.168.3.1")},
// 				Hostname: "test",
// 				TTL:      0,
// 				RTT:      10 * time.Millisecond,
// 				Error:    nil,
// 				Geo:      testGeo,
// 			},
// 			{
// 				Success:  true,
// 				Address:  &net.IPAddr{IP: net.ParseIP("192.168.3.1")},
// 				Hostname: "test",
// 				TTL:      0,
// 				RTT:      10 * time.Millisecond,
// 				Error:    nil,
// 				Geo:      testGeo,
// 			},
// 		},
// 		{
// 			{
// 				Success:  false,
// 				Address:  nil,
// 				Hostname: "",
// 				TTL:      0,
// 				RTT:      0,
// 				Error:    errors.New("test error"),
// 				Geo:      nil,
// 			},
// 			{
// 				Success:  true,
// 				Address:  &net.IPAddr{IP: net.ParseIP("192.168.3.1")},
// 				Hostname: "test",
// 				TTL:      0,
// 				RTT:      10 * time.Millisecond,
// 				Error:    nil,
// 				Geo:      nil,
// 			},
// 		},
// 		{
// 			{
// 				Success:  true,
// 				Address:  &net.IPAddr{IP: net.ParseIP("192.168.3.1")},
// 				Hostname: "test",
// 				TTL:      0,
// 				RTT:      0,
// 				Error:    nil,
// 				Geo:      &ipgeo.IPGeoData{},
// 			},
// 			{
// 				Success:  true,
// 				Address:  &net.IPAddr{IP: net.ParseIP("192.168.3.1")},
// 				Hostname: "",
// 				TTL:      0,
// 				RTT:      10 * time.Millisecond,
// 				Error:    nil,
// 				Geo:      testGeo,
// 			},
// 		},
// 	},
// }

// // func TestTraceroutePrinter(t *testing.T) {
// // 	TraceroutePrinter(testResult)
// // }

// func TestTracerouteTablePrinter(t *testing.T) {
// 	TracerouteTablePrinter(testResult)
// }

// func TestRealtimePrinter(t *testing.T) {
// 	RealtimePrinter(testResult, 0)
// 	// RealtimePrinter(testResult, 1)
// 	// RealtimePrinter(testResult, 2)
// }
