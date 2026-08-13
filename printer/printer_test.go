package printer

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/nxtrace/NTrace-core/trace"
)

var errTraceStopWriter = errors.New("trace stop writer failed")

type failingTraceStopWriter struct{}

func (failingTraceStopWriter) Write([]byte) (int, error) {
	return 0, errTraceStopWriter
}

func TestFormatTraceStopReason(t *testing.T) {
	tests := []struct {
		name   string
		reason *trace.StopReason
		want   string
	}{
		{name: "nil"},
		{
			name: "destination",
			reason: &trace.StopReason{
				Hop:       5,
				Reason:    trace.StopReasonDestination,
				Responses: []string{"ICMP Echo Reply"},
			},
			want: "Trace Stopped: Destination Reached at Hop 5 (ICMP Echo Reply)",
		},
		{
			name: "unreachable",
			reason: &trace.StopReason{
				Hop:       7,
				Reason:    trace.StopReasonUnreachable,
				Responses: []string{"ICMP Host Unreachable (!H)", "ICMP Network Unreachable (!N)"},
				Markers:   []string{"!H", "!N"},
			},
			want: "Trace Stopped: No Continuing Route Observed at Hop 7 (ICMP Host Unreachable (!H), ICMP Network Unreachable (!N))",
		},
		{
			name:   "max hops",
			reason: &trace.StopReason{Hop: 30, Reason: trace.StopReasonMaxHops},
			want:   "Trace Stopped: Maximum Hops Reached at Hop 30 (No Destination Response)",
		},
		{
			name:   "unknown reason",
			reason: &trace.StopReason{Hop: 9, Reason: "custom_stop"},
			want:   "Trace Stopped: custom_stop at Hop 9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatTraceStopReason(tt.reason); got != tt.want {
				t.Fatalf("FormatTraceStopReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteTraceStopReason(t *testing.T) {
	reason := &trace.StopReason{Hop: 5, Reason: trace.StopReasonDestination, Responses: []string{"ICMP Echo Reply"}}
	var output bytes.Buffer
	if err := WriteTraceStopReason(&output, reason); err != nil {
		t.Fatalf("WriteTraceStopReason() error = %v", err)
	}
	if got, want := output.String(), "Trace Stopped: Destination Reached at Hop 5 (ICMP Echo Reply)\n"; got != want {
		t.Fatalf("WriteTraceStopReason() = %q, want %q", got, want)
	}
	if err := WriteTraceStopReason(failingTraceStopWriter{}, reason); !errors.Is(err, errTraceStopWriter) {
		t.Fatalf("WriteTraceStopReason() error = %v, want %v", err, errTraceStopWriter)
	}
}

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
	}{
		{name: "nil"},
		{name: "destination", reason: &trace.StopReason{Hop: 5, Reason: trace.StopReasonDestination, Responses: []string{"ICMP Echo Reply"}}},
		{name: "unreachable", reason: &trace.StopReason{Hop: 7, Reason: trace.StopReasonUnreachable, Responses: []string{"ICMP Host Unreachable (!H)"}, Markers: []string{"!H"}}},
		{name: "max hops", reason: &trace.StopReason{Hop: 30, Reason: trace.StopReasonMaxHops}},
		{name: "unknown reason", reason: &trace.StopReason{Hop: 9, Reason: "custom_stop"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			color.Output = &output
			color.NoColor = true
			if err := PrintTraceStopReason(tt.reason); err != nil {
				t.Fatalf("PrintTraceStopReason() error = %v", err)
			}

			if got, want := strings.TrimSpace(output.String()), FormatTraceStopReason(tt.reason); got != want {
				t.Fatalf("PrintTraceStopReason() = %q, want %q", got, want)
			}
		})
	}
}

func TestPrintTraceStopReasonReturnsWriterError(t *testing.T) {
	previousOutput := color.Output
	previousNoColor := color.NoColor
	defer func() {
		color.Output = previousOutput
		color.NoColor = previousNoColor
	}()

	color.Output = failingTraceStopWriter{}
	color.NoColor = true
	err := PrintTraceStopReason(&trace.StopReason{Hop: 5, Reason: trace.StopReasonDestination})
	if !errors.Is(err, errTraceStopWriter) {
		t.Fatalf("PrintTraceStopReason() error = %v, want %v", err, errTraceStopWriter)
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
