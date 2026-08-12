package printer

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/nxtrace/NTrace-core/trace"
)

func PrintTraceStopReason(reason *trace.StopReason) {
	if reason == nil {
		return
	}

	label := color.New(color.FgWhite, color.Bold).Sprint("Trace Stopped:")
	hop := color.New(color.FgCyan, color.Bold).Sprintf("Hop %d", reason.Hop)
	switch reason.Reason {
	case trace.StopReasonDestination:
		status := color.New(color.FgGreen, color.Bold).Sprint("Destination Reached")
		fmt.Fprintf(color.Output, "%s %s at %s", label, status, hop)
		printResponseDetails(reason.Responses)
		fmt.Fprintln(color.Output)
	case trace.StopReasonUnreachable:
		status := color.New(color.FgRed, color.Bold).Sprint("No Continuing Route Observed")
		fmt.Fprintf(color.Output, "%s %s at %s", label, status, hop)
		printResponseDetails(reason.Responses)
		fmt.Fprintln(color.Output)
	case trace.StopReasonMaxHops:
		status := color.New(color.FgYellow, color.Bold).Sprint("Maximum Hops Reached")
		fmt.Fprintf(color.Output, "%s %s at %s (No Destination Response)\n", label, status, hop)
	default:
		status := color.New(color.FgYellow, color.Bold).Sprint(reason.Reason)
		fmt.Fprintf(color.Output, "%s %s at %s\n", label, status, hop)
	}
}

func printResponseDetails(details []string) {
	if len(details) == 0 {
		return
	}
	responses := color.New(color.FgWhite).Sprint(strings.Join(details, ", "))
	fmt.Fprintf(color.Output, " (%s)", responses)
}
