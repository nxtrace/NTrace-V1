package printer

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/nxtrace/NTrace-core/trace"
)

type traceStopLine struct {
	status    string
	responses string
	suffix    string
}

func buildTraceStopLine(reason *trace.StopReason) (traceStopLine, bool) {
	if reason == nil {
		return traceStopLine{}, false
	}

	line := traceStopLine{}
	switch reason.Reason {
	case trace.StopReasonDestination:
		line.status = "Destination Reached"
		line.responses = strings.Join(reason.Responses, ", ")
	case trace.StopReasonUnreachable:
		line.status = "No Continuing Route Observed"
		line.responses = strings.Join(reason.Responses, ", ")
	case trace.StopReasonMaxHops:
		line.status = "Maximum Hops Reached"
		line.suffix = " (No Destination Response)"
	default:
		line.status = reason.Reason
	}
	return line, true
}

func (line traceStopLine) plain(hop int) string {
	responses := ""
	if line.responses != "" {
		responses = " (" + line.responses + ")"
	}
	return fmt.Sprintf("Trace Stopped: %s at Hop %d%s%s", line.status, hop, responses, line.suffix)
}

// FormatTraceStopReason returns the canonical plain-text stop line without a trailing newline.
func FormatTraceStopReason(reason *trace.StopReason) string {
	line, ok := buildTraceStopLine(reason)
	if !ok {
		return ""
	}
	return line.plain(reason.Hop)
}

// WriteTraceStopReason writes the canonical plain-text stop line.
func WriteTraceStopReason(w io.Writer, reason *trace.StopReason) error {
	line := FormatTraceStopReason(reason)
	if line == "" {
		return nil
	}
	_, err := fmt.Fprintln(w, line)
	return err
}

// PrintTraceStopReason writes a styled stop line to the terminal output.
func PrintTraceStopReason(reason *trace.StopReason) error {
	line, ok := buildTraceStopLine(reason)
	if !ok {
		return nil
	}

	label := color.New(color.FgWhite, color.Bold).Sprint("Trace Stopped:")
	hop := color.New(color.FgCyan, color.Bold).Sprintf("Hop %d", reason.Hop)
	statusColor := color.FgYellow
	switch reason.Reason {
	case trace.StopReasonDestination:
		statusColor = color.FgGreen
	case trace.StopReasonUnreachable:
		statusColor = color.FgRed
	}
	status := color.New(statusColor, color.Bold).Sprint(line.status)
	responses := ""
	if line.responses != "" {
		responses = fmt.Sprintf(" (%s)", color.New(color.FgWhite).Sprint(line.responses))
	}
	_, err := fmt.Fprintf(color.Output, "%s %s at %s%s%s\n", label, status, hop, responses, line.suffix)
	return err
}
