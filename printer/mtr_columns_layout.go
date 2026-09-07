package printer

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/nxtrace/NTrace-core/trace"
	"github.com/rodaine/table"
	"os"
	"strings"
	"time"
)

// MTRColumnEditor is an immutable frame snapshot supplied by the TUI controller.
type MTRColumnEditor struct {
	Active       bool
	Draft, Error string
}

func renderMTRColumnEditor(b *strings.Builder, editor MTRColumnEditor, width int) {
	var line string
	for _, word := range strings.Fields("L=Loss S=Snt R=Received N=Last A=Avg B=Best W=Wrst V=StDev") {
		if line != "" && len(line)+1+len(word) > width {
			tuiLine(b, "%s", line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	tuiLine(b, "%s", truncateByDisplayWidth(line, width))
	for _, help := range []string{"Enter: apply Esc: cancel", "Backspace: delete", "Ctrl-U: clear"} {
		tuiLine(b, "%s", truncateByDisplayWidth(help, width))
	}

	prefix := "Columns: "
	available := max(1, width-len(prefix)-1)
	draft := editor.Draft
	if len(draft) > available {
		draft = draft[len(draft)-available:]
	}
	tuiLine(b, "%s", truncateByDisplayWidth(prefix+draft+"_", width))
	if editor.Error != "" {
		tuiLine(b, "%s", truncateByDisplayWidth(editor.Error, width))
	}
}

func renderMTRSelectedColumns(b *strings.Builder, header MTRTUIHeader, stats []trace.MTRHopStat, width int) {
	columns := header.Columns
	widths := mtrColumnWidths(columns, stats)
	maxTTL, _ := scanMTRTUIStats(stats)
	prefixW := max(tuiPrefixW, len(fmt.Sprint(maxTTL))+2)
	metricsW := len(mtrSelectedMetrics(columns, widths, nil, false))
	hostW := width - prefixW - 1 - metricsW
	if hostW < tuiHostMin {
		for _, line := range []string{"Select fewer columns", "or widen terminal (O)."} {
			tuiLine(b, "%s", truncateByDisplayWidth(line, width))
		}
		return
	}
	prefix := strings.Repeat(" ", prefixW)
	if isDefaultMTRColumns(columns) {
		packetsW := widths[0] + 1 + widths[1]
		tuiLine(b, "%s", prefix+padRight("Host", hostW)+" "+mtrTUIHeaderColor(centerIn("Packets", packetsW)+" "+centerIn("Pings", metricsW-packetsW-1)))
		tuiLine(b, "%s", prefix+strings.Repeat(" ", hostW)+" "+mtrTUIHeaderColor(mtrSelectedMetrics(columns, widths, nil, false)))
	} else {
		tuiLine(b, "%s", prefix+mtrTUIHeaderColor(padRight("Host", hostW)+" "+mtrSelectedMetrics(columns, widths, nil, false)))
	}
	parts := buildTUIHostPartSet(stats, header)
	asnW := computeTUIASNWidthFromParts(parts)
	prevTTL := 0
	for i, stat := range stats {
		host := fitMTRHostWithMarker(formatTUIHost(parts[i], asnW), mtrResponseMarker(stat), hostW)
		hostStyle := mtrTUIHostColor
		if isWaitingHopStat(stat) {
			hostStyle = mtrTUIWaitColor
		}
		tuiLine(b, "%s", mtrTUIHopColor(formatTUIHopPrefix(stat.TTL, prevTTL, prefixW))+hostStyle(host)+" "+mtrSelectedMetrics(columns, widths, &stat, true))
		renderMTRTUIMPLSRows(b, mtrTUILayout{prefixW: prefixW, hostW: hostW}, stat.MPLS, header.DisableMPLS)
		prevTTL = stat.TTL
	}
}

// MTRTablePrinterWithColumns preserves Hop/Host placement and the default wrapper.
func MTRTablePrinterWithColumns(stats []trace.MTRHopStat, iteration, mode, nameMode int, lang string, showIPs bool, columns []MTRColumn) {
	if columns == nil {
		MTRTablePrinter(stats, iteration, mode, nameMode, lang, showIPs)
		return
	}
	fmt.Print("\033[H\033[2J")
	headers := []any{"Hop"}
	for _, c := range columns {
		headers = append(headers, mtrColumnDefinitions[c].title)
	}
	headers = append(headers, "Host")
	tbl := table.New(headers...).WithWriter(os.Stdout)
	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc()).WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())
	prevTTL := 0
	for _, s := range stats {
		hop := fmt.Sprint(s.TTL)
		if s.TTL == prevTTL {
			hop = ""
		}
		prevTTL = s.TTL
		row := []any{hop}
		for _, c := range columns {
			row = append(row, mtrColumnValue(c, s))
		}
		row = append(row, appendMTRResponseMarker(formatMTRHostWithMPLS(s, mode, nameMode, lang, showIPs), s))
		tbl.AddRow(row...)
	}
	tbl.Print()
}

func printMTRSelectedReport(stats []trace.MTRHopStat, opts MTRReportOptions, hosts []string, hostW int) {
	widths := mtrColumnWidths(opts.Columns, stats)
	hostHeader := opts.SrcHost
	if !opts.Wide {
		hostHeader = reportTruncateToWidth(hostHeader, hostW)
	}
	fmt.Printf("HOST: %s %s\n", reportPadRight(hostHeader, hostW), mtrSelectedMetrics(opts.Columns, widths, nil, false))
	prevTTL := 0
	for i, s := range stats {
		fmt.Printf("%s%s %s\n", mtrReportPrefix(s.TTL, prevTTL), reportPadRight(hosts[i], hostW), mtrSelectedMetrics(opts.Columns, widths, &s, false))
		prevTTL = s.TTL
	}
}

// Keep custom frames within the terminal even when the legacy shortcut bar
// would wrap over the data. O remains visible in the narrowest supported view.
func renderMTRSelectedHeader(b *strings.Builder, header MTRTUIHeader, width int) {
	tuiLine(b, "%s", buildMTRTUITitleLine(header, width))
	if width < 40 {
		tuiLine(b, "%s", truncateByDisplayWidth(buildMTRTUIRouteText(header), width))
	} else {
		tuiLine(b, "%s", buildMTRTUIRouteLine(header, width, time.Now()))
	}
	if width >= 160 {
		tuiLine(b, "%s", buildMTRTUIControlsLine(header, width))
	} else {
		tuiLine(b, "%s", truncateByDisplayWidth("O:cols Q:quit "+mtrTUIStatusText(header.Status), width))
	}
}
