package printer

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestMTRColumnContract(t *testing.T) {
	for _, tt := range []struct{ names, codes string }{
		{"loss,snt,last,avg,best,wrst,stdev", "LSNABWV"},
		{"received", "r"}, {" LAST ", "n"},
		{"loss,snt,received,last,avg,best,wrst,stdev", "L S R N A B W V"},
		{"stdev,wrst,best,avg,last,received,snt,loss", "vwb anrsl"},
		{"avg,received,loss,stdev,snt", "ARLVS"},
	} {
		a, err := ParseMTRColumns(tt.names, false)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseMTRColumns(tt.codes, true)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(a, b) {
			t.Fatalf("%q != %q", a, b)
		}
		c, err := ParseMTRColumns(MTRColumnCodes(a), true)
		if err != nil || !slices.Equal(a, c) {
			t.Fatalf("roundtrip: %v", err)
		}
	}
	for _, s := range []string{"", " ", ",", "loss,", ",snt", "loss,,snt", "loss,LOSS", "rcv", "jitter"} {
		if _, err := ParseMTRColumns(s, false); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"", " ", "LL", "l L", "X", "L,S", "L\nS", "L\tS", "Ｌ"} {
		if _, err := ParseMTRColumns(s, true); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestMTRSelectedLayoutPreservesCompleteNumbers(t *testing.T) {
	columns, _ := ParseMTRColumns("received,stdev,loss,snt,last,avg,best,wrst", false)
	maxInt := int(^uint(0) >> 1)
	stats := []trace.MTRHopStat{
		{TTL: 1, IP: "192.0.2.1", Host: "中文主机.example.test", Snt: maxInt, Received: 1000, Last: 0, Avg: 1.23, Best: 0, Wrst: 99999.99, StDev: 12.34, MPLS: []string{"[MPLS: Lbl 123 Exp 0 S 1 TTL 1]"}},
		{TTL: 1, IP: "192.0.2.2", Snt: 1000, Received: 999, Loss: 0.1},
		{TTL: 2, Loss: 100, Snt: 1000},
	}
	before := fmt.Sprint(stats)
	for _, width := range []int{24, 40, 60, 80, 120, 200} {
		var b strings.Builder
		renderMTRSelectedColumns(&b, MTRTUIHeader{Columns: columns, Lang: "cn"}, stats, width)
		out := b.String()
		for _, line := range strings.Split(out, "\r\n") {
			if displayWidth(line) > width {
				t.Fatalf("width %d overflow: %q", width, line)
			}
		}
		if strings.Contains(out, "Select fewer") {
			continue
		}
		for _, value := range []string{fmt.Sprint(maxInt), "1000", "99999.99", "0.00", "12.34", "Rcv"} {
			if !strings.Contains(out, value) {
				t.Fatalf("missing %s at %d: %s", value, width, out)
			}
		}
		if strings.Contains(out, "Packets") || strings.Contains(out, "Pings") {
			t.Fatal("misleading groups")
		}
	}
	if fmt.Sprint(stats) != before {
		t.Fatal("renderer changed statistics")
	}
	widths := mtrColumnWidths(columns, stats)
	if widths[0] != 4 || widths[3] != len(fmt.Sprint(maxInt)) {
		t.Fatalf("count widths %v", widths)
	}
	if strings.TrimSpace(mtrSelectedMetrics(columns, widths, &stats[2], false)) != "" {
		t.Fatal("waiting metrics not blank")
	}
	if sntWidthForMax(maxInt) != len(fmt.Sprint(maxInt)) {
		t.Fatal("max integer width")
	}
}

func TestMTRSelectedReportAndTableOrder(t *testing.T) {
	columns, _ := ParseMTRColumns("received,avg,loss", false)
	stats := []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Snt: 1000, Received: 999, Avg: 1.23, Loss: 0.1}}
	for _, wide := range []bool{false, true} {
		out := captureStdout(t, func() { MTRReportPrint(stats, MTRReportOptions{Columns: columns, SrcHost: "source", Wide: wide}) })
		if !strings.Contains(out, "Rcv  Avg Loss%") || !strings.Contains(out, "999 1.23  0.1%") || strings.Contains(out, "StDev") {
			t.Fatal(out)
		}
	}
	out := captureStdout(t, func() { MTRTablePrinterWithColumns(stats, 1, 0, 0, "cn", false, columns) })
	for _, v := range []string{"Hop", "Rcv", "Avg", "Loss%", "Host"} {
		i := strings.Index(out, v)
		if i < 0 {
			t.Fatal(out)
		}
		out = out[i+len(v):]
	}
}

func TestMTRCustomFrameAndEditorStayWithinTerminal(t *testing.T) {
	columns, _ := ParseMTRColumns("received,loss,snt,last,avg,best,wrst,stdev", false)
	for _, width := range []int{24, 40, 60, 80, 120, 200} {
		for _, editing := range []bool{false, true} {
			header := MTRTUIHeader{Columns: columns, ColumnEditor: MTRColumnEditor{Active: editing, Draft: strings.Repeat("L", 256)}, Target: "192.0.2.1", SrcHost: "中文主机.example", Status: MTRTUIPaused}
			out := mtrTUIRenderStringWithWidth(header, nil, width)
			out = strings.TrimPrefix(out, "\x1b[H\x1b[2J")
			for _, line := range strings.Split(out, "\r\n") {
				if displayWidth(line) > width {
					t.Fatalf("width %d: %q", width, line)
				}
			}
			if editing {
				for _, code := range []string{"L=Loss", "S=Snt", "R=Received", "N=Last", "A=Avg", "B=Best", "W=Wrst", "V=StDev"} {
					if !strings.Contains(out, code) {
						t.Fatalf("missing %s in %d: %s", code, width, out)
					}
				}
			} else if !strings.Contains(out, "O") {
				t.Fatal("missing O hint")
			}
		}
	}
}

func TestMTRColumnsDistinguishesEmptyAndUnknownEntries(t *testing.T) {
	for _, input := range []string{"", " ", ",loss", "loss,", "loss,,snt", "loss, ,snt"} {
		_, err := ParseMTRColumns(input, false)
		if err == nil || err.Error() != "empty MTR column entry" {
			t.Fatalf("input %q: %v", input, err)
		}
	}
	_, err := ParseMTRColumns("jitter", false)
	if err == nil || err.Error() != `unknown MTR column "jitter"` {
		t.Fatalf("unknown column: %v", err)
	}
}

func TestMTRDefaultControlsFitTerminal(t *testing.T) {
	for _, width := range []int{24, 40, 60, 80, 120, 160, 200} {
		for _, history := range []bool{false, true} {
			line := buildMTRTUIControlsLine(MTRTUIHeader{HistoryMode: history}, width)
			if displayWidth(line) > width {
				t.Fatalf("width %d: %q", width, line)
			}
			if !strings.Contains(line, "O") {
				t.Fatal("missing column editor hint")
			}
		}
	}
	line := buildMTRTUIControlsLine(MTRTUIHeader{}, 120)
	for _, hint := range []string{"O-columns", "Y-display", "N-host", "D-history(off)"} {
		if !strings.Contains(line, hint) {
			t.Fatalf("missing %q: %s", hint, line)
		}
	}
}

func TestMTRDefaultControlsMeasureVisibleColorWidth(t *testing.T) {
	old := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = old })
	line := buildMTRTUIControlsLine(MTRTUIHeader{}, 120)
	plain := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(line, "")
	if displayWidth(plain) > 120 || !strings.Contains(plain, "D-history(off)") {
		t.Fatalf("colored controls: %q", line)
	}
}
