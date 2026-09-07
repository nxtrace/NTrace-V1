package printer

import (
	"fmt"
	"github.com/nxtrace/NTrace-core/trace"
	"slices"
	"strings"
	"testing"
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
