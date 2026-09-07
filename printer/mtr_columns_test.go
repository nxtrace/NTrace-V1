package printer

import (
	"slices"
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
