package cmd

import (
	"github.com/akamensky/argparse"
	"testing"
)

func TestMTRColumnsModeContract(t *testing.T) {
	for _, tt := range []struct {
		name       string
		modes      effectiveMTRModes
		json       bool
		standalone string
		valid      bool
	}{
		{"traditional", effectiveMTRModes{}, false, "", false},
		{"tui", effectiveMTRModes{mtr: true}, false, "", true},
		{"report", effectiveMTRModes{mtr: true, report: true}, false, "", true},
		{"wide", effectiveMTRModes{mtr: true, report: true, wide: true}, false, "", true},
		{"raw", effectiveMTRModes{mtr: true, raw: true}, false, "", false},
		{"json", effectiveMTRModes{mtr: true}, true, "", false},
		{"standalone", effectiveMTRModes{mtr: true}, false, "--mtu", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveMTRColumns("received", true, tt.modes, tt.json, tt.standalone)
			if (err == nil) != tt.valid {
				t.Fatalf("%v", err)
			}
			cols, err := resolveMTRColumns("", false, tt.modes, tt.json, tt.standalone)
			if err != nil || cols != nil {
				t.Fatal("implicit selection changed")
			}
		})
	}
	p := argparse.NewParser("test", "")
	f := registerMTRFlags(p)
	if err := p.Parse([]string{"test", "--mtr-columns", "received"}); err != nil {
		t.Fatal(err)
	}
	if *f.columns != "received" || *f.mtrMode {
		t.Fatal("column flag changed mode")
	}
}
