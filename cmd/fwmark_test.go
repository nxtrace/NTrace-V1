package cmd

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestParseFWMark(t *testing.T) {
	for input, want := range map[string]uint32{"0": 0, "000256": 256, "256": 256, "0x100": 256, "0XFFFFFFFF": 0xffffffff, "4294967295": 0xffffffff} {
		got, err := parseFWMark(input, true)
		if err != nil || got != want {
			t.Fatalf("%q: %d %v", input, got, err)
		}
	}
	for _, input := range []string{"", "-1", "+1", "0x", "0b10", "0o10", "0x100/0xff", "4294967296", "0x100000000", " 1", "1_000"} {
		if _, err := parseFWMark(input, true); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	if _, err := parseFWMark("", false); err != nil {
		t.Fatal(err)
	}
}

func TestFWMarkArgumentBoundaries(t *testing.T) {
	for _, args := range [][]string{{"--fwmark", "0"}, {"--fwmark=0"}, {"--source", "127.0.0.1", "--fwmark", "256"}} {
		if !containsFWMarkFlag(args) {
			t.Fatal(args)
		}
	}
	for _, args := range [][]string{{"--", "--fwmark"}, {"--file", "--fwmark"}, {"--source=--fwmark"}, {"--output", "--fwmark"}} {
		if containsFWMarkFlag(args) {
			t.Fatal(args)
		}
	}
	if containsDoctorFlag([]string{"--fwmark", "--doctor"}) {
		t.Fatal("mark value stolen by doctor dispatcher")
	}
	for _, args := range [][]string{{"--dns", "--fwmark", "0"}, {"--speed", "--fwmark=0"}, {"--doctor", "--fwmark", "0"}} {
		var out, err bytes.Buffer
		var handled bool
		var code int
		switch args[0] {
		case "--dns":
			handled, code = maybeRunDNSModeWithAvailability(true, args, &out, &err, nil)
		case "--speed":
			handled, code = maybeRunSpeedModeWithAvailability(true, args, &out, &err)
		default:
			handled, code = maybeRunDoctorMode(args, &out, &err)
		}
		if !handled || code != 2 || out.Len() != 0 || err.Len() == 0 {
			t.Fatalf("%v: %v %d %q %q", args, handled, code, out.String(), err.String())
		}
	}
}

func TestFWMarkJSONOptionalParameter(t *testing.T) {
	for _, mark := range []*uint32{nil, new(uint32), ptrFWMark(0xffffffff)} {
		b, err := json.Marshal(mtrJSONParameters{FWMark: mark})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if mark == nil {
			if fields["fwmark"] != nil {
				t.Fatal(string(b))
			}
			continue
		}
		var got uint32
		if err = json.Unmarshal(fields["fwmark"], &got); err != nil || got != *mark {
			t.Fatalf("%s %v", b, err)
		}
	}
}
func ptrFWMark(v uint32) *uint32 { return &v }

func TestFWMarkConflictNamesMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only option")
	}
	for _, mode := range []string{"--mtu", "--dns", "--file", "--from"} {
		err := validateFWMarkMode(true, map[string]bool{mode: true, "--deploy": false})
		if err == nil || !strings.Contains(err.Error(), mode) {
			t.Fatalf("mode=%s err=%v", mode, err)
		}
	}
	if err := validateFWMarkMode(false, map[string]bool{"--mtu": true}); err != nil {
		t.Fatal(err)
	}
}
