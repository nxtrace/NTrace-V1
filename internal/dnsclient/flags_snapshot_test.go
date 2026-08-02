//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/natesales/q/cli"
)

const qFlagsV01912SnapshotSHA256 = "f420ba51fa495a0c12b8658f17af8a9a4e1d52543a632f3bfa2bd4017789408f"

func TestQFlagsV01912Snapshot(t *testing.T) {
	typeOfFlags := reflect.TypeOf(cli.Flags{})
	var snapshot strings.Builder
	for i := 0; i < typeOfFlags.NumField(); i++ {
		field := typeOfFlags.Field(i)
		_, _ = fmt.Fprintf(
			&snapshot,
			"%s|%s|%s\n",
			field.Name,
			field.Type,
			field.Tag,
		)
	}
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot.String())))
	if got != qFlagsV01912SnapshotSHA256 {
		t.Fatalf("q cli.Flags changed: snapshot sha256 = %s, want %s; review q cli/root orchestration before updating this test\n%s", got, qFlagsV01912SnapshotSHA256, snapshot.String())
	}
}
