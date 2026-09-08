//go:build windows && amd64

package internal

import (
	"errors"
	"net"
	"testing"
)

func TestClosedICMPSpecCannotReopenLazyWinDivertHandle(t *testing.T) {
	spec := &ICMPSpec{}
	spec.Close()
	spec.Close()
	_, err := spec.sendICMPWithWinDivert(true)
	if !errors.Is(err, net.ErrClosed) || spec.sendHandle != 0 {
		t.Fatalf("closed spec reopened a send handle: handle=%v error=%v", spec.sendHandle, err)
	}
}
