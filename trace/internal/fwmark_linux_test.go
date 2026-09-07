//go:build linux && !android

package internal

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

type fwmarkConn struct {
	net.PacketConn
	raw syscall.RawConn
	err error
}

func (c fwmarkConn) SyscallConn() (syscall.RawConn, error) { return c.raw, c.err }

type fwmarkRaw struct{ err error }

func (r fwmarkRaw) Control(fn func(uintptr)) error {
	if r.err != nil {
		return r.err
	}
	fn(^uintptr(0))
	return nil
}
func (r fwmarkRaw) Read(func(uintptr) bool) error  { return nil }
func (r fwmarkRaw) Write(func(uintptr) bool) error { return nil }

func TestFWMarkSocketErrors(t *testing.T) {
	if err := setPacketConnFWMark(nil, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := setPacketConnFWMark(nil, 0, true); err == nil {
		t.Fatal("explicit zero silently ignored")
	}
	for _, c := range []fwmarkConn{{err: syscall.EPERM}, {raw: fwmarkRaw{err: syscall.EPERM}}} {
		if err := setPacketConnFWMark(c, 256, true); !errors.Is(err, syscall.EPERM) {
			t.Fatal(err)
		}
	}
	if err := setPacketConnFWMark(fwmarkConn{raw: fwmarkRaw{}}, 256, true); !errors.Is(err, syscall.EBADF) {
		t.Fatal(err)
	}
}

func TestFWMarkNativeSockets(t *testing.T) {
	if os.Getenv("NEXTTRACE_FWMARK_INTEGRATION") != "1" {
		t.Skip("requires privileged Linux fixture")
	}
	for _, v := range []int{4, 6} {
		for _, mark := range []uint32{0, 256, 0xffffffff} {
			src := net.ParseIP("127.0.0.1")
			if v == 6 {
				src = net.ParseIP("::1")
			}
			icmp := NewICMPSpec(v, 0, 1234, src, src)
			icmp.FWMark, icmp.FWMarkSet = mark, true
			if err := icmp.InitICMP(); err != nil {
				t.Fatal(err)
			}
			checkSocketMark(t, icmp.icmp, mark)
			icmp.Close()
			tcp := NewTCPSpec(v, 0, src, src, 80, 0)
			tcp.FWMark, tcp.FWMarkSet = mark, true
			if err := tcp.InitTCP(); err != nil {
				t.Fatal(err)
			}
			if err := tcp.InitICMP(); err != nil {
				tcp.Close()
				t.Fatal(err)
			}
			checkSocketMark(t, tcp.tcp, mark)
			checkSocketMark(t, tcp.icmp, 0)
			tcp.Close()
			udp := NewUDPSpec(v, 0, src, src, 33494)
			udp.FWMark, udp.FWMarkSet = mark, true
			if err := udp.InitUDP(); err != nil {
				t.Fatal(err)
			}
			if err := udp.InitICMP(); err != nil {
				udp.Close()
				t.Fatal(err)
			}
			checkSocketMark(t, udp.udp, mark)
			checkSocketMark(t, udp.icmp, 0)
			udp.Close()
		}
	}
}
func checkSocketMark(t *testing.T, c net.PacketConn, want uint32) {
	t.Helper()
	r, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var optionErr error
	if err = r.Control(func(fd uintptr) { got, optionErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK) }); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil || uint32(got) != want {
		t.Fatalf("mark=%#x want=%#x error=%v", uint32(got), want, optionErr)
	}
}

func TestFWMarkPermissionDenied(t *testing.T) {
	if os.Getenv("NEXTTRACE_FWMARK_NO_CAPS") != "1" {
		t.Skip("requires capabilities removed by fixture")
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for _, mark := range []uint32{0, 256} {
		if err = setPacketConnFWMark(conn, mark, true); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("mark=%d error=%v", mark, err)
		}
	}
	checkSocketMark(t, conn, 0)
}
