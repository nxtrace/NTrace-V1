//go:build linux && !386 && !s390x

package routeprobe

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func disconnectRawRouteSocket(fd int) error {
	addr := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	if errno != 0 {
		return errno
	}
	return nil
}
