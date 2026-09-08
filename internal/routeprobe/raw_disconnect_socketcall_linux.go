//go:build linux && (386 || s390x)

package routeprobe

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func disconnectRawRouteSocket(fd int) error {
	addr := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	// These architectures use socketcall on older supported Linux kernels.
	args := [3]uintptr{uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr)}
	const connectCall = 3
	_, _, errno := unix.Syscall(unix.SYS_SOCKETCALL, connectCall, uintptr(unsafe.Pointer(&args)), 0)
	runtime.KeepAlive(&addr)
	if errno != 0 {
		return errno
	}
	return nil
}
