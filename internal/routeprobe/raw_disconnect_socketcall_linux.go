//go:build linux && (386 || s390x)

package routeprobe

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func disconnectRawRouteSocket(fd int) error {
	addr := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	// These architectures use socketcall on older supported Linux kernels.
	// Keep the nested address visible to the GC if the stack moves. The
	// kernel still receives three native machine words in socketcall order.
	args := struct {
		fd     uintptr
		addr   unsafe.Pointer
		length uintptr
	}{uintptr(fd), unsafe.Pointer(&addr), unsafe.Sizeof(addr)}
	const connectCall = 3
	_, _, errno := unix.Syscall(unix.SYS_SOCKETCALL, connectCall, uintptr(unsafe.Pointer(&args)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
