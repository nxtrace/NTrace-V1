//go:build linux || darwin

package doctor

import (
	"context"
	"errors"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// The route socket is nonblocking; short poll intervals bound cancellation
// latency without leaving a goroutine owning a live descriptor.
func readRouteDatagram(ctx context.Context, fd int, buf []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		ms := 100
		if deadline, ok := ctx.Deadline(); ok {
			left := time.Until(deadline)
			if left <= 0 {
				return 0, context.DeadlineExceeded
			}
			if left < 100*time.Millisecond {
				ms = int(left/time.Millisecond) + 1
			}
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(p, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if p[0].Revents == 0 {
			continue
		}
		var n, flags int
		if runtime.GOOS == "darwin" {
			// x/sys Recvmsg attempts to decode the sender's AF_ROUTE sockaddr,
			// which it does not support. Routing messages already identify their
			// requester, so read the datagram without asking for a sockaddr.
			n, err = unix.Read(fd, buf)
			if n == len(buf) {
				return 0, errors.New("possibly truncated route response")
			}
		} else {
			n, _, flags, _, err = unix.Recvmsg(fd, buf, nil, 0)
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if flags&unix.MSG_TRUNC != 0 {
			return 0, errors.New("truncated route response")
		}
		return n, err
	}
}
