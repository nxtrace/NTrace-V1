//go:build darwin

package internal

import "context"

func checkTCPCapture(ctx context.Context, s *TCPSpec) []BackendCheck {
	return []BackendCheck{backendStep(ctx, "tcp_capture_filter", func() error {
		h, err := openDarwinTCPSniffHandle(s.captureDevice())
		if err != nil {
			return err
		}
		defer h.Close()
		return setDarwinTCPFilter(h, s.tcpCaptureFilter())
	})}
}

func checkUDPCapture(ctx context.Context, s *UDPSpec) []BackendCheck {
	return []BackendCheck{backendStep(ctx, "udp_capture_filter", func() error {
		h, err := s.openCapture()
		if err == nil {
			h.Close()
		}
		return err
	})}
}
