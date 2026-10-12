// Package udp holds the read loop shared by the UDP pots.
package udp

import (
	"errors"
	"net"
	"net/netip"
	"time"
)

const (
	bufSize    = 65535
	minBackoff = time.Millisecond
	maxBackoff = time.Second
)

// Loop reads datagrams from conn and calls handle for each one until conn is
// closed, then returns nil. The request slice points into a buffer that is
// allocated once and reused: it is valid only during the call of handle, so
// handle must copy what it keeps. Other read errors are retried after a
// pause that doubles from 1 ms up to 1 s and starts again after a
// successful read.
func Loop(conn *net.UDPConn, handle func(req []byte, src netip.AddrPort)) error {
	return loop(conn.ReadFromUDPAddrPort, handle, time.Sleep)
}

func loop(read func([]byte) (int, netip.AddrPort, error), handle func([]byte, netip.AddrPort), sleep func(time.Duration)) error {
	buf := make([]byte, bufSize)
	pause := minBackoff
	for {
		n, src, err := read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			sleep(pause)
			if pause *= 2; pause > maxBackoff {
				pause = maxBackoff
			}
			continue
		}
		pause = minBackoff
		handle(buf[:n], src)
	}
}
