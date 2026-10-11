package dnspot

import (
	"net"
	"net/netip"
	"sync"
)

// LimitListener returns a listener that keeps at most total connections
// open at a time, and at most perAddr from one address. A connection
// beyond either bound is closed right after it is accepted.
func LimitListener(l net.Listener, total, perAddr int) net.Listener {
	return &capListener{Listener: l, total: total, perAddr: perAddr, open: make(map[netip.Addr]int)}
}

type capListener struct {
	net.Listener
	total, perAddr int

	mu   sync.Mutex // guards the fields below
	n    int
	open map[netip.Addr]int
}

func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap.Addr().Unmap()
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		a := remoteAddr(c)
		l.mu.Lock()
		ok := l.n < l.total && l.open[a] < l.perAddr
		if ok {
			l.n++
			l.open[a]++
		}
		l.mu.Unlock()
		if !ok {
			c.Close()
			continue
		}
		return &capConn{Conn: c, l: l, addr: a}, nil
	}
}

func (l *capListener) release(a netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n--
	if l.open[a]--; l.open[a] <= 0 {
		delete(l.open, a)
	}
}

// Open returns the number of open connections.
func (l *capListener) Open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

type capConn struct {
	net.Conn
	l    *capListener
	addr netip.Addr
	once sync.Once
}

func (c *capConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.release(c.addr) })
	return err
}
