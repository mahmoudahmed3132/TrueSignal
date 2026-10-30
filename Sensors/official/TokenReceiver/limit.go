package main

import (
	"net"
	"sync"
)

// The receiver faces the internet, so concurrent TCP clients are capped: a
// burst of idle connections could otherwise hold a goroutine and a
// descriptor each until its read deadline and starve beacon traffic. A
// connection beyond the cap is closed at once rather than queued, so slow
// clients can't hold the accept loop either.
const (
	maxDNSTCPConns = 128
	maxHTTPConns   = 256
)

type limitListener struct {
	net.Listener
	slots chan struct{}
}

func newLimitListener(ln net.Listener, max int) net.Listener {
	return &limitListener{Listener: ln, slots: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

// limitConn frees its slot on the first Close.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
