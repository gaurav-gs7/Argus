package testutil

import (
	"io"
	"net"
	"sync"
	"testing"
)

// TCPProxy forwards connections to a target and can be severed and restored,
// to make a dependency unreachable for a while without stopping it.
type TCPProxy struct {
	t      *testing.T
	target string
	addr   string

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
}

// NewTCPProxy listens on a free local port and forwards to target
// ("host:port"). It is closed when the test ends.
func NewTCPProxy(t *testing.T, target string) *TCPProxy {
	t.Helper()
	p := &TCPProxy{t: t, target: target, conns: map[net.Conn]struct{}{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p.addr = listener.Addr().String()
	p.serve(listener)
	t.Cleanup(p.Sever)
	return p
}

// Addr is the proxy's "host:port".
func (p *TCPProxy) Addr() string { return p.addr }

func (p *TCPProxy) serve(listener net.Listener) {
	p.mu.Lock()
	p.listener = listener
	p.mu.Unlock()
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", p.target)
			if err != nil {
				client.Close()
				continue
			}
			p.mu.Lock()
			p.conns[client], p.conns[upstream] = struct{}{}, struct{}{}
			p.mu.Unlock()
			go func() { _, _ = io.Copy(upstream, client); upstream.Close() }()
			go func() { _, _ = io.Copy(client, upstream); client.Close() }()
		}
	}()
}

// Sever drops every connection and refuses new ones.
func (p *TCPProxy) Sever() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		p.listener.Close()
		p.listener = nil
	}
	for conn := range p.conns {
		conn.Close()
	}
	p.conns = map[net.Conn]struct{}{}
}

// Restore accepts connections again on the same address.
func (p *TCPProxy) Restore() {
	p.t.Helper()
	listener, err := net.Listen("tcp", p.addr)
	if err != nil {
		p.t.Fatalf("restore proxy on %s: %v", p.addr, err)
	}
	p.serve(listener)
}
