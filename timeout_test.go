package httpfx_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
)

// testTimeout bounds every request in this file. The assertions allow up to
// double it, so a broken bound (hang) fails the suite instead of stalling it.
const testTimeout = time.Millisecond * 300

// requestURL is dialed through the SOCKS5 proxy under test. No DNS lookup
// ever happens for it: the fake proxies below answer or stall first.
const requestURL = "http://telegram.test/bot123:getMe"

// watchdogTimeout is the outer bound enforced by startWatchdog: four times
// the client timeout, well past the 2x assertion bound, so it only fires
// when a request truly hangs instead of racing the normal deadline.
const watchdogTimeout = testTimeout * 4

// TestClientTimeoutBoundsDialThroughSilentProxy stands in for a wedged proxy
// process: the kernel accepts the TCP connection but the SOCKS5 handshake
// never progresses. The client Timeout must still bound the dial.
func TestClientTimeoutBoundsDialThroughSilentProxy(t *testing.T) { //nolint:paralleltest // clearProxyEnv uses t.Setenv
	clearProxyEnv(t)

	listener := startSilentTCPListener(t)

	client, err := httpfx.NewClientForTest(httpfx.Config{
		ProxyURL: "socks5://" + listener.addr(),
		Timeout:  testTimeout,
	})
	if err != nil {
		t.Fatalf("NewClientForTest() error = %v, want nil", err)
	}

	start := time.Now()
	watchdog := startWatchdog(t, watchdogTimeout, listener.closeAll)
	_, err = client.Get(requestURL)
	elapsed := time.Since(start)

	select {
	case <-watchdog:
		t.Fatal("watchdog force-closed the proxy connections while Get hung; client.Timeout did not bound the dial")
	default:
	}

	if err == nil {
		t.Fatal("Get() error = nil, want a timeout against a silent proxy")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Get() error = %v, want a deadline error", err)
	}
	if elapsed < testTimeout/2 {
		t.Errorf("Get() returned after %v, want at least the dial timeout %v", elapsed, testTimeout)
	}
	if elapsed > testTimeout*2 {
		t.Errorf("Get() returned after %v, want bounded by about %v", elapsed, testTimeout)
	}
}

// TestClientTimeoutBoundsRequestThroughHoldingProxy covers the production
// wedge shape: the SOCKS5 handshake and CONNECT reply complete, the request
// is delivered, and the answer never comes. The client Timeout must bound
// the wait for the response.
func TestClientTimeoutBoundsRequestThroughHoldingProxy(t *testing.T) { //nolint:paralleltest // env is set via t.Setenv
	clearProxyEnv(t)

	listener := startHoldingSocks5Listener(t)

	client, err := httpfx.NewClientForTest(httpfx.Config{
		ProxyURL: "socks5://" + listener.addr(),
		Timeout:  testTimeout,
	})
	if err != nil {
		t.Fatalf("NewClientForTest() error = %v, want nil", err)
	}

	start := time.Now()
	watchdog := startWatchdog(t, watchdogTimeout, listener.closeAll)
	_, err = client.Get(requestURL)
	elapsed := time.Since(start)

	select {
	case <-watchdog:
		t.Fatal("watchdog force-closed the proxy connections while Get hung; client.Timeout did not bound the request")
	default:
	}

	// The holding proxy must have received the HTTP request before the
	// client deadline: a timeout that fires during SOCKS5 negotiation
	// must not pass this test without exercising the response wait.
	select {
	case <-listener.received:
	case <-time.After(testTimeout):
		t.Fatal("request never reached the holding proxy; want the timeout to bound the response wait")
	}

	if err == nil {
		t.Fatal("Get() error = nil, want a timeout against a proxy that never answers")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get() error = %v, want context deadline exceeded", err)
	}
	if elapsed < testTimeout/2 {
		t.Errorf("Get() returned after %v, want at least the client timeout %v", elapsed, testTimeout)
	}
	if elapsed > testTimeout*2 {
		t.Errorf("Get() returned after %v, want bounded by about %v", elapsed, testTimeout)
	}
}

// startWatchdog arms an independent upper bound for a timeout test and
// returns a channel that closes only if the watchdog fires. It deliberately
// does not touch the request: a second request-level timeout could mask a
// failure of client.Timeout, the bound under test. Instead it closes the
// proxy connections, so a hung Get returns and the test fails with a
// bounded runtime instead of stalling until the test binary panics.
func startWatchdog(t *testing.T, timeout time.Duration, closeConns func()) <-chan struct{} {
	t.Helper()

	fired := make(chan struct{})
	done := make(chan struct{})

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-timer.C:
			close(fired)
			closeConns()
		case <-done:
		}
	}()

	t.Cleanup(func() { close(done) })

	return fired
}

// silentTCPListener accepts connections and never answers.
type silentTCPListener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startSilentTCPListener(t *testing.T) *silentTCPListener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	listener := &silentTCPListener{ln: ln}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			listener.mu.Lock()
			listener.conns = append(listener.conns, conn)
			listener.mu.Unlock()
		}
	}()

	t.Cleanup(listener.closeAll)

	return listener
}

func (l *silentTCPListener) addr() string {
	return l.ln.Addr().String()
}

// closeAll closes the listener and every accepted connection, unblocking
// any client dial still stuck in the silent handshake.
func (l *silentTCPListener) closeAll() {
	_ = l.ln.Close()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, conn := range l.conns {
		_ = conn.Close()
	}
}

// holdingSocks5Listener completes the SOCKS5 handshake and the CONNECT
// reply, then consumes client bytes without ever producing an HTTP response.
// received closes once a connection has delivered a full HTTP request.
type holdingSocks5Listener struct {
	ln       net.Listener
	received chan struct{}
	recvOnce sync.Once

	mu    sync.Mutex
	conns []net.Conn
}

func startHoldingSocks5Listener(t *testing.T) *holdingSocks5Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	listener := &holdingSocks5Listener{ln: ln, received: make(chan struct{})}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			listener.mu.Lock()
			listener.conns = append(listener.conns, conn)
			listener.mu.Unlock()

			go func() {
				_ = listener.handleConn(conn)
				_ = conn.Close()
			}()
		}
	}()

	t.Cleanup(listener.closeAll)

	return listener
}

func (l *holdingSocks5Listener) addr() string {
	return l.ln.Addr().String()
}

// closeAll closes the listener and every accepted connection, unblocking
// any client request still waiting for the held response.
func (l *holdingSocks5Listener) closeAll() {
	_ = l.ln.Close()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, conn := range l.conns {
		_ = conn.Close()
	}
}

// handleConn implements RFC 1928 no-auth negotiation far enough to answer
// CONNECT, reads the HTTP request, signals its receipt, and then swallows
// the connection without ever producing an HTTP response.
func (l *holdingSocks5Listener) handleConn(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil {
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}

	if err := skipSocks5Address(reader, header[3]); err != nil {
		return err
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return err
	}
	_ = binary.BigEndian.Uint16(portBytes[:])

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	// Read the HTTP request and signal its receipt: the test requires the
	// request to have arrived before it accepts the client timeout as a
	// response-wait bound.
	if err := readHTTPRequest(reader); err != nil {
		return err
	}
	l.recvOnce.Do(func() { close(l.received) })

	_, _ = io.Copy(io.Discard, conn)

	return nil
}

// readHTTPRequest consumes the request line and headers, returning once the
// blank line that terminates them has been read.
func readHTTPRequest(reader *bufio.Reader) error {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func skipSocks5Address(reader *bufio.Reader, addressType byte) error {
	switch addressType {
	case 0x01:
		var ip [4]byte
		_, err := io.ReadFull(reader, ip[:])
		return err
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return err
		}
		name := make([]byte, int(length[0]))
		_, err := io.ReadFull(reader, name)
		return err
	case 0x04:
		var ip [16]byte
		_, err := io.ReadFull(reader, ip[:])
		return err
	default:
		return errors.New("unsupported address type " + strconv.Itoa(int(addressType)))
	}
}
