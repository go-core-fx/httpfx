package httpfx_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
	"golang.org/x/net/proxy"
)

// errFakeDialerFailure is the sentinel error returned by fakeDialer. It proves
// a dial was routed through the (always failing) proxy instead of bypassing it.
var errFakeDialerFailure = errors.New("fake dialer failure")

// fakeDialer is a proxy.Dialer that always fails. Combined with applyBypass,
// it distinguishes proxied dials (fail with errFakeDialerFailure) from
// bypassed dials (connect directly and succeed).
type fakeDialer struct{}

func (fakeDialer) Dial(_, _ string) (net.Conn, error) {
	return nil, errFakeDialerFailure
}

// clearProxyEnv clears every proxy-related environment variable so the
// SOCKS5 tests are hermetic regardless of the host's proxy configuration.
func clearProxyEnv(t *testing.T) {
	t.Helper()

	for _, key := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(key, "")
	}
}

func TestClientDefaultConfig(t *testing.T) {
	client, err := httpfx.NewClientForTest(httpfx.Config{})
	if err != nil {
		t.Fatalf("httpfx.NewClientForTest(httpfx.Config{}) returned error: %v", err)
	}
	if client == nil {
		t.Fatal("httpfx.NewClientForTest(httpfx.Config{}) returned nil client")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)

	if transport.Proxy == nil {
		t.Error("transport.Proxy = nil, want inherited http.DefaultTransport.Proxy")
	}
	if transport.DialContext == nil {
		t.Error("transport.DialContext = nil, want inherited http.DefaultTransport.DialContext")
	}
	if client.Timeout != 0 {
		t.Errorf("client.Timeout = %v, want 0 (inherits http.DefaultClient)", client.Timeout)
	}
	if transport.MaxIdleConns != defaultTransport.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want inherited default %d",
			transport.MaxIdleConns, defaultTransport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != defaultTransport.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want inherited default %d",
			transport.MaxIdleConnsPerHost, defaultTransport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != defaultTransport.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want inherited default %v",
			transport.IdleConnTimeout, defaultTransport.IdleConnTimeout)
	}
	if transport == defaultTransport {
		t.Error("client Transport is the shared http.DefaultTransport, want a distinct clone")
	}
}

func TestClientInvalidProxyURL(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
	}{
		{name: "missing_scheme", proxyURL: "://missing-scheme"},
		{name: "invalid_percent_escape", proxyURL: "socks5://%zz@127.0.0.1:1080"},
		{name: "empty_hostname", proxyURL: "socks5://:1080"},
		{name: "colon_port_without_scheme", proxyURL: "127.0.0.1:1080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := httpfx.NewClientForTest(httpfx.Config{ProxyURL: tt.proxyURL})

			if client != nil {
				t.Errorf("client = %v, want nil on error", client)
			}
			if err == nil {
				t.Fatal("httpfx.NewClientForTest() error = nil, want httpfx.ErrInvalidProxyURL")
			}
			if !errors.Is(err, httpfx.ErrInvalidProxyURL) {
				t.Errorf("error = %v, want wrapped httpfx.ErrInvalidProxyURL", err)
			}
		})
	}
}

func TestClientTransportSettings(t *testing.T) {
	defaultTransport := http.DefaultTransport.(*http.Transport)

	tests := []struct {
		name                    string
		config                  httpfx.Config
		wantMaxIdleConns        int
		wantMaxIdleConnsPerHost int
		wantIdleConnTimeout     time.Duration
		wantTimeout             time.Duration
	}{
		{
			name:                    "zero_defaults",
			config:                  httpfx.Config{},
			wantMaxIdleConns:        defaultTransport.MaxIdleConns,
			wantMaxIdleConnsPerHost: defaultTransport.MaxIdleConnsPerHost,
			wantIdleConnTimeout:     defaultTransport.IdleConnTimeout,
			wantTimeout:             0,
		},
		{
			name: "typical_values",
			config: httpfx.Config{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				Timeout:             30 * time.Second,
			},
			wantMaxIdleConns:        100,
			wantMaxIdleConnsPerHost: 10,
			wantIdleConnTimeout:     90 * time.Second,
			wantTimeout:             30 * time.Second,
		},
		{
			name: "negative_values_propagated_verbatim",
			config: httpfx.Config{
				MaxIdleConns:        -1,
				MaxIdleConnsPerHost: -1,
				IdleConnTimeout:     -time.Second,
				Timeout:             -time.Second,
			},
			wantMaxIdleConns:        -1,
			wantMaxIdleConnsPerHost: -1,
			wantIdleConnTimeout:     -time.Second,
			wantTimeout:             -time.Second,
		},
		{
			name: "large_values",
			config: httpfx.Config{
				MaxIdleConns:        1<<31 - 1,
				MaxIdleConnsPerHost: 4096,
				IdleConnTimeout:     24 * time.Hour,
				Timeout:             time.Hour,
			},
			wantMaxIdleConns:        1<<31 - 1,
			wantMaxIdleConnsPerHost: 4096,
			wantIdleConnTimeout:     24 * time.Hour,
			wantTimeout:             time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := httpfx.NewClientForTest(tt.config)
			if err != nil {
				t.Fatalf("httpfx.NewClientForTest() error = %v, want nil", err)
			}

			transport, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
			}

			if transport.MaxIdleConns != tt.wantMaxIdleConns {
				t.Errorf("MaxIdleConns = %d, want %d",
					transport.MaxIdleConns, tt.wantMaxIdleConns)
			}
			if transport.MaxIdleConnsPerHost != tt.wantMaxIdleConnsPerHost {
				t.Errorf("MaxIdleConnsPerHost = %d, want %d",
					transport.MaxIdleConnsPerHost, tt.wantMaxIdleConnsPerHost)
			}
			if transport.IdleConnTimeout != tt.wantIdleConnTimeout {
				t.Errorf("IdleConnTimeout = %v, want %v",
					transport.IdleConnTimeout, tt.wantIdleConnTimeout)
			}
			if client.Timeout != tt.wantTimeout {
				t.Errorf("client.Timeout = %v, want %v", client.Timeout, tt.wantTimeout)
			}
		})
	}
}

func TestClientDistinctTransportsPerCall(t *testing.T) {
	cfg := httpfx.Config{MaxIdleConns: 42}

	first, err := httpfx.NewClientForTest(cfg)
	if err != nil {
		t.Fatalf("first httpfx.NewClientForTest() error = %v, want nil", err)
	}
	second, err := httpfx.NewClientForTest(cfg)
	if err != nil {
		t.Fatalf("second httpfx.NewClientForTest() error = %v, want nil", err)
	}

	t1, ok := first.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("first Transport type = %T, want *http.Transport", first.Transport)
	}
	t2, ok := second.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("second Transport type = %T, want *http.Transport", second.Transport)
	}

	if t1 == t2 {
		t.Error("clients created from identical config share a transport, want distinct instances")
	}
}

func TestClientSOCKS5Proxy(t *testing.T) {
	tests := []struct {
		name       string
		config     httpfx.Config
		wantErr    error
		wantDialer bool
	}{
		{
			name:       "plain_socks5_sets_dial_context",
			config:     httpfx.Config{ProxyURL: "socks5://127.0.0.1:1080"},
			wantDialer: true,
		},
		{
			name:       "socks5_with_userinfo",
			config:     httpfx.Config{ProxyURL: "socks5://user:secret@127.0.0.1:1080"},
			wantDialer: true,
		},
		{
			name: "socks5_with_comma_separated_bypass_list",
			config: httpfx.Config{
				ProxyURL: "socks5://127.0.0.1:1080",
				Bypass:   "localhost,127.0.0.1,10.0.0.0/8",
			},
			wantDialer: true,
		},
		{
			name: "socks5_with_whitespace_padded_bypass",
			config: httpfx.Config{
				ProxyURL: "socks5://127.0.0.1:1080",
				Bypass:   "  localhost, 127.0.0.1  ",
			},
			wantDialer: true,
		},
		{
			name:       "unsupported_scheme_rejected_as_invalid",
			config:     httpfx.Config{ProxyURL: "http://127.0.0.1:8080"},
			wantErr:    httpfx.ErrInvalidProxyURL,
			wantDialer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearProxyEnv(t)

			client, err := httpfx.NewClientForTest(tt.config)

			if tt.wantErr != nil {
				if client != nil {
					t.Errorf("client = %v, want nil on error", client)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want wrapped %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("httpfx.NewClientForTest() error = %v, want nil", err)
			}

			transport, ok := client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
			}

			// SOCKS5 proxies are handled at the dialer layer via
			// transport.DialContext. The transport.Proxy field is inherited
			// from http.DefaultTransport and left untouched here.
			if tt.wantDialer && transport.DialContext == nil {
				t.Error("transport.DialContext = nil, want non-nil SOCKS5 dialer")
			}
			if !tt.wantDialer && transport.DialContext != nil {
				t.Error("transport.DialContext set, want nil")
			}
		})
	}
}

func TestClientBypassStringHandling(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open loopback listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	tests := []struct {
		name       string
		bypass     string
		wantDirect bool
		wantSame   bool // applyBypass must return the input dialer unwrapped
	}{
		{
			name:       "empty_bypass_returns_original_dialer",
			bypass:     "",
			wantDirect: false,
			wantSame:   true,
		},
		{
			name:       "whitespace_only_bypass_returns_original_dialer",
			bypass:     "   ",
			wantDirect: false,
			wantSame:   true,
		},
		{
			name:       "exact_ip_bypass_connects_directly",
			bypass:     "127.0.0.1",
			wantDirect: true,
		},
		{
			name:       "cidr_bypass_connects_directly",
			bypass:     "127.0.0.0/8",
			wantDirect: true,
		},
		{
			name:       "comma_separated_list_matches_entry",
			bypass:     "localhost,127.0.0.1,10.0.0.0/8",
			wantDirect: true,
		},
		{
			name:       "non_matching_cidr_still_proxied",
			bypass:     "10.0.0.0/8",
			wantDirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := httpfx.ApplyBypassForTest(fakeDialer{}, tt.bypass)

			if tt.wantSame {
				if _, ok := dialer.(fakeDialer); !ok {
					t.Fatalf("httpfx.ApplyBypassForTest(%q) returned %T, want original fakeDialer", tt.bypass, dialer)
				}
			} else if _, ok := dialer.(*proxy.PerHost); !ok {
				t.Fatalf("httpfx.ApplyBypassForTest(%q) returned %T, want *proxy.PerHost", tt.bypass, dialer)
			}

			conn, dialErr := dialer.Dial("tcp", addr)

			if tt.wantDirect {
				if dialErr != nil {
					t.Fatalf("Dial(%q) with bypass %q error = %v, want direct connect", addr, tt.bypass, dialErr)
				}
				if conn == nil {
					t.Fatal("Dial() conn = nil, want established connection")
				}
				_ = conn.Close()
				return
			}

			if !errors.Is(dialErr, errFakeDialerFailure) {
				t.Errorf("Dial(%q) with bypass %q error = %v, want proxied dial (%v)",
					addr, tt.bypass, dialErr, errFakeDialerFailure)
			}
		})
	}
}

// recordingProxy implements http.ProxyFunc: it records every call and returns
// a dummy proxy URL. It proves whether the transport routed a request through
// an inherited HTTP proxy function.
type recordingProxy struct {
	calls atomic.Int64
}

func (r *recordingProxy) proxyFunc() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) {
		r.calls.Add(1)
		return &url.URL{Scheme: "http", Host: "inherited-proxy.invalid:8080"}, nil
	}
}

// TestClientSOCKS5ClearsInheritedProxy verifies that configuring a SOCKS5
// ProxyURL disables any HTTP proxy inherited from the cloned base transport.
// If transport.Proxy were left set, requests would be tunneled through the
// inherited HTTP proxy instead of the configured SOCKS5 dialer.
func TestClientSOCKS5ClearsInheritedProxy(t *testing.T) {
	clearProxyEnv(t)

	// Install a sentinel inherited proxy on the base transport, then restore
	// it so other tests keep inheriting the default behavior.
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not *http.Transport; cannot inject inherited proxy")
	}
	origProxy := baseTransport.Proxy
	rec := &recordingProxy{}
	baseTransport.Proxy = rec.proxyFunc()
	t.Cleanup(func() { baseTransport.Proxy = origProxy })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open loopback listener: %v", err)
	}
	defer listener.Close()

	client, err := httpfx.NewClientForTest(httpfx.Config{
		ProxyURL: "socks5://127.0.0.1:1080",
		Bypass:   "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("httpfx.NewClientForTest() error = %v, want nil", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}

	// The inherited HTTP proxy must be cleared so SOCKS5 is the only path.
	if transport.Proxy != nil {
		t.Error("transport.Proxy != nil after SOCKS5 config, want cleared inherited proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("transport.DialContext = nil, want SOCKS5 dialer")
	}

	// A bypassed address must dial directly (PerHost routes it to proxy.Direct)
	// and must NOT reach the inherited HTTP proxy.
	bypassedConn, dialErr := transport.DialContext(context.Background(), "tcp", listener.Addr().String())
	if dialErr != nil {
		t.Fatalf("DialContext(bypassed %q) error = %v, want direct connect", listener.Addr().String(), dialErr)
	}
	_ = bypassedConn.Close()

	// A non-bypassed address must go through the SOCKS5 dialer (to the
	// configured, non-running proxy) and fail there — proving it did NOT use
	// the inherited HTTP proxy.
	if _, nonBypassedDialErr := transport.DialContext(
		context.Background(),
		"tcp",
		"10.0.0.1:80",
	); nonBypassedDialErr == nil {
		t.Error("DialContext(non-bypassed) succeeded, want SOCKS5 dial failure (no proxy server)")
	}

	if rec.calls.Load() != 0 {
		t.Errorf("inherited proxy func called %d times, want 0 (SOCKS5 path must bypass it)", rec.calls.Load())
	}
}
