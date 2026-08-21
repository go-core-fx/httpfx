package httpfx_test

import (
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
	"golang.org/x/net/proxy"
)

// Environment variables coordinating the child-process scenarios in
// TestClientProxyFromEnv.
const (
	envProxyTestCase  = "HTTPFX_TEST_ENV_PROXY_CASE"
	envProxyTestKey   = "HTTPFX_TEST_ENV_PROXY_KEY"
	envProxyTestValue = "HTTPFX_TEST_ENV_PROXY_VALUE"
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

// clearProxyEnv clears every environment variable that proxy.FromEnvironment
// consults, making env-dependent tests hermetic.
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

	if transport.Proxy != nil {
		t.Errorf("transport.Proxy set = %t, want false (no proxy by default)", transport.Proxy != nil)
	}
	if transport.DialContext != nil {
		t.Errorf("transport.DialContext set = %t, want false (no proxy by default)",
			transport.DialContext != nil)
	}
	if client.Timeout != 0 {
		t.Errorf("client.Timeout = %v, want 0", client.Timeout)
	}
	if transport.MaxIdleConns != 0 {
		t.Errorf("MaxIdleConns = %d, want 0", transport.MaxIdleConns)
	}
	if transport.IdleConnTimeout != 0 {
		t.Errorf("IdleConnTimeout = %v, want 0", transport.IdleConnTimeout)
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
	tests := []struct {
		name                    string
		config                  httpfx.Config
		wantMaxIdleConns        int
		wantMaxIdleConnsPerHost int
		wantIdleConnTimeout     time.Duration
		wantTimeout             time.Duration
	}{
		{
			name:                "zero_defaults",
			config:              httpfx.Config{},
			wantMaxIdleConns:    0,
			wantTimeout:         0,
			wantIdleConnTimeout: 0,
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
			name:       "unsupported_scheme_fails_dialer_creation",
			config:     httpfx.Config{ProxyURL: "http://127.0.0.1:8080"},
			wantErr:    httpfx.ErrProxyDialFailed,
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

			// SOCKS5 proxies are handled at the dialer layer, not via
			// transport.Proxy (which is for HTTP CONNECT proxies).
			if transport.Proxy != nil {
				t.Error("transport.Proxy set, want nil for SOCKS5 dialer")
			}
			if tt.wantDialer && transport.DialContext == nil {
				t.Error("transport.DialContext = nil, want non-nil SOCKS5 dialer")
			}
			if !tt.wantDialer && transport.DialContext != nil {
				t.Error("transport.DialContext set, want nil")
			}
		})
	}
}

func TestClientProxyURLTakesPrecedenceOverEnv(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("ALL_PROXY", "")

	client, err := httpfx.NewClientForTest(httpfx.Config{
		ProxyURL:     "socks5://127.0.0.1:1080",
		ProxyFromEnv: true,
	})
	if err != nil {
		t.Fatalf("httpfx.NewClientForTest() error = %v, want nil", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Error("transport.DialContext = nil, want explicit ProxyURL to win over env mode")
	}
}

// TestClientProxyFromEnv verifies the ProxyFromEnv path for every ALL_PROXY
// state. Each scenario runs in a fresh child process because
// golang.org/x/net/proxy caches the environment lookup (envOnce) on first use,
// making in-process t.Setenv variations unreliable.
func TestClientProxyFromEnv(t *testing.T) {
	if caseName := os.Getenv(envProxyTestCase); caseName != "" {
		runClientProxyFromEnvCase(t, caseName)
		return
	}

	tests := []struct {
		name     string
		envKey   string
		envValue string
		wantErr  error
	}{
		{
			name:     "valid_all_proxy_uppercase",
			envKey:   "ALL_PROXY",
			envValue: "socks5://127.0.0.1:1080",
		},
		{
			name:     "valid_all_proxy_lowercase",
			envKey:   "all_proxy",
			envValue: "socks5://127.0.0.1:1080",
		},
		{name: "unset_env_yields_direct_transport"},
		{
			name:     "unsupported_scheme_in_env",
			envKey:   "ALL_PROXY",
			envValue: "http://127.0.0.1:8080",
			wantErr:  httpfx.ErrInvalidProxyURL,
		},
		{
			name:     "unparseable_env_value",
			envKey:   "ALL_PROXY",
			envValue: ":::",
			wantErr:  httpfx.ErrInvalidProxyURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestClientProxyFromEnv$", "-test.v")
			cmd.Env = append(os.Environ(),
				envProxyTestCase+"="+tt.name,
				envProxyTestKey+"="+tt.envKey,
				envProxyTestValue+"="+tt.envValue,
			)

			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child process for case %q failed: %v\n%s", tt.name, err, out)
			}
		})
	}
}

// runClientProxyFromEnvCase executes a single env scenario inside the child
// process with a pristine proxy.FromEnvironment cache.
func runClientProxyFromEnvCase(t *testing.T, caseName string) {
	t.Helper()

	clearProxyEnv(t)

	var (
		wantErr    error
		wantDialer bool
	)

	switch caseName {
	case "valid_all_proxy_uppercase", "valid_all_proxy_lowercase":
		wantDialer = true
	case "unset_env_yields_direct_transport":
	case "unsupported_scheme_in_env", "unparseable_env_value":
		wantErr = httpfx.ErrInvalidProxyURL
	default:
		t.Fatalf("unknown env proxy test case %q", caseName)
	}

	if key := os.Getenv(envProxyTestKey); key != "" {
		t.Setenv(key, os.Getenv(envProxyTestValue))
	}

	client, err := httpfx.NewClientForTest(httpfx.Config{ProxyFromEnv: true})

	if wantErr != nil {
		if client != nil {
			t.Errorf("client = %v, want nil on error", client)
		}
		if !errors.Is(err, wantErr) {
			t.Errorf("error = %v, want wrapped %v", err, wantErr)
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
	if wantDialer && transport.DialContext == nil {
		t.Error("transport.DialContext = nil, want env proxy dialer")
	}
	if !wantDialer && transport.DialContext != nil {
		t.Error("transport.DialContext set, want nil without proxy env")
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
