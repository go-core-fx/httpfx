package httpfx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

func newClient(config Config) (*http.Client, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	transport := base.Clone()

	if config.MaxIdleConns != 0 {
		transport.MaxIdleConns = config.MaxIdleConns
	}
	if config.MaxIdleConnsPerHost != 0 {
		transport.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
	}
	if config.IdleConnTimeout != 0 {
		transport.IdleConnTimeout = config.IdleConnTimeout
	}

	if err := applyProxy(transport, config); err != nil {
		return nil, err
	}

	tlsCfg, err := buildTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

	client := *http.DefaultClient
	client.Transport = transport
	if config.Timeout != 0 {
		client.Timeout = config.Timeout
	}

	return &client, nil
}

func applyProxy(transport *http.Transport, config Config) error {
	if config.ProxyURL == "" {
		return nil
	}

	if !strings.HasPrefix(config.ProxyURL, "socks5://") && !strings.HasPrefix(config.ProxyURL, "socks5h://") {
		return fmt.Errorf("%w: %q", ErrInvalidProxyURL, config.ProxyURL)
	}

	u, err := url.Parse(config.ProxyURL)
	if err != nil {
		return fmt.Errorf("%w", ErrInvalidProxyURL)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("%w: empty hostname", ErrInvalidProxyURL)
	}

	dialer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProxyDialFailed, err)
	}

	dialer = applyBypass(dialer, config.Bypass)
	setTransportDialer(transport, dialer)

	// Clear any proxy function inherited from the cloned base transport
	// (e.g. http.ProxyFromEnvironment). With SOCKS5 handled at the dialer
	// layer, leaving transport.Proxy set would tunnel requests through the
	// inherited HTTP proxy instead of the configured SOCKS5 dialer.
	transport.Proxy = nil

	return nil
}

func applyBypass(dialer proxy.Dialer, bypass string) proxy.Dialer {
	bypass = strings.TrimSpace(bypass)
	if bypass == "" {
		return dialer
	}

	perHost := proxy.NewPerHost(dialer, proxy.Direct)
	perHost.AddFromString(bypass)

	return perHost
}

func setTransportDialer(transport *http.Transport, dialer proxy.Dialer) {
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		transport.DialContext = cd.DialContext
		return
	}

	transport.DialContext = func(
		_ context.Context,
		network,
		addr string,
	) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
}
