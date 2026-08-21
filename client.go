package httpfx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/proxy"
)

func newClient(config Config) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
	}

	if err := applyProxy(transport, config); err != nil {
		return nil, err
	}

	tlsCfg, err := buildTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsCfg

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}, nil
}

func applyProxy(transport *http.Transport, config Config) error {
	switch {
	case config.ProxyURL != "":
		return applySOCKSProxy(transport, config.ProxyURL, config.Bypass)
	case config.ProxyFromEnv:
		return applyEnvProxy(transport, config.Bypass)
	default:
		return nil
	}
}

func applySOCKSProxy(transport *http.Transport, rawURL, bypass string) error {
	u, err := url.Parse(rawURL)
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

	dialer = applyBypass(dialer, bypass)
	setTransportDialer(transport, dialer)

	return nil
}

func applyEnvProxy(transport *http.Transport, bypass string) error {
	hasProxyEnv := os.Getenv("ALL_PROXY") != "" || os.Getenv("all_proxy") != ""

	dialer := proxy.FromEnvironment()

	if dialer == proxy.Direct {
		if hasProxyEnv {
			return fmt.Errorf("%w: proxy environment variable set but invalid", ErrInvalidProxyURL)
		}
		return nil
	}

	dialer = applyBypass(dialer, bypass)
	setTransportDialer(transport, dialer)

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
