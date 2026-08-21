package httpfx

import (
	"crypto/tls"
	"net/http"

	"golang.org/x/net/proxy"
)

// NewClientForTest exposes newClient to the external httpfx_test package so
// black-box tests can exercise client construction and its error paths
// directly, mirroring what Factory.NewClient does internally.
func NewClientForTest(config Config) (*http.Client, error) {
	return newClient(config)
}

// BuildTLSConfigForTest exposes buildTLSConfig to the external httpfx_test
// package for direct verification of [*tls.Config] construction behavior.
func BuildTLSConfigForTest(tlsCfg TLSConfig) (*tls.Config, error) {
	return buildTLSConfig(tlsCfg)
}

// ApplyBypassForTest exposes applyBypass to the external httpfx_test package
// so tests can assert dialer wrapping semantics directly.
func ApplyBypassForTest(dialer proxy.Dialer, bypass string) proxy.Dialer {
	return applyBypass(dialer, bypass)
}

// ApplyOptionsForTest applies opts onto base exactly as Factory.NewClient
// does internally, returning the merged Config for inspection by black-box
// tests of the Option wiring.
func ApplyOptionsForTest(base Config, opts ...Option) Config {
	co := new(clientOptions)
	for _, opt := range opts {
		opt(co)
	}

	return co.apply(base)
}

// FactoryConfigForTest returns the base configuration stored in f, letting
// black-box tests verify that per-client overrides leave it untouched.
func FactoryConfigForTest(f Factory) Config {
	return f.(*factory).config
}
