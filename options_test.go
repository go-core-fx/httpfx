package httpfx_test

import (
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
)

func TestWithRootCAFileSetsOption(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "typical_absolute_path", path: "/etc/ssl/certs/custom-root-ca.pem"},
		{name: "empty_path_clears_source", path: ""},
		{name: "relative_path", path: "certs/root-ca.pem"},
		{name: "path_with_spaces", path: "/etc/ssl/my certs/root ca.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpfx.ApplyOptionsForTest(httpfx.Config{}, httpfx.WithRootCAFile(tt.path))

			if got.TLS.RootCAFile != tt.path {
				t.Errorf("TLS.RootCAFile = %q, want %q", got.TLS.RootCAFile, tt.path)
			}
			if got.TLS.RootCAPEM != "" || got.TLS.RootCAReplaceSystem {
				t.Error("WithRootCAFile must not touch other root CA option fields")
			}
		})
	}
}

func TestWithRootCAPEMSetsOption(t *testing.T) {
	tests := []struct {
		name string
		pem  string
	}{
		{name: "single_cert_pem", pem: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"},
		{name: "empty_pem_clears_source", pem: ""},
		{name: "multi_cert_bundle", pem: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n" +
			"-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----\n"},
		{name: "garbage_payload", pem: "not a certificate at all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpfx.ApplyOptionsForTest(httpfx.Config{}, httpfx.WithRootCAPEM(tt.pem))

			if got.TLS.RootCAPEM != tt.pem {
				t.Errorf("TLS.RootCAPEM = %q, want %q", got.TLS.RootCAPEM, tt.pem)
			}
			if got.TLS.RootCAFile != "" || got.TLS.RootCAReplaceSystem {
				t.Error("WithRootCAPEM must not touch other root CA option fields")
			}
		})
	}
}

func TestWithRootCAReplaceSystemSetsOption(t *testing.T) {
	tests := []struct {
		name    string
		replace bool
	}{
		{name: "replace_true", replace: true},
		{name: "replace_false_explicit", replace: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpfx.ApplyOptionsForTest(
				httpfx.Config{},
				httpfx.WithRootCAReplaceSystem(tt.replace),
			)

			if got.TLS.RootCAReplaceSystem != tt.replace {
				t.Errorf("TLS.RootCAReplaceSystem = %t, want %t",
					got.TLS.RootCAReplaceSystem, tt.replace)
			}
			if got.TLS.RootCAFile != "" || got.TLS.RootCAPEM != "" {
				t.Error("WithRootCAReplaceSystem must not touch other root CA option fields")
			}
		})
	}
}

func TestClientOptionsApplyOverridesBaseTLS(t *testing.T) {
	base := httpfx.Config{
		ProxyURL: "socks5://127.0.0.1:1080",
		Bypass:   "localhost",
		Timeout:  30 * time.Second,
		TLS: httpfx.TLSConfig{
			RootCAFile:          "/base/ca.pem",
			RootCAPEM:           "base-pem-data",
			RootCAReplaceSystem: false,
		},
	}

	got := httpfx.ApplyOptionsForTest(base,
		httpfx.WithRootCAFile("/override/ca.pem"),
		httpfx.WithRootCAPEM("override-pem-data"),
		httpfx.WithRootCAReplaceSystem(true),
	)

	if got.TLS.RootCAFile != "/override/ca.pem" {
		t.Errorf("TLS.RootCAFile = %q, want %q", got.TLS.RootCAFile, "/override/ca.pem")
	}
	if got.TLS.RootCAPEM != "override-pem-data" {
		t.Errorf("TLS.RootCAPEM = %q, want %q", got.TLS.RootCAPEM, "override-pem-data")
	}
	if !got.TLS.RootCAReplaceSystem {
		t.Error("TLS.RootCAReplaceSystem = false, want true")
	}

	// Non-TLS base fields must pass through untouched.
	if got.ProxyURL != base.ProxyURL || got.Bypass != base.Bypass ||
		got.Timeout != base.Timeout {
		t.Errorf("apply() altered non-TLS fields: %+v", got)
	}

	// Value semantics: the caller's base config must stay untouched.
	if base.TLS.RootCAFile != "/base/ca.pem" || base.TLS.RootCAPEM != "base-pem-data" ||
		base.TLS.RootCAReplaceSystem {
		t.Errorf("apply() mutated base config TLS: %+v", base.TLS)
	}
}

func TestClientOptionsApplyWithoutRootCAKeepsBaseTLS(t *testing.T) {
	base := httpfx.Config{
		Timeout: time.Second,
		TLS: httpfx.TLSConfig{
			RootCAFile:          "/base/ca.pem",
			RootCAPEM:           "base-pem-data",
			RootCAReplaceSystem: true,
		},
	}

	got := httpfx.ApplyOptionsForTest(base, httpfx.WithTimeout(5*time.Second))

	if got.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v (option must still apply)", got.Timeout, 5*time.Second)
	}
	if got.TLS != base.TLS {
		t.Errorf("TLS = %+v, want untouched %+v when no root CA options are given",
			got.TLS, base.TLS)
	}
}

func TestClientOptionsApplyZeroValuesClearBaseTLS(t *testing.T) {
	base := httpfx.Config{
		TLS: httpfx.TLSConfig{
			RootCAFile:          "/base/ca.pem",
			RootCAPEM:           "base-pem-data",
			RootCAReplaceSystem: true,
		},
	}

	got := httpfx.ApplyOptionsForTest(base,
		httpfx.WithRootCAFile(""),
		httpfx.WithRootCAPEM(""),
		httpfx.WithRootCAReplaceSystem(false),
	)

	if got.TLS != (httpfx.TLSConfig{}) {
		t.Errorf("TLS = %+v, want zero value after explicit empty overrides", got.TLS)
	}
}

func TestWithProxyURLSetsURLAndBypass(t *testing.T) {
	got := httpfx.ApplyOptionsForTest(httpfx.Config{},
		httpfx.WithProxyURL("socks5://127.0.0.1:1080", "localhost,127.0.0.1"),
	)

	if got.ProxyURL != "socks5://127.0.0.1:1080" {
		t.Errorf("ProxyURL = %q, want %q", got.ProxyURL, "socks5://127.0.0.1:1080")
	}
	if got.Bypass != "localhost,127.0.0.1" {
		t.Errorf("Bypass = %q, want %q", got.Bypass, "localhost,127.0.0.1")
	}
}
