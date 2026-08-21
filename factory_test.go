package httpfx_test

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
)

func TestNewClientAppliesRootCAOverrideEndToEnd(t *testing.T) {
	authority := newTestAuthority(t, "httpfx-option-ca")
	serverURL := startTLSServer(t, authority)

	factory := httpfx.NewFactory(httpfx.Config{})

	client, err := factory.NewClient(httpfx.WithRootCAPEM(string(authority.certPEM)))
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("NewClient() = nil client")
	}

	client.Timeout = 5 * time.Second
	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("request over option-provided CA failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestNewClientPerClientOverridesAreIndependent(t *testing.T) {
	baseAuthority := newTestAuthority(t, "httpfx-base-ca")
	overrideAuthority := newTestAuthority(t, "httpfx-override-ca")

	basePEM := string(baseAuthority.certPEM)
	clientFactory := httpfx.NewFactory(httpfx.Config{TLS: httpfx.TLSConfig{RootCAPEM: basePEM}})

	overrideClient, err := clientFactory.NewClient(
		httpfx.WithRootCAPEM(string(overrideAuthority.certPEM)),
	)
	if err != nil {
		t.Fatalf("override NewClient() error = %v, want nil", err)
	}

	defaultClient, err := clientFactory.NewClient()
	if err != nil {
		t.Fatalf("default NewClient() error = %v, want nil", err)
	}

	if overrideClient == nil || defaultClient == nil {
		t.Fatal("NewClient() returned nil client")
	}
	if overrideClient == defaultClient {
		t.Fatal("clients share one instance, want independent per-client configs")
	}

	overrideClient.Timeout = 5 * time.Second
	defaultClient.Timeout = 5 * time.Second

	// Override client must trust ONLY the override CA (replace-free append to
	// system pool still rejects an unknown authority).
	overrideURL := startTLSServer(t, overrideAuthority)
	if _, reqErr := overrideClient.Get(overrideURL); reqErr != nil {
		t.Errorf("override client rejected its own CA: %v", reqErr)
	}
	if resp, reqErr := defaultClient.Get(overrideURL); reqErr == nil {
		resp.Body.Close()
		t.Error("default client trusted override CA, want base config unchanged")
	} else if !strings.Contains(reqErr.Error(), "certificate") {
		t.Errorf("default client failure = %v, want certificate verification error", reqErr)
	}

	// Default client must still trust the base CA.
	baseURL := startTLSServer(t, baseAuthority)
	if resp, reqErr := defaultClient.Get(baseURL); reqErr != nil {
		t.Errorf("default client lost base CA trust: %v", reqErr)
	} else {
		resp.Body.Close()
	}

	// Base factory config must remain untouched by the override call.
	stored := httpfx.FactoryConfigForTest(clientFactory).TLS
	if stored.RootCAPEM != basePEM {
		t.Errorf("factory config TLS.RootCAPEM mutated: len = %d, want %d, present = %v",
			len(stored.RootCAPEM), len(basePEM), len(stored.RootCAPEM) > 0)
	}
	if stored.RootCAFile != "" || stored.RootCAReplaceSystem {
		t.Errorf("factory config TLS gained unexpected fields: RootCAFile = %q, RootCAReplaceSystem = %v",
			stored.RootCAFile, stored.RootCAReplaceSystem)
	}
}

func TestNewClientInvalidConfigReturnsError(t *testing.T) {
	garbagePEM := "-----BEGIN CERTIFICATE-----\n" +
		sensitivePayloadMarker + "\n" +
		"-----END CERTIFICATE-----\n"

	validAuthority := newTestAuthority(t, "httpfx-valid-base-ca")

	tests := []struct {
		name       string
		baseConfig httpfx.Config
		opts       []httpfx.Option
		wantErr    error
	}{
		{
			name:       "invalid_root_ca_file_in_base_config",
			baseConfig: httpfx.Config{TLS: httpfx.TLSConfig{RootCAFile: filepath.Join(t.TempDir(), "missing.pem")}},
			wantErr:    httpfx.ErrCertPoolFailed,
		},
		{
			name:    "missing_file_via_option",
			opts:    []httpfx.Option{httpfx.WithRootCAFile(filepath.Join(t.TempDir(), "missing.pem"))},
			wantErr: httpfx.ErrCertPoolFailed,
		},
		{
			name:    "directory_as_file_via_option",
			opts:    []httpfx.Option{httpfx.WithRootCAFile(t.TempDir())},
			wantErr: httpfx.ErrCertPoolFailed,
		},
		{
			name:    "garbage_pem_via_option",
			opts:    []httpfx.Option{httpfx.WithRootCAPEM(garbagePEM)},
			wantErr: httpfx.ErrEmptyCertPEM,
		},
		{
			name:       "invalid_option_overrides_valid_base_config",
			baseConfig: httpfx.Config{TLS: httpfx.TLSConfig{RootCAPEM: string(validAuthority.certPEM)}},
			opts:       []httpfx.Option{httpfx.WithRootCAPEM(garbagePEM)},
			wantErr:    httpfx.ErrEmptyCertPEM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := httpfx.NewFactory(tt.baseConfig)

			client, err := factory.NewClient(tt.opts...)

			if client != nil {
				t.Errorf("client = %v, want nil on construction failure", client)
			}
			if err == nil {
				t.Fatal("NewClient() error = nil, want error for invalid config")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapped %v", err, tt.wantErr)
			}

			// Hard constraint: raw PEM/cert payloads must never reach error text.
			if strings.Contains(err.Error(), sensitivePayloadMarker) {
				t.Error("error text leaks raw PEM payload contents")
			}
		})
	}
}

func TestNewClientSuccessReturnsUsableClient(t *testing.T) {
	factory := httpfx.NewFactory(httpfx.Config{})

	client, err := factory.NewClient(httpfx.WithRootCAReplaceSystem(false))
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("client = nil, want successfully constructed client")
	}
}
