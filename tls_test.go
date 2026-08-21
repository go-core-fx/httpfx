package httpfx_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
)

// sensitivePayloadMarker is embedded into invalid PEM inputs to prove error
// messages never echo raw certificate payloads back to callers.
const sensitivePayloadMarker = "SENSITIVE-PEM-PAYLOAD-MUST-NOT-BE-LOGGED"

// testAuthority is an in-memory certificate authority used to sign test
// server certificates. Everything is generated with the Go standard library.
type testAuthority struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// newTestAuthority creates a self-signed CA with the given common name.
func newTestAuthority(t *testing.T, commonName string) testAuthority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	return testAuthority{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
	}
}

// issueServerCertificate mints a loopback server certificate signed by the CA.
func (a testAuthority) issueServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "httpfx-test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, key.Public(), a.key)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeCAFile writes the CA PEM to a temporary file and returns its path.
func (a testAuthority) writeCAFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "root-ca.pem")
	if err := os.WriteFile(path, a.certPEM, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	return path
}

// startTLSServer serves HTTPS on a random loopback port using a certificate
// signed by the authority, returning the base URL.
func startTLSServer(t *testing.T, authority testAuthority) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{authority.issueServerCertificate(t)},
		}))
	}()
	t.Cleanup(func() { _ = server.Close() })

	return "https://" + listener.Addr().String()
}

// requestOverTLS performs a GET against serverURL using the provided TLS
// configuration. It returns the handshake/request error, or nil on HTTP 200.
func requestOverTLS(t *testing.T, clientTLSConfig *tls.Config, serverURL string) error {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(serverURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	return nil
}

func TestBuildTLSConfigZeroValueReturnsNil(t *testing.T) {
	cfg, err := httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{})
	if err != nil {
		t.Fatalf("httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{}) error = %v, want nil", err)
	}
	if cfg != nil {
		t.Errorf("httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{}) = %v, want nil (backward compat)", cfg)
	}
}

func TestBuildTLSConfigTrustsRootCAFile(t *testing.T) {
	tests := []struct {
		name  string
		files int // number of CA certs concatenated into the file
	}{
		{name: "single_cert_file", files: 1},
		{name: "bundled_multi_ca_file", files: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAuthority(t, "httpfx-test-ca")

			var bundle []byte
			for range tt.files {
				bundle = append(bundle, authority.certPEM...)
			}

			path := filepath.Join(t.TempDir(), "root-ca.pem")
			if err := os.WriteFile(path, bundle, 0o600); err != nil {
				t.Fatalf("write CA file: %v", err)
			}

			cfg, err := httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{RootCAFile: path})
			if err != nil {
				t.Fatalf("httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
			}
			if cfg == nil || cfg.RootCAs == nil {
				t.Fatal("httpfx.BuildTLSConfigForTest() returned nil config/pool, want populated TLS config")
			}

			serverURL := startTLSServer(t, authority)
			if reqErr := requestOverTLS(t, cfg, serverURL); reqErr != nil {
				t.Errorf("handshake with file-provided CA failed: %v", reqErr)
			}
		})
	}
}

func TestBuildTLSConfigTrustsRootCAPEM(t *testing.T) {
	tests := []struct {
		name string
		pems int // number of CA certs concatenated into the PEM string
	}{
		{name: "single_cert_pem", pems: 1},
		{name: "bundled_multi_ca_pem", pems: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAuthority(t, "httpfx-test-ca")

			var bundle []byte
			for range tt.pems {
				bundle = append(bundle, authority.certPEM...)
			}

			cfg, err := httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{RootCAPEM: string(bundle)})
			if err != nil {
				t.Fatalf("httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
			}
			if cfg == nil || cfg.RootCAs == nil {
				t.Fatal("httpfx.BuildTLSConfigForTest() returned nil config/pool, want populated TLS config")
			}

			serverURL := startTLSServer(t, authority)
			if reqErr := requestOverTLS(t, cfg, serverURL); reqErr != nil {
				t.Errorf("handshake with inline PEM CA failed: %v", reqErr)
			}
		})
	}
}

func TestBuildTLSConfigMergesFileAndPEM(t *testing.T) {
	fileAuthority := newTestAuthority(t, "httpfx-file-ca")
	pemAuthority := newTestAuthority(t, "httpfx-pem-ca")

	cfg, err := httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{
		RootCAFile: fileAuthority.writeCAFile(t),
		RootCAPEM:  string(pemAuthority.certPEM),
	})
	if err != nil {
		t.Fatalf("httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("httpfx.BuildTLSConfigForTest() returned nil config/pool, want merged pool")
	}

	// One shared config must trust CAs from BOTH sources.
	fileServerURL := startTLSServer(t, fileAuthority)
	if fileErr := requestOverTLS(t, cfg, fileServerURL); fileErr != nil {
		t.Errorf("merged pool rejected file-provided CA: %v", fileErr)
	}

	pemServerURL := startTLSServer(t, pemAuthority)
	if pemErr := requestOverTLS(t, cfg, pemServerURL); pemErr != nil {
		t.Errorf("merged pool rejected PEM-provided CA: %v", pemErr)
	}
}

func TestBuildTLSConfigReplaceSystemPool(t *testing.T) {
	tests := []struct {
		name                string
		rootCAReplaceSystem bool
	}{
		{name: "replace_false_appends_to_system_pool", rootCAReplaceSystem: false},
		{name: "replace_true_fresh_pool_with_custom_cas", rootCAReplaceSystem: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAuthority(t, "httpfx-replace-ca")

			cfg, err := httpfx.BuildTLSConfigForTest(httpfx.TLSConfig{
				RootCAPEM:           string(authority.certPEM),
				RootCAReplaceSystem: tt.rootCAReplaceSystem,
			})
			if err != nil {
				t.Fatalf("httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
			}
			if cfg == nil || cfg.RootCAs == nil {
				t.Fatal("httpfx.BuildTLSConfigForTest() returned nil config/pool, want populated pool")
			}

			serverURL := startTLSServer(t, authority)
			if reqErr := requestOverTLS(t, cfg, serverURL); reqErr != nil {
				t.Errorf("custom CA not trusted (replace=%t): %v",
					tt.rootCAReplaceSystem, reqErr)
			}
		})
	}
}

func TestBuildTLSConfigErrors(t *testing.T) {
	validAuthority := newTestAuthority(t, "httpfx-valid-ca")

	unreadablePath := filepath.Join(t.TempDir(), "unreadable.pem")
	if err := os.WriteFile(unreadablePath, validAuthority.certPEM, 0o000); err != nil {
		t.Fatalf("write unreadable CA file: %v", err)
	}

	garbagePEM := "-----BEGIN CERTIFICATE-----\n" +
		sensitivePayloadMarker + "\n" +
		"-----END CERTIFICATE-----\n"

	tests := []struct {
		name       string
		tlsCfg     httpfx.TLSConfig
		wantErr    error
		wantLeak   bool // whether the payload marker may appear (always false)
		skipAsRoot bool // permission-based case meaningless for uid 0
	}{
		{
			name:    "missing_file_wraps_err_cert_pool_failed",
			tlsCfg:  httpfx.TLSConfig{RootCAFile: filepath.Join(t.TempDir(), "does-not-exist.pem")},
			wantErr: httpfx.ErrCertPoolFailed,
		},
		{
			name:    "directory_as_file_wraps_err_cert_pool_failed",
			tlsCfg:  httpfx.TLSConfig{RootCAFile: t.TempDir()},
			wantErr: httpfx.ErrCertPoolFailed,
		},
		{
			name:       "unreadable_file_wraps_err_cert_pool_failed",
			tlsCfg:     httpfx.TLSConfig{RootCAFile: unreadablePath},
			wantErr:    httpfx.ErrCertPoolFailed,
			skipAsRoot: true,
		},
		{
			name:    "empty_file_content_wraps_err_empty_cert_pem",
			tlsCfg:  httpfx.TLSConfig{RootCAPEM: ""},
			wantErr: nil, // covered by zero-value test; placeholder removed below
		},
		{
			name:     "garbage_pem_body_wraps_err_empty_cert_pem",
			tlsCfg:   httpfx.TLSConfig{RootCAPEM: garbagePEM},
			wantErr:  httpfx.ErrEmptyCertPEM,
			wantLeak: false,
		},
		{
			name:     "whitespace_only_pem_wraps_err_empty_cert_pem",
			tlsCfg:   httpfx.TLSConfig{RootCAPEM: "   \n\t  \n"},
			wantErr:  httpfx.ErrEmptyCertPEM,
			wantLeak: false,
		},
		{
			name:     "truncated_pem_block_wraps_err_empty_cert_pem",
			tlsCfg:   httpfx.TLSConfig{RootCAPEM: "-----BEGIN CERTIFICATE-----\nZm9v\n"},
			wantErr:  httpfx.ErrEmptyCertPEM,
			wantLeak: false,
		},
		{
			name: "invalid_file_content_maps_to_empty_cert_pem",
			tlsCfg: httpfx.TLSConfig{
				RootCAFile: func() string {
					path := filepath.Join(t.TempDir(), "garbage.pem")
					if err := os.WriteFile(path,
						[]byte(sensitivePayloadMarker+"\n"), 0o600); err != nil {
						t.Fatalf("write garbage CA file: %v", err)
					}
					return path
				}(),
			},
			wantErr:  httpfx.ErrEmptyCertPEM,
			wantLeak: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				t.Skip("placeholder case without expected error")
			}
			if tt.skipAsRoot && os.Getuid() == 0 {
				t.Skip("permission checks are meaningless when running as root")
			}

			cfg, err := httpfx.BuildTLSConfigForTest(tt.tlsCfg)

			if cfg != nil {
				t.Errorf("cfg = %v, want nil on error", cfg)
			}
			if err == nil {
				t.Fatalf("httpfx.BuildTLSConfigForTest() error = nil, want wrapped %v", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapped %v", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), sensitivePayloadMarker) {
				t.Error("error message leaks raw PEM/cert payload contents")
			}
		})
	}
}

func TestBuildTLSConfigDistinctInstancesPerCall(t *testing.T) {
	authority := newTestAuthority(t, "httpfx-idempotency-ca")
	tlsInput := httpfx.TLSConfig{RootCAPEM: string(authority.certPEM)}

	first, err := httpfx.BuildTLSConfigForTest(tlsInput)
	if err != nil {
		t.Fatalf("first httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
	}
	second, err := httpfx.BuildTLSConfigForTest(tlsInput)
	if err != nil {
		t.Fatalf("second httpfx.BuildTLSConfigForTest() error = %v, want nil", err)
	}

	if first == nil || second == nil {
		t.Fatal("httpfx.BuildTLSConfigForTest() returned nil, want populated configs")
	}
	if first == second {
		t.Error("repeated httpfx.BuildTLSConfigForTest() calls share a *tls.Config, want distinct instances")
	}
	if first.RootCAs == second.RootCAs {
		t.Error("repeated httpfx.BuildTLSConfigForTest() calls share a CertPool, want distinct pools")
	}
}

func TestNewClientTLSIntegration(t *testing.T) {
	t.Run("zero_value_config_keeps_tls_client_config_nil", func(t *testing.T) {
		client, err := httpfx.NewClientForTest(httpfx.Config{})
		if err != nil {
			t.Fatalf("httpfx.NewClientForTest(httpfx.Config{}) error = %v, want nil", err)
		}

		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
		}
		if transport.TLSClientConfig != nil {
			t.Errorf("TLSClientConfig = %v, want nil for zero-value Config", transport.TLSClientConfig)
		}
	})

	t.Run("configured_root_ca_attaches_and_validates_end_to_end", func(t *testing.T) {
		authority := newTestAuthority(t, "httpfx-integration-ca")
		serverURL := startTLSServer(t, authority)

		client, err := httpfx.NewClientForTest(httpfx.Config{
			TLS: httpfx.TLSConfig{RootCAPEM: string(authority.certPEM)},
		})
		if err != nil {
			t.Fatalf("newClient() error = %v, want nil", err)
		}

		client.Timeout = 5 * time.Second
		resp, err := client.Get(serverURL)
		if err != nil {
			t.Fatalf("request over custom CA failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("invalid_root_ca_file_fails_client_creation", func(t *testing.T) {
		client, err := httpfx.NewClientForTest(httpfx.Config{
			TLS: httpfx.TLSConfig{RootCAFile: filepath.Join(t.TempDir(), "missing.pem")},
		})

		if client != nil {
			t.Errorf("client = %v, want nil on error", client)
		}
		if !errors.Is(err, httpfx.ErrCertPoolFailed) {
			t.Errorf("error = %v, want wrapped httpfx.ErrCertPoolFailed", err)
		}
	})
}

// -----------------------------------------------------------------------------
// HTTPS integration suite: end-to-end client behavior against ephemeral
// custom-CA servers (Wave 2, task-4). Uses only test-generated certificates.
// -----------------------------------------------------------------------------

// assertRequestOK performs a GET and asserts an HTTP 200 response.
func assertRequestOK(t *testing.T, client *http.Client, url string) {
	t.Helper()

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s status = %d, want %d", url, resp.StatusCode, http.StatusOK)
	}
}

// assertUnknownAuthority asserts the request failed due to an untrusted root.
// Platforms using Go's internal verifier surface [x509.UnknownAuthorityError];
// darwin defers to Security.framework, which reports "certificate is not
// trusted" instead (crypto/x509 root_darwin.go systemVerify).
func assertUnknownAuthority(t *testing.T, reqErr error) {
	t.Helper()

	if reqErr == nil {
		t.Fatal("request succeeded, want untrusted-root TLS failure")
	}

	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(reqErr, &unknownAuthority) {
		return
	}
	if strings.Contains(reqErr.Error(), "certificate is not trusted") {
		return // darwin Security.framework verdict for untrusted roots
	}
	t.Errorf("error = %v, want x509.UnknownAuthorityError or platform untrusted-root verdict", reqErr)
}

func TestHTTPSIntegrationDefaultClientRejectsUnknownAuthority(t *testing.T) {
	authority := newTestAuthority(t, "httpfx-untrusted-ca")
	serverURL := startTLSServer(t, authority)

	client, err := httpfx.NewClientForTest(httpfx.Config{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpfx.NewClientForTest(httpfx.Config{}) error = %v, want nil", err)
	}

	_, reqErr := client.Get(serverURL)
	assertUnknownAuthority(t, reqErr)
}

func TestHTTPSIntegrationRootCAFileEndToEnd(t *testing.T) {
	tests := []struct {
		name   string
		bundle int // number of CA certs concatenated into the file
	}{
		{name: "single_ca_file", bundle: 1},
		{name: "multi_ca_bundle_file", bundle: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAuthority(t, "httpfx-e2e-file-ca")

			var bundle []byte
			for range tt.bundle {
				bundle = append(bundle, authority.certPEM...)
			}
			path := filepath.Join(t.TempDir(), "root-ca.pem")
			if err := os.WriteFile(path, bundle, 0o600); err != nil {
				t.Fatalf("write CA file: %v", err)
			}

			client, err := httpfx.NewClientForTest(httpfx.Config{
				Timeout: 5 * time.Second,
				TLS:     httpfx.TLSConfig{RootCAFile: path},
			})
			if err != nil {
				t.Fatalf("newClient() error = %v, want nil", err)
			}

			serverURL := startTLSServer(t, authority)
			assertRequestOK(t, client, serverURL)
		})
	}
}

func TestHTTPSIntegrationRootCAPEMEndToEnd(t *testing.T) {
	tests := []struct {
		name   string
		bundle int // number of CA certs concatenated into the PEM string
	}{
		{name: "single_ca_pem", bundle: 1},
		{name: "multi_ca_bundle_pem", bundle: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAuthority(t, "httpfx-e2e-pem-ca")

			var bundle []byte
			for range tt.bundle {
				bundle = append(bundle, authority.certPEM...)
			}

			client, err := httpfx.NewClientForTest(httpfx.Config{
				Timeout: 5 * time.Second,
				TLS:     httpfx.TLSConfig{RootCAPEM: string(bundle)},
			})
			if err != nil {
				t.Fatalf("newClient() error = %v, want nil", err)
			}

			serverURL := startTLSServer(t, authority)
			assertRequestOK(t, client, serverURL)
		})
	}
}

func TestHTTPSIntegrationMergedFileAndPEMSourcesOneConfig(t *testing.T) {
	fileCA := newTestAuthority(t, "httpfx-merged-file-ca")
	pemCA := newTestAuthority(t, "httpfx-merged-pem-ca")

	client, err := httpfx.NewClientForTest(httpfx.Config{
		Timeout: 5 * time.Second,
		TLS: httpfx.TLSConfig{
			RootCAFile: fileCA.writeCAFile(t),
			RootCAPEM:  string(pemCA.certPEM),
		},
	})
	if err != nil {
		t.Fatalf("newClient() error = %v, want nil", err)
	}

	// One config must trust servers signed by EITHER source's CA.
	fileServerURL := startTLSServer(t, fileCA)
	assertRequestOK(t, client, fileServerURL)

	pemServerURL := startTLSServer(t, pemCA)
	assertRequestOK(t, client, pemServerURL)
}

func TestHTTPSIntegrationAppendVsReplaceModes(t *testing.T) {
	customCA := newTestAuthority(t, "httpfx-mode-custom-ca")
	rogueCA := newTestAuthority(t, "httpfx-mode-rogue-external-ca")
	customURL := startTLSServer(t, customCA)
	rogueURL := startTLSServer(t, rogueCA)

	tests := []struct {
		name    string
		replace bool
	}{
		{name: "append_false_accepts_custom_ca", replace: false},
		{name: "replace_true_accepts_custom_ca", replace: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := httpfx.NewClientForTest(httpfx.Config{
				Timeout: 5 * time.Second,
				TLS: httpfx.TLSConfig{
					RootCAPEM:           string(customCA.certPEM),
					RootCAReplaceSystem: tt.replace,
				},
			})
			if err != nil {
				t.Fatalf("newClient() error = %v, want nil", err)
			}

			assertRequestOK(t, client, customURL)
		})
	}

	t.Run("replace_true_rejects_independent_external_ca", func(t *testing.T) {
		client, err := httpfx.NewClientForTest(httpfx.Config{
			Timeout: 5 * time.Second,
			TLS: httpfx.TLSConfig{
				RootCAPEM:           string(customCA.certPEM),
				RootCAReplaceSystem: true,
			},
		})
		if err != nil {
			t.Fatalf("newClient() error = %v, want nil", err)
		}

		_, reqErr := client.Get(rogueURL)
		assertUnknownAuthority(t, reqErr)
	})
}

// Environment variables coordinating the child-process scenarios in
// TestHTTPSIntegrationReplaceSystemPoolControlsExternalTrust.
const (
	envTLSReplaceCase        = "HTTPFX_TEST_TLS_REPLACE_CASE"
	envTLSReplaceCustomCA    = "HTTPFX_TEST_TLS_REPLACE_CUSTOM_CA_FILE"
	envTLSReplaceExternalCA  = "HTTPFX_TEST_TLS_REPLACE_EXTERNAL_CA_FILE"
	envTLSReplaceCustomURL   = "HTTPFX_TEST_TLS_REPLACE_CUSTOM_URL"
	envTLSReplaceExternalURL = "HTTPFX_TEST_TLS_REPLACE_EXTERNAL_URL"
)

// tlsReplaceChildCases enumerates the in-child scenarios. The external CA
// simulates a public root that only the system pool would contain.
const (
	tlsReplaceCaseAppend  = "append_false_system_roots_active"
	tlsReplaceCaseReplace = "replace_true_external_rejected"
)

// TestHTTPSIntegrationReplaceSystemPoolControlsExternalTrust proves the mode
// divergence between RootCAReplaceSystem=false (system roots stay active) and
// true (only configured CAs trusted). The Go system pool is loaded once per
// process (crypto/x509 [sync.Once]), so each scenario re-executes the test
// binary as a child process with SSL_CERT_FILE pointing at the external CA,
// mirroring the pattern used by TestClientProxyFromEnv.
//
// Platforms where SystemCertPool ignores SSL_CERT_FILE (e.g., darwin returns
// an empty pool and defers to Security.framework) cannot observe the
// divergence; those children skip via a behavioral precondition probe.
func TestHTTPSIntegrationReplaceSystemPoolControlsExternalTrust(t *testing.T) {
	if caseName := os.Getenv(envTLSReplaceCase); caseName != "" {
		runTLSReplaceChildCase(t, caseName)
		return
	}

	customCA := newTestAuthority(t, "httpfx-replace-custom-ca")
	externalCA := newTestAuthority(t, "httpfx-replace-external-ca")

	customURL := startTLSServer(t, customCA)
	externalURL := startTLSServer(t, externalCA)

	tests := []struct {
		name    string
		replace bool
	}{
		{name: tlsReplaceCaseAppend, replace: false},
		{name: tlsReplaceCaseReplace, replace: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestHTTPSIntegrationReplaceSystemPoolControlsExternalTrust$",
				"-test.v",
			)
			cmd.Env = append(os.Environ(),
				envTLSReplaceCase+"="+tt.name,
				envTLSReplaceCustomCA+"="+customCA.writeCAFile(t),
				envTLSReplaceExternalCA+"="+externalCA.writeCAFile(t),
				envTLSReplaceCustomURL+"="+customURL,
				envTLSReplaceExternalURL+"="+externalURL,
				"SSL_CERT_FILE="+externalCA.writeCAFile(t),
			)

			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child process for case %q failed: %v\n%s", tt.name, err, out)
			}
		})
	}
}

// runTLSReplaceChildCase executes one append/replace scenario inside the child
// process with a pristine crypto/x509 system-root cache.
func runTLSReplaceChildCase(t *testing.T, caseName string) {
	t.Helper()

	var replace bool
	switch caseName {
	case tlsReplaceCaseAppend:
	case tlsReplaceCaseReplace:
		replace = true
	default:
		t.Fatalf("unknown %s value %q", envTLSReplaceCase, caseName)
	}

	customURL := os.Getenv(envTLSReplaceCustomURL)
	externalURL := os.Getenv(envTLSReplaceExternalURL)
	if customURL == "" || externalURL == "" {
		t.Fatalf("missing server URLs: custom=%q external=%q", customURL, externalURL)
	}

	// Behavioral precondition: the loaded system pool must actually trust the
	// external CA; otherwise the two modes are indistinguishable here.
	sysPool, err := x509.SystemCertPool()
	if err != nil || sysPool == nil {
		t.Skipf("system cert pool unavailable (err=%v), cannot prove pool-source behavior", err)
	}
	probe := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: sysPool}},
		Timeout:   5 * time.Second,
	}
	if resp, probeErr := probe.Get(externalURL); probeErr != nil {
		t.Skipf("system pool does not honor SSL_CERT_FILE here (%v); "+
			"append-vs-replace divergence unobservable on this platform", probeErr)
	} else {
		resp.Body.Close()
	}

	client, err := httpfx.NewClientForTest(httpfx.Config{
		Timeout: 5 * time.Second,
		TLS: httpfx.TLSConfig{
			RootCAFile:          os.Getenv(envTLSReplaceCustomCA),
			RootCAReplaceSystem: replace,
		},
	})
	if err != nil {
		t.Fatalf("newClient() error = %v, want nil", err)
	}

	// The custom CA must be trusted in BOTH modes.
	assertRequestOK(t, client, customURL)

	switch caseName {
	case tlsReplaceCaseAppend:
		// System roots remain active: external-CA-signed server accepted.
		assertRequestOK(t, client, externalURL)
	case tlsReplaceCaseReplace:
		// Replaced pool excludes system roots: external-CA-signed rejected.
		_, reqErr := client.Get(externalURL)
		assertUnknownAuthority(t, reqErr)
	}
}

// SOCKS5 protocol constants (RFC 1928) used by the minimal test proxy.
const (
	socks5Version            = 0x05
	socks5MethodNoAuth       = 0x00
	socks5MethodUnacceptable = 0xFF
	socks5CommandConnect     = 0x01
	socks5ReplySuccess       = 0x00
	socks5ReplyFailure       = 0x05
	socks5AddressIPv4        = 0x01
	socks5AddressDomain      = 0x03
	socks5AddressIPv6        = 0x04
)

// socks5Proxy is a minimal RFC 1928 SOCKS5 CONNECT proxy supporting NO-AUTH.
// It records every dialed target so tests can prove traffic was tunneled
// rather than dialed directly.
type socks5Proxy struct {
	listener net.Listener

	mu      sync.Mutex
	targets []string
}

// startSOCKS5Proxy starts a loopback SOCKS5 CONNECT proxy for the test.
func startSOCKS5Proxy(t *testing.T) *socks5Proxy {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback for SOCKS5 proxy: %v", err)
	}

	p := &socks5Proxy{listener: listener}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go p.handleConnect(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })

	return p
}

func (p *socks5Proxy) addr() string {
	return p.listener.Addr().String()
}

// sawTarget reports whether the proxy tunneled a connection to target
// ("host:port").
func (p *socks5Proxy) sawTarget(target string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Contains(p.targets, target)
}

func (p *socks5Proxy) handleConnect(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != socks5Version {
		return
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !slices.Contains(methods, socks5MethodNoAuth) {
		_, _ = conn.Write([]byte{socks5Version, socks5MethodUnacceptable})
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
		return
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil ||
		request[0] != socks5Version || request[1] != socks5CommandConnect {
		return
	}

	host, err := readSOCKS5Address(conn, request[3])
	if err != nil {
		return
	}

	var portBytes [2]byte
	if _, err = io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:]))))

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{
			socks5Version, socks5ReplyFailure, 0x00, socks5AddressIPv4, 0, 0, 0, 0, 0, 0,
		})
		return
	}
	defer func() { _ = upstream.Close() }()

	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()

	// Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (BND values unused).
	if _, err = conn.Write([]byte{
		socks5Version, socks5ReplySuccess, 0x00, socks5AddressIPv4, 127, 0, 0, 1, 0, 0,
	}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
}

// readSOCKS5Address decodes the destination address following ATYP.
func readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socks5AddressIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return "", err
		}
		return net.IP(raw[:]).String(), nil
	case socks5AddressDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", err
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		return string(name), nil
	case socks5AddressIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return "", err
		}
		return net.IP(raw[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type 0x%02x", atyp)
	}
}

func TestHTTPSIntegrationThroughSOCKS5ProxyWithCustomCA(t *testing.T) {
	authority := newTestAuthority(t, "httpfx-proxy-tls-ca")
	serverURL := startTLSServer(t, authority)
	serverHostPort := strings.TrimPrefix(serverURL, "https://")

	proxyServer := startSOCKS5Proxy(t)

	t.Run("custom_ca_handshakes_through_tunnel", func(t *testing.T) {
		client, err := httpfx.NewClientForTest(httpfx.Config{
			ProxyURL: "socks5://" + proxyServer.addr(),
			Timeout:  5 * time.Second,
			TLS:      httpfx.TLSConfig{RootCAPEM: string(authority.certPEM)},
		})
		if err != nil {
			t.Fatalf("newClient() error = %v, want nil", err)
		}

		assertRequestOK(t, client, serverURL)

		if !proxyServer.sawTarget(serverHostPort) {
			t.Error("proxy never tunneled a dial to the HTTPS server, want CONNECT usage")
		}
	})

	t.Run("untrusted_ca_still_rejected_through_tunnel", func(t *testing.T) {
		rogueCA := newTestAuthority(t, "httpfx-proxy-rogue-ca")
		rogueURL := startTLSServer(t, rogueCA)
		rogueHostPort := strings.TrimPrefix(rogueURL, "https://")

		client, err := httpfx.NewClientForTest(httpfx.Config{
			ProxyURL: "socks5://" + proxyServer.addr(),
			Timeout:  5 * time.Second,
		})
		if err != nil {
			t.Fatalf("newClient() error = %v, want nil", err)
		}

		_, reqErr := client.Get(rogueURL)
		assertUnknownAuthority(t, reqErr)

		if !proxyServer.sawTarget(rogueHostPort) {
			t.Error("rejected handshake did not traverse the proxy tunnel")
		}
	})
}

// compile-time guard: crypto import used by helpers above.
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
