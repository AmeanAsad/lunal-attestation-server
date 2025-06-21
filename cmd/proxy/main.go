package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	HTTPPort      = ":80"
	HTTPSPort     = ":443"
	TPMDevicePath = "/dev/tpm0"
)

var (
	cachedAttestation     []byte
	cachedAttestationB64  string
	lastAttestationTime   time.Time
	attestationTTLMinutes = 60
	hostParam             = flag.String("host", "", "Host domain for TLS certificate (required)")
	upstreamParam         = flag.String("upstream", "", "Upstream server URL (required)")
	platformParam         = flag.String("platform", "", "Attestation platform: sev-snp or tdx (required)")
	attestBinaryPath      string
)

func init() {
	// Get the directory where the current executable is located
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)

	// attestBinaryPath will be set based on platform parameter
	log.Printf("Executable directory: %s", execDir)
}

func main() {
	flag.Parse()

	// Validate required parameters
	if *hostParam == "" {
		log.Fatal("--host parameter is required")
	}
	if *upstreamParam == "" {
		log.Fatal("--upstream parameter is required")
	}
	if *platformParam == "" {
		log.Fatal("--platform parameter is required (sev-snp or tdx)")
	}

	// Set attestBinaryPath based on platform
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)

	switch *platformParam {
	case "sev-snp":
		attestBinaryPath = filepath.Join(execDir, "attest-sev-snp")
	case "tdx":
		attestBinaryPath = filepath.Join(execDir, "attest-tdx")
	default:
		log.Fatalf("Invalid platform: %s. Must be 'sev-snp' or 'tdx'", *platformParam)
	}

	log.Printf("Starting proxy with host: %s, upstream: %s", *hostParam, *upstreamParam)

	generateAttestation()

	target, err := url.Parse(*upstreamParam)
	if err != nil {
		log.Fatal("Invalid upstream server:", err)
	}

	// Create reverse proxy with defaults
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom director to add attestation headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		refreshAttestationIfNeeded(req)

		req.Header.Set("X-Forwarded-Proto", getScheme(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", getClientIP(req))
	}

	// Add attestation to response
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Attestation-Report", cachedAttestationB64)
		return nil
	}

	// Auto HTTPS with Let's Encrypt
	m := &autocert.Manager{
		Cache:      autocert.DirCache("certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*hostParam),
	}

	// Add logging for certificate events
	log.Printf("Autocert manager configured for: %s", *hostParam)

	server := &http.Server{
		Addr:    HTTPSPort,
		Handler: proxy,
		TLSConfig: &tls.Config{
			GetCertificate: m.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"}, // Explicit HTTP/2 support for gRPC
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Redirect HTTP to HTTPS
	go func() {
		log.Println("Starting HTTP->HTTPS redirect on", HTTPPort)
		log.Fatal(http.ListenAndServe(HTTPPort, m.HTTPHandler(nil)))
	}()

	log.Println("Starting HTTPS server on", HTTPSPort)
	log.Printf("Auto-certificates enabled for: %s", *hostParam)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return req.RemoteAddr
}

func generateAttestation() {
	// Execute the attest command from the same directory as this executable
	cmd := exec.Command(attestBinaryPath, "--format", "compressed")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to execute attest command at %s: %v", attestBinaryPath, err)
	}

	// The output is already base64 encoded, just clean it up
	cachedAttestationB64 = strings.TrimSpace(string(output))

	// Print the attestation for debugging
	log.Printf("Generated attestation: %s...",
		cachedAttestationB64)

	lastAttestationTime = time.Now()
}

func refreshAttestationIfNeeded(r *http.Request) {
	log.Printf("[TASK] Processing request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("[TASK] User-Agent: %s", r.Header.Get("User-Agent"))
	log.Printf("[TASK] Remote Address: %s", r.RemoteAddr)
	log.Println("[TASK] Attestation is included in response header")
	generateAttestation()
}
