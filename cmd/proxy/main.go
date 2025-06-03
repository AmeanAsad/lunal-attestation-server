package main

import (
	"crypto/tls"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"lunal-tee-attestation/pkg/attestation" // Update this with your actual module path
)

const (
	HTTPPort      = ":80"
	HTTPSPort     = ":443"
	TargetServer  = "http://127.0.0.1:8082"
	TPMDevicePath = "/dev/tpm0"
)

var (
	cachedAttestation     []byte
	cachedAttestationB64  string
	lastAttestationTime   time.Time
	attestationTTLMinutes = 60
)

func main() {
	generateAttestation()

	// Parse target URL once
	target, err := url.Parse(TargetServer)
	if err != nil {
		log.Fatal("Invalid target server:", err)
	}

	// Create reverse proxy with better defaults
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom director to add attestation headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		refreshAttestationIfNeeded(req)

		// Better proxy headers
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
		HostPolicy: autocert.HostWhitelist("miden.lunal.dev", "35.239.17.184"),
	}

	// Add logging for certificate events
	log.Println("Autocert manager configured for: miden.lunal.dev")

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
	log.Println("Auto-certificates enabled for: miden.lunal.dev")
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
	// Create attestation with default options
	opts := attestation.DefaultAttestOptions()
	opts.Nonce = []byte("fixed-deterministic-nonce-for-server")

	attestBytes, err := attestation.Attest(opts)
	if err != nil {
		log.Printf("WARNING: Failed to generate attestation: %v", err)
		cachedAttestationB64 = base64.StdEncoding.EncodeToString([]byte("attestation-generation-failed"))
		return
	}

	// Cache the attestation and its base64 representation
	cachedAttestation = attestBytes
	cachedAttestationB64 = base64.StdEncoding.EncodeToString(attestBytes)
	lastAttestationTime = time.Now()

	log.Printf("Successfully generated attestation (%d bytes)", len(attestBytes))
}

func refreshAttestationIfNeeded(r *http.Request) {
	log.Printf("[TASK] Processing request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("[TASK] User-Agent: %s", r.Header.Get("User-Agent"))
	log.Printf("[TASK] Remote Address: %s", r.RemoteAddr)
	log.Println("[TASK] Attestation is included in response header")
	generateAttestation()
}
