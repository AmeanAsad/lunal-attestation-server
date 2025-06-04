package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"lunal-tee-attestation/pkg/attestation" // Replace with your actual module path

	"golang.org/x/crypto/acme/autocert"
)

// Configuration constants
const (
	TargetServer = "http://localhost:3000" // Your backend server
	HTTPPort     = ":80"
	HTTPSPort    = ":443"
)

var (
	cachedAttestationB64  string
	cachedAttestationGzip []byte
	lastAttestationTime   time.Time
)

func generateAttestation() {
	opts := attestation.DefaultAttestOptions()
	opts.Nonce = []byte("fixed-deterministic-nonce-for-server")

	// data, err := attestation.Attest(opts)
	// if err != nil {
	// 	log.Fatalf("Failed to generate attestation: %v", err)
	// }

	// Cache the base64 encoded version

	// Get and cache the gzipped JSON version as raw bytes
	cachedAttestationGzip, err := attestation.GetAttestationGzipJSON(opts)
	cachedAttestationB64 = base64.StdEncoding.EncodeToString(cachedAttestationGzip)

	if err != nil {
		log.Fatalf("Failed to generate JSON gzip attestation: %v", err)
	}

	lastAttestationTime = time.Now()
}

func main() {
	generateAttestation()
	log.Println("Attestation generated successfully")

	// Parse target URL once
	target, err := url.Parse(TargetServer)
	if err != nil {
		log.Fatal("Invalid target server:", err)
	}
	log.Printf("Configured proxy to target: %s", TargetServer)

	// Create reverse proxy with better defaults
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom director to add attestation headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		log.Printf("Incoming request: %s %s from %s", req.Method, req.URL.Path, getClientIP(req))
		originalDirector(req)

		// Better proxy headers
		req.Header.Set("X-Forwarded-Proto", getScheme(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", getClientIP(req))
		log.Printf("Forwarding request to backend: %s %s", req.Method, req.URL.String())
	}

	// Add attestation to response
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Attestation-Report", cachedAttestationB64)

		// Read and log the response body for debugging
		if resp.Body != nil {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error reading response body: %v", err)
			} else {
				// Print the response body content
				log.Printf("Response body: %s", string(bodyBytes))

				// Create a new reader with the same content for the downstream response
				resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		log.Printf("Response from backend: %d %s for %s %s",
			resp.StatusCode, resp.Status, resp.Request.Method, resp.Request.URL.Path)
		return nil
	}

	// Add error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v for %s %s from %s",
			err, r.Method, r.URL.Path, getClientIP(r))
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Proxy Error: " + err.Error()))
	}

	// Auto HTTPS with Let's Encrypt
	m := &autocert.Manager{
		Cache:      autocert.DirCache("certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("nexus-mcp.lunal.dev"),
	}

	// Add logging for certificate events
	log.Println("Autocert manager configured for: nexus-mcp.lunal.dev")

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
	log.Println("Auto-certificates enabled for: nexus-mcp.lunal.dev")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// getScheme returns the scheme (http or https) of the request
func getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// getClientIP extracts the client's real IP address
func getClientIP(req *http.Request) string {
	// Try standard headers first
	for _, header := range []string{"X-Real-IP", "X-Forwarded-For"} {
		if ip := req.Header.Get(header); ip != "" {
			return ip
		}
	}
	// Fall back to RemoteAddr
	return req.RemoteAddr
}
