package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"lunal-tee-attestation/pkg/attestation" // Update this with your actual module path
)

const (
	// Port for the proxy server
	ProxyPort = ":9080"
	// Target server URL (local server on same machine)
	TargetServer = "http://127.0.0.1:8082" // Fixed: using your Miden proxy port
	// TPM device path
	TPMDevicePath = "/dev/tpm0" // Adjust if your TPM device path is different
)

var (
	// Store the attestation data to avoid regenerating it for every request
	cachedAttestation     []byte
	cachedAttestationB64  string
	lastAttestationTime   time.Time
	attestationTTLMinutes = 60 // Refresh attestation every 60 minutes
)

func main() {
	// Generate initial attestation on startup
	generateAttestation()

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler)

	fmt.Printf("Proxy server starting on port %s with HTTP/2 support\n", ProxyPort)
	fmt.Printf("Forwarding all requests to %s\n", TargetServer)

	h2s := &http2.Server{
		MaxConcurrentStreams: 100,
		MaxReadFrameSize:     1048576, // 1MB
		IdleTimeout:          60 * time.Second,
	}

	server := &http.Server{
		Addr:         ProxyPort,
		Handler:      h2c.NewHandler(mux, h2s),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
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
	// Check if attestation is stale (currently commented out the time check)
	// if time.Since(lastAttestationTime).Minutes() > float64(attestationTTLMinutes) {
	log.Println("Refreshing attestation...")
	fmt.Printf("[TASK] Processing request: %s %s\n", r.Method, r.URL.Path)
	fmt.Printf("[TASK] User-Agent: %s\n", r.Header.Get("User-Agent"))
	fmt.Printf("[TASK] Remote Address: %s\n", r.RemoteAddr)
	fmt.Println("[TASK] Attestation is included in response header")
	generateAttestation()
	// }
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Refresh attestation if needed
	refreshAttestationIfNeeded(r)

	// Create the target URL (keep the same path)
	targetURL, err := url.Parse(TargetServer)
	if err != nil {
		http.Error(w, "Invalid target server", http.StatusInternalServerError)
		return
	}

	targetURL.Path = r.URL.Path
	targetURL.RawQuery = r.URL.RawQuery

	// Create a new request to forward to the target server
	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
		return
	}

	// Copy all headers from original request (critical for gRPC)
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Ensure critical gRPC headers are preserved
	proxyReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	if te := r.Header.Get("TE"); te != "" {
		proxyReq.Header.Set("TE", te)
	}

	// Set/override some headers (but preserve gRPC headers)
	if !strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
		proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
		proxyReq.Header.Set("X-Forwarded-Proto", getScheme(r))
		if r.Header.Get("X-Real-IP") == "" {
			proxyReq.Header.Set("X-Real-IP", getClientIP(r))
		}
	}

	// Create HTTP client - FIXED VERSION
	client := createHTTPClient()

	// Send the request to target server
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("Error forwarding request to %s: %v", targetURL.String(), err)
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Modify response headers before sending back
	modifyResponseHeaders(w, resp)

	// Copy the response body
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}

func createHTTPClient() *http.Client {
	// Use HTTP/1.1 to avoid double HTTP/2 wrapping
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	return &http.Client{
		Timeout:   300 * time.Second, // Longer timeout for proving operations
		Transport: transport,
	}
}

func modifyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	// Copy original response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Add attestation header
	w.Header().Set("Attestation-Report", cachedAttestationB64)

	// Add some debugging headers
	w.Header().Set("X-Proxy-Version", "1.0")
	w.Header().Set("X-Proxy-Protocol", resp.Proto)
}

// Helper function to get client IP
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Helper function to get scheme
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}
