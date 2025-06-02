package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"lunal-tee-attestation/pkg/attestation" // Update this with your actual module path
)

const (
	// Port for the proxy server
	ProxyPort = ":9080"
	// Target server URL (local server on same machine)
	TargetServer = "http://127.0.0.1:8082"
	// TPM device path
	TPMDevicePath = "/dev/tpm0" // Adjust if your TPM device path is different
)

var (
	// Store the attestation data to avoid regenerating it for every request
	cachedAttestation     []byte
	cachedAttestationB64  string
	lastAttestationTime   time.Time
	attestationTTLMinutes = 60 // Refresh attestation every 5 minutes
)

func main() {
	// Generate initial attestation on startup
	// generateAttestation()

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler)

	fmt.Printf("Proxy server starting on port %s with HTTP/2 support\n", ProxyPort)
	fmt.Printf("Forwarding all requests to %s\n", TargetServer)

	h2s := &http2.Server{}

	server := &http.Server{
		Addr:    ProxyPort,
		Handler: h2c.NewHandler(mux, h2s),
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
	// Check if attestation is stale
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
	// refreshAttestationIfNeeded(r)

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

	// Copy all headers from original request
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Set/override some headers
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("X-Forwarded-Proto", "http")
	if r.Header.Get("X-Real-IP") == "" {
		proxyReq.Header.Set("X-Real-IP", r.RemoteAddr)
	}

	// Create HTTP client with HTTP/2 support
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			// Dial function for HTTP/2 over TCP
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	// Send the request to target server
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Modify response headers before sending back
	modifyResponseHeaders(w, resp)

	// Copy the response body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func modifyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	// Copy original response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.Header().Set("Attestation-Report", cachedAttestationB64)
}
