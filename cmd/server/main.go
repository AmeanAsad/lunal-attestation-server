package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	// Port for the proxy server
	ProxyPort = ":9080"
	// Target server URL (local server on same machine)
	TargetServer = "http://127.0.0.1:8082"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler)

	fmt.Printf("Proxy server starting on port %s with HTTP/2 support\n", ProxyPort)
	fmt.Printf("Forwarding all requests to %s\n", TargetServer)

	// Create HTTP/2 server that works without TLS (h2c - HTTP/2 cleartext)
	h2s := &http2.Server{}

	server := &http.Server{
		Addr:    ProxyPort,
		Handler: h2c.NewHandler(mux, h2s),
	}

	log.Fatal(server.ListenAndServe())
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Perform your custom task here
	performCustomTask(r)

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
			// Allow HTTP/2 without TLS
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

	// Add custom attestation header
	w.Header().Set("Attestation-Report", "verified-proxy-attestation-12345")
}

func performCustomTask(r *http.Request) {
	// Placeholder for your custom task
	fmt.Printf("[TASK] Processing request: %s %s\n", r.Method, r.URL.Path)
	fmt.Printf("[TASK] User-Agent: %s\n", r.Header.Get("User-Agent"))
	fmt.Printf("[TASK] Remote Address: %s\n", r.RemoteAddr)
	fmt.Println("[TASK] Custom task completed!")

	// Add your actual task logic here:
	// - Database operations
	// - Logging
	// - Authentication
	// - Rate limiting
	// - Analytics
	// - etc.
}
