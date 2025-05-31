package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	// Port for the target server
	TargetPort = ":8082"
)

type Response struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRequest)

	// Create HTTP/2 server that works without TLS (h2c - HTTP/2 cleartext)
	h2s := &http2.Server{}

	server := &http.Server{
		Addr:    TargetPort,
		Handler: h2c.NewHandler(mux, h2s),
	}

	fmt.Printf("Target server starting on port %s with HTTP/2 support\n", TargetPort)
	log.Fatal(server.ListenAndServe())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	fmt.Printf("Target server received: %s %s\n", r.Method, r.URL.Path)

	// Create response data
	response := Response{
		Message:   "Hello from the target server!",
		Timestamp: time.Now(),
		Path:      r.URL.Path,
		Method:    r.Method,
	}

	// Add headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write JSON response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
