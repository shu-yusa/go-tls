package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/shu-yusa/go-tls/tls13"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, TLS 1.3!")
}

func fullTLSServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	// TLS 1.3
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}

	server := &http.Server{
		Addr:      ":https",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
}

func main() {
	tls13.Server()
	// fullTLSServer()
}
