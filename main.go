package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, TLS 1.3!")
}

func fullTLSServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	// TLS 1.3の設定
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13, // TLS 1.3を最小バージョンとして指定
		PreferServerCipherSuites: true,             // サーバー側の暗号スイートを優先
		// 必要に応じて他の設定を追加
	}

	server := &http.Server{
		Addr:      ":https",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// TLS証明書と秘密鍵のパスを指定してサーバーを開始
	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
}

func main() {
	// tls13.Server()
	fullTLSServer()
}
