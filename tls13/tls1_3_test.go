// Add test of tls1_3.go

package tls13

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	// TLS 1.3の設定
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13, // TLS 1.3を最小バージョンとして指定
		PreferServerCipherSuites: true,             // サーバー側の暗号スイートを優先
		// 必要に応じて他の設定を追加
	}

	server := httptest.NewUnstartedServer(mux)
	server.TLS = tlsConfig
	server.StartTLS()

}
