package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIPTrustedProxy(t *testing.T) {
	middleware := RealIP(RealIPConfig{
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	})

	var capturedRemoteAddr string
	handler := middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedRemoteAddr = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.10.10.10:12345"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if capturedRemoteAddr != "203.0.113.10" {
		t.Fatalf("unexpected remote address from trusted proxy: %q", capturedRemoteAddr)
	}
}

func TestRealIPUntrustedProxy(t *testing.T) {
	middleware := RealIP(RealIPConfig{
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	})

	var capturedRemoteAddr string
	handler := middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedRemoteAddr = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("CF-Connecting-IP", "198.51.100.20")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if capturedRemoteAddr != "203.0.113.5:54321" {
		t.Fatalf("unexpected remote address from untrusted proxy: %q", capturedRemoteAddr)
	}
}
