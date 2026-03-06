package middleware

import (
	"net"
	"net/http"
	"strings"
)

type RealIPConfig struct {
	TrustedProxyCIDRs []string
}

func RealIP(cfg RealIPConfig) func(http.Handler) http.Handler {
	trustedProxyNets := make([]*net.IPNet, 0, len(cfg.TrustedProxyCIDRs))
	for _, rawCIDR := range cfg.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err != nil {
			continue
		}

		trustedProxyNets = append(trustedProxyNets, network)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trustedProxyNets) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			remoteIP := requestIP(r.RemoteAddr)
			if remoteIP == nil || !isTrustedProxy(remoteIP, trustedProxyNets) {
				next.ServeHTTP(w, r)
				return
			}

			forwardedIP := forwardedClientIP(r)
			if forwardedIP == nil {
				next.ServeHTTP(w, r)
				return
			}

			clonedRequest := r.Clone(r.Context())
			clonedRequest.RemoteAddr = forwardedIP.String()
			next.ServeHTTP(w, clonedRequest)
		})
	}
}

func forwardedClientIP(r *http.Request) net.IP {
	for _, headerValue := range []string{
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("True-Client-IP"),
	} {
		if ip := requestIP(headerValue); ip != nil {
			return ip
		}
	}

	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := requestIP(part); ip != nil {
			return ip
		}
	}

	return requestIP(r.Header.Get("X-Real-IP"))
}

func isTrustedProxy(ip net.IP, trustedProxyNets []*net.IPNet) bool {
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func requestIP(raw string) net.IP {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}

	return net.ParseIP(trimmed)
}
