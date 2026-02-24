package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	originutil "github.com/katsutoo/kickoutchi/api/internal/origin"
)

type CSRFConfig struct {
	AllowedOrigins []string
}

func CSRFOriginCheck(cfg CSRFConfig) func(http.Handler) http.Handler {
	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		normalized, err := originutil.Normalize(origin)
		if err != nil {
			continue
		}

		allowedOrigins[normalized] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				origin = originFromReferer(r.Header.Get("Referer"))
			}

			normalizedOrigin, err := originutil.Normalize(origin)
			if err != nil {
				writeCSRFFailure(w)
				return
			}

			if _, ok := allowedOrigins[normalizedOrigin]; ok {
				next.ServeHTTP(w, r)
				return
			}

			requestOrigin := requestOrigin(r)
			if requestOrigin != "" && requestOrigin == normalizedOrigin {
				next.ServeHTTP(w, r)
				return
			}

			writeCSRFFailure(w)
		})
	}
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func originFromReferer(rawReferer string) string {
	if strings.TrimSpace(rawReferer) == "" {
		return ""
	}

	parsed, err := url.Parse(rawReferer)
	if err != nil {
		return ""
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}

	return parsed.Scheme + "://" + parsed.Host
}

func requestOrigin(r *http.Request) string {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		return ""
	}

	return scheme + "://" + host
}

func writeCSRFFailure(w http.ResponseWriter) {
	apierror.WriteError(w, apierror.New(
		http.StatusForbidden,
		"CSRF_ORIGIN_INVALID",
		"origin validation failed",
		nil,
	))
}
