package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
)

const maxRateLimitBodyReadBytes = 1 << 20

type KeyRateLimiter struct {
	mu              sync.Mutex
	entries         map[string]*rateLimiterEntry
	limit           rate.Limit
	burst           int
	entryTTL        time.Duration
	compactInterval time.Duration
	nextCompactAt   time.Time
	now             func() time.Time
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewKeyRateLimiter(requests int, window time.Duration, burst int) *KeyRateLimiter {
	if requests <= 0 {
		requests = 1
	}

	if window <= 0 {
		window = time.Second
	}

	if burst <= 0 {
		burst = 1
	}

	limit := rate.Every(window / time.Duration(requests))

	return &KeyRateLimiter{
		entries:         make(map[string]*rateLimiterEntry),
		limit:           limit,
		burst:           burst,
		entryTTL:        30 * time.Minute,
		compactInterval: 5 * time.Minute,
		now:             time.Now,
	}
}

func (l *KeyRateLimiter) Allow(key string) (bool, time.Duration) {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		trimmedKey = "unknown"
	}

	now := l.now().UTC()

	l.mu.Lock()
	if l.nextCompactAt.IsZero() {
		l.nextCompactAt = now.Add(l.compactInterval)
	}

	if !now.Before(l.nextCompactAt) {
		l.compact(now)
		l.nextCompactAt = now.Add(l.compactInterval)
	}

	entry, ok := l.entries[trimmedKey]
	if !ok {
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[trimmedKey] = entry
	}
	entry.lastSeen = now

	limiter := entry.limiter
	l.mu.Unlock()

	if limiter.Allow() {
		return true, 0
	}

	reservation := limiter.Reserve()
	if !reservation.OK() {
		return false, time.Second
	}

	retryAfter := reservation.Delay()
	reservation.Cancel()

	if retryAfter < 0 {
		retryAfter = 0
	}

	return false, retryAfter
}

func (l *KeyRateLimiter) compact(now time.Time) {
	cutoff := now.Add(-l.entryTTL)
	for key, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

func RateLimitByIP(limiter *KeyRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := requestClientIP(r)
			if allowed, retryAfter := limiter.Allow(clientIP); !allowed {
				writeRateLimited(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RateLimitByJSONField(limiter *KeyRateLimiter, field string) func(http.Handler) http.Handler {
	trimmedField := strings.TrimSpace(field)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := requestClientIP(r)

			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxRateLimitBodyReadBytes))
			if err == nil {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				if trimmedField != "" {
					var payload map[string]any
					if decodeErr := json.Unmarshal(bodyBytes, &payload); decodeErr == nil {
						if rawValue, exists := payload[trimmedField]; exists {
							if value, ok := rawValue.(string); ok {
								normalized := strings.ToLower(strings.TrimSpace(value))
								if normalized != "" {
									key = normalized
								}
							}
						}
					}
				}
			} else {
				r.Body = io.NopCloser(bytes.NewReader(nil))
			}

			if allowed, retryAfter := limiter.Allow(key); !allowed {
				writeRateLimited(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RateLimitByAuthenticatedUser(limiter *KeyRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := requestClientIP(r)

			if authUser, ok := AuthUserFromContext(r.Context()); ok {
				key = authUser.ID.String()
			}

			if allowed, retryAfter := limiter.Allow(key); !allowed {
				writeRateLimited(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	w.Header().Set("Retry-After", strconv.Itoa(seconds))

	apierror.WriteError(w, &apierror.Error{
		Status:  http.StatusTooManyRequests,
		Code:    "RATE_LIMITED",
		Message: "too many requests",
		Details: map[string]any{
			"retry_after_seconds": seconds,
		},
	})
}

func requestClientIP(r *http.Request) string {
	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}

	if remoteAddr == "" {
		return "unknown"
	}

	return remoteAddr
}
