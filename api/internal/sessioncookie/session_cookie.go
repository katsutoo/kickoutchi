package sessioncookie

import (
	"net/http"
	"strings"
	"time"
)

const (
	defaultName = "kickoutchi_session"
	defaultTTL  = 30 * 24 * time.Hour
)

type Config struct {
	Name     string
	Domain   string
	Secure   bool
	SameSite string
	TTL      time.Duration
}

func NormalizeConfig(cfg Config) Config {
	if cfg.Name == "" {
		cfg.Name = defaultName
	}

	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}

	return cfg
}

func Set(w http.ResponseWriter, cfg Config, token string, expiresAt time.Time) {
	normalized := NormalizeConfig(cfg)

	maxAge := int(normalized.TTL.Seconds())
	if maxAge <= 0 {
		maxAge = int(time.Until(expiresAt).Seconds())
	}

	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     normalized.Name,
		Value:    token,
		Path:     "/",
		Domain:   normalized.Domain,
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   normalized.Secure,
		SameSite: ParseSameSite(normalized.SameSite),
	})
}

func Clear(w http.ResponseWriter, cfg Config) {
	normalized := NormalizeConfig(cfg)

	http.SetCookie(w, &http.Cookie{
		Name:     normalized.Name,
		Value:    "",
		Path:     "/",
		Domain:   normalized.Domain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   normalized.Secure,
		SameSite: ParseSameSite(normalized.SameSite),
	})
}

func ParseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
