package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/service"
)

type SessionCookieConfig struct {
	Name     string
	Domain   string
	Secure   bool
	SameSite string
	TTL      time.Duration
}

type sessionAuthenticator interface {
	AuthenticateSession(ctx context.Context, sessionToken string) (service.AuthenticatedSession, error)
}

type authUserContextKey struct{}

func RequireAuth(authenticator sessionAuthenticator, cookie SessionCookieConfig) func(http.Handler) http.Handler {
	if cookie.Name == "" {
		cookie.Name = "kickoutchi_session"
	}

	if cookie.TTL <= 0 {
		cookie.TTL = 30 * 24 * time.Hour
	}

	return func(next http.Handler) http.Handler {
		if next == nil {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionCookie, err := r.Cookie(cookie.Name)
			if err != nil {
				if errors.Is(err, http.ErrNoCookie) {
					writeUnauthorized(w)
					return
				}

				apierror.WriteError(w, apierror.New(
					http.StatusBadRequest,
					"INVALID_REQUEST",
					"invalid session cookie",
					err,
				))
				return
			}

			authSession, err := authenticator.AuthenticateSession(r.Context(), sessionCookie.Value)
			if err != nil {
				switch {
				case errors.Is(err, service.ErrInvalidSession):
					clearSessionCookie(w, cookie)
					writeUnauthorized(w)
				default:
					apierror.WriteError(w, apierror.New(
						http.StatusInternalServerError,
						"INTERNAL_ERROR",
						"internal server error",
						err,
					))
				}
				return
			}

			if authSession.Refreshed {
				setSessionCookie(w, cookie, sessionCookie.Value, authSession.ExpiresAt)
			}

			ctx := context.WithValue(r.Context(), authUserContextKey{}, authSession.User)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AuthUserFromContext(ctx context.Context) (service.UserView, bool) {
	user, ok := ctx.Value(authUserContextKey{}).(service.UserView)
	if !ok {
		return service.UserView{}, false
	}

	return user, true
}

func setSessionCookie(w http.ResponseWriter, cfg SessionCookieConfig, token string, expiresAt time.Time) {
	maxAge := int(cfg.TTL.Seconds())
	if maxAge <= 0 {
		maxAge = int(time.Until(expiresAt).Seconds())
	}

	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    token,
		Path:     "/",
		Domain:   cfg.Domain,
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
	})
}

func clearSessionCookie(w http.ResponseWriter, cfg SessionCookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     "/",
		Domain:   cfg.Domain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
	})
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	apierror.WriteError(w, apierror.New(
		http.StatusUnauthorized,
		"UNAUTHORIZED",
		"authentication required",
		nil,
	))
}
