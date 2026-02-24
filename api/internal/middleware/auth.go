package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/service"
	"github.com/katsutoo/kickoutchi/api/internal/sessioncookie"
)

type SessionCookieConfig = sessioncookie.Config

type sessionAuthenticator interface {
	AuthenticateSession(ctx context.Context, sessionToken string) (service.AuthenticatedSession, error)
}

type authUserContextKey struct{}

func RequireAuth(authenticator sessionAuthenticator, cookie SessionCookieConfig) func(http.Handler) http.Handler {
	cookie = sessioncookie.NormalizeConfig(cookie)

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
					sessioncookie.Clear(w, cookie)
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
				sessioncookie.Set(w, cookie, sessionCookie.Value, authSession.ExpiresAt)
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

func writeUnauthorized(w http.ResponseWriter) {
	apierror.WriteError(w, apierror.New(
		http.StatusUnauthorized,
		"UNAUTHORIZED",
		"authentication required",
		nil,
	))
}
