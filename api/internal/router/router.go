package router

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/handler"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
)

type Dependencies struct {
	Logger                *slog.Logger
	HealthHandler         *handler.HealthHandler
	AuthHandler           *handler.AuthHandler
	RealIP                func(http.Handler) http.Handler
	AuthRequired          func(http.Handler) http.Handler
	CSRFProtection        func(http.Handler) http.Handler
	AuthIPRateLimit       func(http.Handler) http.Handler
	AuthAccountRateLimit  func(http.Handler) http.Handler
	ResendVerifyRateLimit func(http.Handler) http.Handler
}

func New(deps Dependencies) http.Handler {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	authIPRateLimit := ensureMiddleware(deps.AuthIPRateLimit)
	authAccountRateLimit := ensureMiddleware(deps.AuthAccountRateLimit)
	resendVerifyRateLimit := ensureMiddleware(deps.ResendVerifyRateLimit)
	csrfProtection := ensureMiddleware(deps.CSRFProtection)
	realIP := ensureMiddleware(deps.RealIP)

	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(realIP)
	r.Use(appmiddleware.Logging(logger))
	r.Use(appmiddleware.Recovery(logger))

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		apierror.WriteError(w, apierror.New(http.StatusNotFound, "NOT_FOUND", "resource not found", nil))
	})

	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		apierror.WriteError(w, apierror.New(
			http.StatusMethodNotAllowed,
			"METHOD_NOT_ALLOWED",
			"method not allowed",
			nil,
		))
	})

	if deps.HealthHandler != nil {
		r.Get("/health/live", deps.HealthHandler.Live)
		r.Get("/health/ready", deps.HealthHandler.Ready)
	}

	if deps.AuthHandler != nil {
		r.Route("/v1", func(r chi.Router) {
			r.Route("/auth", func(r chi.Router) {
				r.With(authIPRateLimit, authAccountRateLimit).Post("/register", deps.AuthHandler.Register)
				r.With(authIPRateLimit, authAccountRateLimit).Post("/login", deps.AuthHandler.Login)
				r.With(authIPRateLimit).Post("/forgot-password", deps.AuthHandler.ForgotPassword)
				r.With(authIPRateLimit).Post("/reset-password", deps.AuthHandler.ResetPassword)
				r.With(authIPRateLimit).Post("/verify-email", deps.AuthHandler.VerifyEmail)
				r.Get("/oauth/{provider}/start", deps.AuthHandler.OAuthStart)
				r.Get("/oauth/{provider}/callback", deps.AuthHandler.OAuthCallback)

				if deps.AuthRequired != nil {
					r.Group(func(r chi.Router) {
						r.Use(deps.AuthRequired)
						r.With(csrfProtection).Post("/logout", deps.AuthHandler.Logout)
						r.With(resendVerifyRateLimit, csrfProtection).Post("/resend-verification", deps.AuthHandler.ResendVerification)
					})
				}
			})

			if deps.AuthRequired != nil {
				r.Group(func(r chi.Router) {
					r.Use(deps.AuthRequired)
					r.Get("/me", deps.AuthHandler.Me)
					r.With(csrfProtection).Patch("/me", deps.AuthHandler.UpdateMe)
					r.Get("/me/avatar/access-url", deps.AuthHandler.GetAvatarAccessURL)
					r.With(csrfProtection).Post("/me/avatar/upload-url", deps.AuthHandler.CreateAvatarUploadURL)
					r.With(csrfProtection).Post("/me/avatar/confirm", deps.AuthHandler.ConfirmAvatarUpload)
					r.With(csrfProtection).Delete("/me/avatar", deps.AuthHandler.DeleteAvatar)
				})
			}
		})
	}

	return r
}

func ensureMiddleware(mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if mw != nil {
		return mw
	}

	return func(next http.Handler) http.Handler {
		return next
	}
}
