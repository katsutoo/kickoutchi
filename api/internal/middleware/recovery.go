package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error(
						"panic_recovered",
						slog.Any("panic", recovered),
						slog.String("request_id", chimiddleware.GetReqID(r.Context())),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.String("remote_ip", r.RemoteAddr),
						slog.String("stack", string(debug.Stack())),
					)

					apierror.WriteError(w, apierror.New(
						http.StatusInternalServerError,
						"INTERNAL_ERROR",
						"internal server error",
						nil,
					))
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
