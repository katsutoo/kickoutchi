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
	Logger        *slog.Logger
	HealthHandler *handler.HealthHandler
}

func New(deps Dependencies) http.Handler {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
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

	return r
}
