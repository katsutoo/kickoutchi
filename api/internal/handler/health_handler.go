package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/apiresponse"
)

type readinessChecker interface {
	Ping(ctx context.Context) error
}

type HealthHandler struct {
	checker readinessChecker
	timeout time.Duration
}

type healthResponse struct {
	Status string `json:"status"`
}

func NewHealthHandler(checker readinessChecker, timeout time.Duration) *HealthHandler {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	return &HealthHandler{
		checker: checker,
		timeout: timeout,
	}
}

func (h *HealthHandler) Live(w http.ResponseWriter, _ *http.Request) {
	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[healthResponse]{
		Data: healthResponse{Status: "ok"},
	})
}

func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if h.checker == nil {
		apierror.WriteError(w, &apierror.Error{
			Status:  http.StatusServiceUnavailable,
			Code:    "SERVICE_UNAVAILABLE",
			Message: "service unavailable",
			Details: map[string]any{"dependency": "postgres"},
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if err := h.checker.Ping(ctx); err != nil {
		apierror.WriteError(w, &apierror.Error{
			Status:  http.StatusServiceUnavailable,
			Code:    "SERVICE_UNAVAILABLE",
			Message: "service unavailable",
			Details: map[string]any{"dependency": "postgres"},
			Err:     err,
		})
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[healthResponse]{
		Data: healthResponse{Status: "ok"},
	})
}
