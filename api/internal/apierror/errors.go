package apierror

import (
	"errors"
	"net/http"

	"github.com/katsutoo/kickoutchi/api/internal/apiresponse"
)

type Error struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
	Err     error
}

func New(status int, code, message string, err error) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
		Err:     err,
	}
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}

	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

type ErrorEnvelope struct {
	Error   string         `json:"error"`
	Code    string         `json:"code"`
	Details map[string]any `json:"details,omitempty"`
}

func WriteError(w http.ResponseWriter, appErr *Error) {
	if appErr == nil {
		appErr = New(http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error", nil)
	}

	if appErr.Status == 0 {
		appErr.Status = http.StatusInternalServerError
	}

	if appErr.Code == "" {
		appErr.Code = "INTERNAL_ERROR"
	}

	if appErr.Message == "" {
		appErr.Message = http.StatusText(appErr.Status)
	}

	_ = apiresponse.WriteJSON(w, appErr.Status, ErrorEnvelope{
		Error:   appErr.Message,
		Code:    appErr.Code,
		Details: appErr.Details,
	})
}

func From(err error) *Error {
	if err == nil {
		return nil
	}

	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr
	}

	return New(http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error", err)
}
