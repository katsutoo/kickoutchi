package apiresponse

import (
	"encoding/json"
	"net/http"
)

type DataEnvelope[T any] struct {
	Data T `json:"data"`
}

func WriteJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		return err
	}

	return nil
}
