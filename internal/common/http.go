package common

import (
	"encoding/json"
	"net/http"
)

func ReadJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

// ReadExternalJSON decodes a payload whose schema is owned by another system,
// such as an Alertmanager webhook. Unknown fields are ignored so a sender
// upgrade cannot turn every delivery into a 400; the body size is bounded.
func ReadExternalJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	defer r.Body.Close()
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(dst)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]any{
		"error": message,
	})
}
