package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/saubhagyabhadhouria/sauth/internal/apierror"
)

const maxBodyBytes = 1 << 20 // 1 MiB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

type errorBody struct {
	Error struct {
		Code      apierror.Code `json:"code"`
		Message   string        `json:"message"`
		RequestID string        `json:"request_id"`
	} `json:"error"`
}

// writeError renders err as the standard error envelope. Non-apierror errors
// are logged and collapsed to a 500 so internals never leak to clients.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) {
		apiErr = apierror.Internal()
		slog.Error("unhandled error",
			"err", err,
			"path", r.URL.Path,
			"request_id", middleware.GetReqID(r.Context()),
		)
	}

	var body errorBody
	body.Error.Code = apiErr.Code
	body.Error.Message = apiErr.Message
	body.Error.RequestID = middleware.GetReqID(r.Context())
	writeJSON(w, apiErr.Status, body)
}

// decodeJSON strictly decodes the request body into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return apierror.InvalidRequest("request body is not valid JSON: " + err.Error())
	}
	if dec.More() {
		return apierror.InvalidRequest("request body must contain a single JSON object")
	}
	return nil
}
