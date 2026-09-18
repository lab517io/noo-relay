package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// errorBody matches FastAPI's error envelope, {"detail": "..."}, because
// deployed clients read that field.
type errorBody struct {
	Detail string `json:"detail"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		slog.Error("marshal response", "error", err)
		http.Error(w, `{"detail":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, errorBody{Detail: detail})
}

// writeServerError logs the cause and tells the client nothing about it.
func writeServerError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "Internal server error")
}

// StatusUnprocessableEntity is what FastAPI returns for a request that is
// well-formed HTTP but fails schema validation — a missing field, a bad type,
// an out-of-range query parameter. Clients distinguish it from the 400s the
// handlers raise deliberately, so the split is preserved.
const statusValidation = http.StatusUnprocessableEntity

// maxJSONBody bounds every JSON request body. The largest legitimate one is a
// login — a few short strings — so 64 KiB is generous. Without a bound, the
// unauthenticated /auth endpoints would buffer whatever a client sent: one
// multi-gigabyte "password" is enough to exhaust memory.
const maxJSONBody = 64 << 10

// decodeJSON reads a JSON body, rejecting unknown-shaped input with 422 and an
// oversized one with 413.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength > maxJSONBody {
		writeError(w, http.StatusRequestEntityTooLarge, "Request body too large")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return false
		}
		writeError(w, statusValidation, "Invalid request body: expected a JSON object")
		return false
	}
	return true
}

// validate reports the first failed constraint, mirroring the Pydantic field
// limits on the Python request models.
type fieldRule struct {
	name     string
	value    string
	min, max int
	required bool
}

func validateFields(w http.ResponseWriter, rules ...fieldRule) bool {
	for _, rule := range rules {
		n := len([]rune(rule.value))
		switch {
		case rule.required && rule.value == "":
			writeError(w, statusValidation, "Field required: "+rule.name)
			return false
		case rule.min > 0 && n < rule.min:
			writeError(w, statusValidation,
				rule.name+" must have at least "+itoa(rule.min)+" characters")
			return false
		case rule.max > 0 && n > rule.max:
			writeError(w, statusValidation,
				rule.name+" must have at most "+itoa(rule.max)+" characters")
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
