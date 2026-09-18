package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/lab517/noo-relay/internal/store"
)

// pathUserID reads the {user_id} segment, which is an integer in every admin
// route that has one.
func pathUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("user_id"), 10, 64)
	if err != nil {
		writeError(w, statusValidation, "user_id must be an integer")
		return 0, false
	}
	return id, true
}

func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body registerRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if !validateFields(w, credentialRules(body.Username, body.Password)...) {
		return
	}

	release, ok := s.acquireHash(w, r)
	if !ok {
		return
	}
	id, err := s.createUser(r, body.Username, body.Password)
	release()
	if err != nil {
		if errors.Is(err, store.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "Username already exists")
			return
		}
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "username": body.Username})
}

func (s *Server) adminUserDevices(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUserID(w, r)
	if !ok {
		return
	}
	devices, err := s.store.ListUserDevices(r.Context(), userID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) adminUserChanges(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUserID(w, r)
	if !ok {
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		// A negative or zero limit must be rejected, not passed through to
		// SQLite as "no limit".
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(w, statusValidation, "limit must be an integer between 1 and 200")
			return
		}
		limit = parsed
	}

	changes, err := s.store.ListUserChanges(r.Context(), userID, limit)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, changes)
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUserID(w, r)
	if !ok {
		return
	}
	deleted, err := s.store.DeleteUser(r.Context(), userID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted"})
}
