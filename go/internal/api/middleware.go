package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lab517/noo-relay/internal/auth"
	"github.com/lab517/noo-relay/internal/store"
)

type contextKey int

const claimsKey contextKey = iota

// callerFrom returns the authenticated caller. It is only valid inside a
// handler wrapped by requireUser.
func callerFrom(ctx context.Context) *auth.Claims {
	claims, _ := ctx.Value(claimsKey).(*auth.Claims)
	return claims
}

// writeAuthError answers a rejected credential the way FastAPI does: 401 with
// a WWW-Authenticate challenge, so clients know to re-authenticate.
func writeAuthError(w http.ResponseWriter, detail string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, detail)
}

// bearerToken extracts the credential. A missing or malformed Authorization
// header is reported exactly as FastAPI's HTTPBearer reports it — 401 "Not
// authenticated" — so a client cannot tell the two implementations apart.
func bearerToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		writeAuthError(w, "Not authenticated")
		return "", false
	}
	return token, true
}

// requireUser authenticates the caller and refreshes the device's last_seen.
//
// It re-checks that the token's device still exists on every request, which is
// what makes DELETE /devices/{id} an effective revocation: once the row is
// gone, the device's access tokens stop working immediately.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(w, r)
		if !ok {
			return
		}

		claims, err := s.issuer.Decode(token)
		if err != nil {
			writeAuthError(w, "Invalid or expired token")
			return
		}
		if claims.Type != auth.TypeAccess {
			writeAuthError(w, "Invalid token type")
			return
		}

		known, err := s.store.DeviceBelongsToUser(r.Context(), claims.UserID, claims.DeviceID)
		if err != nil {
			writeServerError(w, r, err)
			return
		}
		if !known {
			writeAuthError(w, "User or device no longer exists")
			return
		}

		if err := s.store.TouchDevice(r.Context(), claims.UserID, claims.DeviceID, store.Now()); err != nil {
			writeServerError(w, r, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

// requireAdmin gates the dashboard API on the NOO_ADMIN_TOKEN bearer token.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(w, r)
		if !ok {
			return
		}
		// Constant-time comparison to avoid leaking the token byte-by-byte
		// via response timing.
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) != 1 {
			writeError(w, http.StatusForbidden, "Invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// accessLog replaces the request line uvicorn used to print.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(started).Round(time.Microsecond))
	})
}
