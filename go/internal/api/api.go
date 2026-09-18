// Package api wires the relay's HTTP surface.
//
// Sync protocol v2 only. The v1 endpoints are gone — the migration was a clean
// epoch break and v1 clients must upgrade.
package api

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/lab517/noo-relay/internal/auth"
	"github.com/lab517/noo-relay/internal/config"
	"github.com/lab517/noo-relay/internal/store"
)

// Version is the release the binary reports on /health, set by main. It lets
// an installer or a deploy confirm which release actually came up.
var Version = "dev"

type Server struct {
	cfg    *config.Config
	store  *store.Store
	issuer *auth.Issuer
	// dummyHash gives a login for an unknown username something to verify
	// against, so it costs what a real one costs. Built once here rather than
	// per request: at cost 12 that is a fifth of a second.
	dummyHash string
	handler   http.Handler
}

func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		cfg:       cfg,
		store:     st,
		issuer:    auth.NewIssuer(cfg.JWTSecret, cfg.AccessTokenExpireMinutes, cfg.RefreshTokenExpireDays),
		dummyHash: auth.DummyHash(cfg.BcryptCost),
	}
	s.handler = accessLog(s.routes())
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Auth: no bearer token required, these are how you get one.
	pair(mux, "POST /api/v2/auth/register", http.HandlerFunc(s.register))
	pair(mux, "POST /api/v2/auth/login", http.HandlerFunc(s.login))
	pair(mux, "POST /api/v2/auth/refresh", http.HandlerFunc(s.refresh))

	// Devices.
	pair(mux, "GET /api/v2/devices", s.requireUser(http.HandlerFunc(s.listDevices)))
	pair(mux, "POST /api/v2/devices", s.requireUser(http.HandlerFunc(s.registerDevice)))
	mux.Handle("DELETE /api/v2/devices/{device_id}", s.requireUser(http.HandlerFunc(s.deleteDevice)))

	// Packets. The path and the response field keep the v1 name "changes":
	// deployed clients depend on it.
	pair(mux, "GET /api/v2/changes/vector", s.requireUser(http.HandlerFunc(s.getVector)))
	pair(mux, "GET /api/v2/changes/usage", s.requireUser(http.HandlerFunc(s.getUsage)))
	pair(mux, "GET /api/v2/changes/hashes", s.requireUser(http.HandlerFunc(s.getStreamHashes)))

	// Attachment blobs (docs/P2P_SYNC.md §3.5). GET also answers HEAD.
	mux.Handle("PUT /api/v2/blobs/{blob_id}", s.requireUser(http.HandlerFunc(s.putBlob)))
	mux.Handle("GET /api/v2/blobs/{blob_id}", s.requireUser(http.HandlerFunc(s.getBlob)))
	pair(mux, "POST /api/v2/changes", s.requireUser(http.HandlerFunc(s.uploadPacket)))
	pair(mux, "GET /api/v2/changes", s.requireUser(http.HandlerFunc(s.pullPackets)))

	// Admin dashboard API.
	pair(mux, "GET /api/v2/admin/stats", s.requireAdmin(http.HandlerFunc(s.adminStats)))
	pair(mux, "GET /api/v2/admin/users", s.requireAdmin(http.HandlerFunc(s.adminListUsers)))
	pair(mux, "POST /api/v2/admin/users", s.requireAdmin(http.HandlerFunc(s.adminCreateUser)))
	pair(mux, "DELETE /api/v2/admin/users/{user_id}", s.requireAdmin(http.HandlerFunc(s.adminDeleteUser)))
	pair(mux, "GET /api/v2/admin/users/{user_id}/devices", s.requireAdmin(http.HandlerFunc(s.adminUserDevices)))
	pair(mux, "GET /api/v2/admin/users/{user_id}/changes", s.requireAdmin(http.HandlerFunc(s.adminUserChanges)))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": Version})
	})

	s.mountStatic(mux)
	return mux
}

// pair registers a route under both its bare and trailing-slash forms.
// Clients in the field use both, and Go's ServeMux treats them as distinct
// patterns — "/x/" alone would be a subtree match, and "/x" alone would 301
// a POST body away.
func pair(mux *http.ServeMux, pattern string, h http.Handler) {
	mux.Handle(pattern, h)
	mux.Handle(pattern+"/{$}", h)
}

// mountStatic serves the admin dashboard, a single hand-written HTML file with
// no build step. It lives at the repository root, outside this module, so the
// directory is configured rather than embedded.
func (s *Server) mountStatic(mux *http.ServeMux) {
	info, err := os.Stat(s.cfg.StaticDir)
	if err != nil || !info.IsDir() {
		slog.Warn("admin dashboard not mounted: static directory not found",
			"path", s.cfg.StaticDir)
		return
	}
	files := http.FileServer(http.Dir(s.cfg.StaticDir))
	mux.Handle("GET /admin/", http.StripPrefix("/admin/", files))
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		// 307 rather than a permanent redirect, matching Starlette's mount
		// behaviour and keeping the path out of browser redirect caches.
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
}
