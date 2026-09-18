package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/lab517/noo-relay/internal/config"
)

// limitServer is newServer without the test conveniences that switch the
// limits off: registration closed, rate limit on — the shipped defaults.
func limitServer(t *testing.T, tweak func(*config.Config)) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.JWTSecret = "test-secret-key-for-testing"
	cfg.AdminToken = "test-admin-token"
	cfg.BcryptCost = bcrypt.MinCost
	cfg.StaticDir = t.TempDir()
	cfg.MinFreeDiskBytes = 0
	if tweak != nil {
		tweak(cfg)
	}
	return newServerWith(t, cfg)
}

func (s *Server) sendFrom(t *testing.T, remote, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(mustJSON(t, body)))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, v)
	return rec.Body.String()
}

func loginBody(username, password string) map[string]string {
	return map[string]string{
		"username": username, "password": password,
		"device_id": "device-1", "device_name": "Device 1",
	}
}

// ---------- Registration ----------

func TestRegistrationClosedByDefault(t *testing.T) {
	srv := limitServer(t, nil)

	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/register",
		map[string]string{"username": "eve", "password": testPassword}, nil)
	requireStatus(t, rec, http.StatusForbidden)

	// The operator still creates accounts, and they log in as usual.
	rec = srv.sendJSON(t, http.MethodPost, "/api/v2/admin/users",
		map[string]string{"username": "amy", "password": testPassword}, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusCreated)
	srv.loginDevice(t, "amy", "device-1", "Device 1", "linux")
}

func TestRegistrationCanBeOpened(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) { c.OpenRegistration = true })
	srv.registerUser(t, "amy")
}

// ---------- Rate limits ----------

func TestAuthRateLimitedPerClientIP(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) { c.AuthRatePerMinute = 3 })

	for i := 0; i < 3; i++ {
		rec := srv.sendFrom(t, "198.51.100.1:1000", http.MethodPost, "/api/v2/auth/login", loginBody("nobody", "wrong-password"), nil)
		requireStatus(t, rec, http.StatusUnauthorized)
	}
	rec := srv.sendFrom(t, "198.51.100.1:1000", http.MethodPost, "/api/v2/auth/login", loginBody("nobody", "wrong-password"), nil)
	requireStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}

	// Another client is unaffected.
	rec = srv.sendFrom(t, "198.51.100.2:1000", http.MethodPost, "/api/v2/auth/login", loginBody("nobody", "wrong-password"), nil)
	requireStatus(t, rec, http.StatusUnauthorized)
}

// Refresh is never throttled: the client drops its tokens when a refresh
// fails, so a 429 there would log the device out.
func TestRefreshIsNotRateLimited(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) {
		c.AuthRatePerMinute = 1
		c.OpenRegistration = true
	})
	srv.registerUser(t, "amy") // spends the one attempt
	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/login", loginBody("amy", testPassword), nil)
	requireStatus(t, rec, http.StatusTooManyRequests)

	// Log in from elsewhere to get a refresh token, then refresh repeatedly
	// from the throttled address.
	rec = srv.sendFrom(t, "198.51.100.9:1", http.MethodPost, "/api/v2/auth/login", loginBody("amy", testPassword), nil)
	requireStatus(t, rec, http.StatusOK)
	var tokens tokenResponse
	decode(t, rec, &tokens)
	for i := 0; i < 5; i++ {
		rec = srv.sendJSON(t, http.MethodPost, "/api/v2/auth/refresh",
			map[string]string{"refresh_token": tokens.RefreshToken}, nil)
		requireStatus(t, rec, http.StatusOK)
	}
}

func TestForwardedForTrustedOnlyFromProxies(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) {
		c.AuthRatePerMinute = 1
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	})
	login := func(remote, xff string) int {
		return srv.sendFrom(t, remote, http.MethodPost, "/api/v2/auth/login",
			loginBody("nobody", "wrong-password"), map[string]string{"X-Forwarded-For": xff}).Code
	}

	// Behind the trusted proxy, each forwarded client has its own budget —
	// judged by the hop the proxy appended, not by what the client claimed.
	if code := login("127.0.0.1:1", "203.0.113.1"); code != http.StatusUnauthorized {
		t.Fatalf("first client: %d", code)
	}
	if code := login("127.0.0.1:1", "203.0.113.2"); code != http.StatusUnauthorized {
		t.Fatalf("second client: %d", code)
	}
	if code := login("127.0.0.1:1", "10.9.9.9, 203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("first client again, behind a spoofed hop: %d, want 429", code)
	}

	// An untrusted peer's header is ignored: rotating it buys nothing.
	if code := login("198.51.100.7:1", "203.0.113.50"); code != http.StatusUnauthorized {
		t.Fatalf("untrusted peer: %d", code)
	}
	if code := login("198.51.100.7:1", "203.0.113.51"); code != http.StatusTooManyRequests {
		t.Fatalf("untrusted peer with a new header: %d, want 429", code)
	}
}

func TestClientIPGroupsIPv6By64(t *testing.T) {
	l := newLimits(1, 1, nil)
	a := httptest.NewRequest(http.MethodGet, "/", nil)
	a.RemoteAddr = "[2001:db8:1:2::1]:443"
	b := httptest.NewRequest(http.MethodGet, "/", nil)
	b.RemoteAddr = "[2001:db8:1:2:ffff::9]:443"
	if l.clientIP(a) != l.clientIP(b) {
		t.Fatalf("%v and %v should share a /64", l.clientIP(a), l.clientIP(b))
	}
}

// ---------- Login backoff ----------

func TestLoginBackoffPerUsername(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) {
		c.AuthRatePerMinute = 0
		c.OpenRegistration = true
	})
	srv.registerUser(t, "amy")

	for _, name := range []string{"amy", "no-such-user"} {
		// Free failures, then one that starts the clock — each from a
		// different address, which must not help.
		for i := 0; i <= loginFreeFailures; i++ {
			remote := "198.51.100." + itoa(10+i) + ":1"
			rec := srv.sendFrom(t, remote, http.MethodPost, "/api/v2/auth/login", loginBody(name, "wrong-password"), nil)
			requireStatus(t, rec, http.StatusUnauthorized)
		}
		// Now even the right password waits, and an unknown name answers the
		// same way as a real one.
		rec := srv.sendFrom(t, "198.51.100.99:1", http.MethodPost, "/api/v2/auth/login", loginBody(name, testPassword), nil)
		requireStatus(t, rec, http.StatusTooManyRequests)
	}

	// Once the wait is over, the right password gets in and clears the slate.
	srv.limits.login.Succeed("amy")
	srv.loginDevice(t, "amy", "device-1", "Device 1", "linux")
}

// ---------- bcrypt slots ----------

func TestLoginAnswers503WhenHashSlotsAreFull(t *testing.T) {
	srv := limitServer(t, func(c *config.Config) {
		c.AuthRatePerMinute = 0
		c.MaxConcurrentHashes = 1
	})
	srv.limits.hashSlots <- struct{}{} // someone else's verification, in flight
	defer func() { <-srv.limits.hashSlots }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login",
		strings.NewReader(mustJSON(t, loginBody("amy", testPassword)))).WithContext(ctx)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusServiceUnavailable)
}

// ---------- Storage limits ----------

func TestQuotaRefusesNewDataOnly(t *testing.T) {
	srv := newServer(t)
	srv.cfg.UserQuotaBytes = 100
	token := srv.registerAndLogin(t, "amy", "device-a", "Device A")
	sixty := bytes.Repeat([]byte("x"), 60)

	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", sixty, uploadHeaders(token, "device-a", 1)), http.StatusCreated)
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", sixty, uploadHeaders(token, "device-a", 2)), http.StatusInsufficientStorage)

	// Re-sending what is held stores nothing, and is never refused.
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", sixty, uploadHeaders(token, "device-a", 1)), http.StatusOK)

	// A snapshot that frees more than it adds gets in — that is how an
	// account at its quota compacts its way back under it.
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", sixty,
		snapshotHeaders(token, "device-a", 2, map[string]int64{"device-a": 1}))
	requireStatus(t, rec, http.StatusCreated)
	if u := srv.usage(t, token); u.Bytes != 60 || u.QuotaBytes != 100 {
		t.Fatalf("usage after compaction: %d bytes, quota %d; want 60 and 100", u.Bytes, u.QuotaBytes)
	}

	// Blobs count against the same quota.
	id := fakeBlobID(7)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), sixty, bearer(token)), http.StatusInsufficientStorage)
}

func TestQuotaAllowsHeldBlob(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "amy", "device-a", "Device A")
	id := fakeBlobID(3)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("blob-bytes"), bearer(token)), http.StatusCreated)

	srv.cfg.UserQuotaBytes = 5 // already over
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("blob-bytes"), bearer(token)), http.StatusOK)
}

func TestStreamCapRefusesNewStreams(t *testing.T) {
	srv := newServer(t)
	srv.cfg.MaxStreamsPerUser = 2
	token := srv.registerAndLogin(t, "amy", "device-a", "Device A")

	srv.fill(t, token, "device-a", 1, 1)
	srv.fill(t, token, "device-b", 1, 1)
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("x"), uploadHeaders(token, "device-c", 1))
	requireStatus(t, rec, http.StatusInsufficientStorage)

	// Existing streams carry on.
	srv.fill(t, token, "device-a", 2, 3)
}

func TestLowDiskRefusesUploads(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "amy", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 1)

	srv.cfg.MinFreeDiskBytes = 1 << 62 // more than any disk has
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("x"), uploadHeaders(token, "device-a", 2))
	requireStatus(t, rec, http.StatusInsufficientStorage)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(fakeBlobID(1)), []byte("b"), bearer(token)), http.StatusInsufficientStorage)

	// A held slot still answers as held.
	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("device-a-blob-1"), uploadHeaders(token, "device-a", 1))
	requireStatus(t, rec, http.StatusOK)
}
