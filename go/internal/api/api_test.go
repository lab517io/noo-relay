package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/lab517/noo-relay/internal/config"
	"github.com/lab517/noo-relay/internal/store"
)

const testPassword = "securepass123"

// newServer builds a relay backed by its own database. Unlike the Python
// suite's fixed test_noo_sync.db in the working directory, each test gets a
// private temp file, so the suite is safe to run with -race and in parallel.
func newServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Default()
	cfg.DatabaseURL = filepath.Join(t.TempDir(), "test_noo_sync.db")
	cfg.JWTSecret = "test-secret-key-for-testing"
	cfg.AdminToken = "test-admin-token"
	// The production cost of 12 would dominate the runtime of a suite that
	// hashes a password in almost every test.
	cfg.BcryptCost = bcrypt.MinCost
	cfg.StaticDir = t.TempDir()

	st, err := store.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	return New(cfg, st)
}

func (s *Server) send(t *testing.T, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func (s *Server) sendJSON(t *testing.T, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	return s.send(t, method, path, encoded, headers)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func uploadHeaders(token, origin string, counter int64) map[string]string {
	return map[string]string{
		"Authorization":       "Bearer " + token,
		"Content-Type":        "application/octet-stream",
		"X-Noo-Origin-Device": origin,
		"X-Noo-Counter":       strconv.FormatInt(counter, 10),
	}
}

func pullPath(have map[string]int64, limit int) string {
	if have == nil {
		have = map[string]int64{}
	}
	encoded, _ := json.Marshal(have)
	query := url.Values{"have": {string(encoded)}}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	return "/api/v2/changes/?" + query.Encode()
}

func (s *Server) registerUser(t *testing.T, username string) {
	t.Helper()
	rec := s.sendJSON(t, http.MethodPost, "/api/v2/auth/register", map[string]string{
		"username": username,
		"password": testPassword,
	}, nil)
	requireStatus(t, rec, http.StatusCreated)
}

func (s *Server) loginDevice(t *testing.T, username, deviceID, deviceName, platform string) tokenResponse {
	t.Helper()
	rec := s.sendJSON(t, http.MethodPost, "/api/v2/auth/login", map[string]string{
		"username":    username,
		"password":    testPassword,
		"device_id":   deviceID,
		"device_name": deviceName,
		"platform":    platform,
	}, nil)
	requireStatus(t, rec, http.StatusOK)

	var tokens tokenResponse
	decode(t, rec, &tokens)
	return tokens
}

// registerAndLogin returns the access token for a fresh user and device.
func (s *Server) registerAndLogin(t *testing.T, username, deviceID, deviceName string) string {
	t.Helper()
	s.registerUser(t, username)
	return s.loginDevice(t, username, deviceID, deviceName, "linux").AccessToken
}

func TestHealth(t *testing.T) {
	srv := newServer(t)
	rec := srv.send(t, http.MethodGet, "/health", nil, nil)
	requireStatus(t, rec, http.StatusOK)

	var body map[string]string
	decode(t, rec, &body)
	if body["status"] != "ok" {
		t.Fatalf("status = %q, want ok", body["status"])
	}
}

func TestRegister(t *testing.T) {
	srv := newServer(t)
	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/register", map[string]string{
		"username": "alice",
		"password": testPassword,
	}, nil)
	requireStatus(t, rec, http.StatusCreated)

	var body map[string]string
	decode(t, rec, &body)
	if body["message"] == "" {
		t.Fatal("expected a message in the response")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	srv := newServer(t)
	srv.registerUser(t, "alice")

	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/register", map[string]string{
		"username": "alice",
		"password": "differentpass1",
	}, nil)
	requireStatus(t, rec, http.StatusConflict)
}

func TestRegisterValidation(t *testing.T) {
	srv := newServer(t)
	for _, tc := range []struct{ name, username, password string }{
		{"username too short", "ab", testPassword},
		{"password too short", "alice", "short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/register", map[string]string{
				"username": tc.username,
				"password": tc.password,
			}, nil)
			requireStatus(t, rec, http.StatusUnprocessableEntity)
		})
	}
}

func TestLogin(t *testing.T) {
	srv := newServer(t)
	srv.registerUser(t, "bob")

	tokens := srv.loginDevice(t, "bob", "device-1", "Bob's Laptop", "linux")
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected both tokens")
	}
	if tokens.TokenType != "bearer" {
		t.Fatalf("token_type = %q, want bearer", tokens.TokenType)
	}
}

func TestLoginInvalidPassword(t *testing.T) {
	srv := newServer(t)
	srv.registerUser(t, "carol")

	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/login", map[string]string{
		"username":    "carol",
		"password":    "wrongpassword!",
		"device_id":   "device-1",
		"device_name": "Carol's PC",
		"platform":    "windows",
	}, nil)
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestRefreshToken(t *testing.T) {
	srv := newServer(t)
	srv.registerUser(t, "dave")
	tokens := srv.loginDevice(t, "dave", "device-1", "Dave's PC", "linux")

	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/refresh", map[string]string{
		"refresh_token": tokens.RefreshToken,
	}, nil)
	requireStatus(t, rec, http.StatusOK)

	var refreshed tokenResponse
	decode(t, rec, &refreshed)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("expected both tokens")
	}
}

// An access token must not be usable where a refresh token is required.
func TestRefreshRejectsAccessToken(t *testing.T) {
	srv := newServer(t)
	access := srv.registerAndLogin(t, "dana", "device-1", "Device")

	rec := srv.sendJSON(t, http.MethodPost, "/api/v2/auth/refresh", map[string]string{
		"refresh_token": access,
	}, nil)
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestUploadAndDownloadPackets(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "eve", "device-a", "Device A")
	tokenB := srv.loginDevice(t, "eve", "device-b", "Device B", "windows").AccessToken

	payload := []byte("encrypted-packet-from-device-a")
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", payload, uploadHeaders(tokenA, "device-a", 1))
	requireStatus(t, rec, http.StatusCreated)

	var upload uploadResponse
	decode(t, rec, &upload)
	if !upload.Stored {
		t.Fatal("stored = false, want true")
	}

	// The vector now reflects device-a's stream.
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(tokenA))
	requireStatus(t, rec, http.StatusOK)

	var vector vectorResponse
	decode(t, rec, &vector)
	if len(vector.Vectors) != 1 || vector.Vectors["device-a"] != 1 {
		t.Fatalf("vectors = %v, want {device-a: 1}", vector.Vectors)
	}

	// Device A's own vector already covers its stream — nothing to pull.
	rec = srv.send(t, http.MethodGet, pullPath(map[string]int64{"device-a": 1}, 0), nil, bearer(tokenA))
	requireStatus(t, rec, http.StatusOK)

	var pull pullResponse
	decode(t, rec, &pull)
	if len(pull.Changes) != 0 || pull.HasMore {
		t.Fatalf("expected an empty pull, got %+v", pull)
	}

	// Device B (empty vector) pulls device A's packet.
	rec = srv.send(t, http.MethodGet, pullPath(nil, 0), nil, bearer(tokenB))
	requireStatus(t, rec, http.StatusOK)

	decode(t, rec, &pull)
	if len(pull.Changes) != 1 {
		t.Fatalf("changes = %d, want 1", len(pull.Changes))
	}
	got := pull.Changes[0]
	if got.OriginDeviceID != "device-a" || got.Counter != 1 {
		t.Fatalf("identity = (%s, %d), want (device-a, 1)", got.OriginDeviceID, got.Counter)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, payload)
	}
}

func TestDuplicateUploadIsNoop(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "frank", "device-a", "Device A")

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), uploadHeaders(token, "device-a", 1))
	requireStatus(t, rec, http.StatusCreated)

	// The same slot again (it also arrived via a LAN peer): a no-op, 200.
	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), uploadHeaders(token, "device-a", 1))
	requireStatus(t, rec, http.StatusOK)

	var upload uploadResponse
	decode(t, rec, &upload)
	if upload.Stored {
		t.Fatal("stored = true, want false for an already-held slot")
	}

	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(token))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-a"] != 1 {
		t.Fatalf("vectors = %v, want {device-a: 1}", vector.Vectors)
	}
}

func TestGapUploadRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "grace", "device-a", "Device A")

	// Counter 2 before counter 1 is a contiguity violation.
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-2"), uploadHeaders(token, "device-a", 2))
	requireStatus(t, rec, http.StatusConflict)

	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-0"), uploadHeaders(token, "device-a", 0))
	requireStatus(t, rec, http.StatusBadRequest)
}

// A device may upload packets on behalf of another device (gossip).
func TestCarriedPacketUpload(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "henry", "device-a", "Device A")

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-from-c"), uploadHeaders(tokenA, "device-c", 1))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(tokenA))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-c"] != 1 {
		t.Fatalf("vectors = %v, want {device-c: 1}", vector.Vectors)
	}
}

func TestPullVectorFiltering(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "irene", "device-a", "Device A")
	tokenB := srv.loginDevice(t, "irene", "device-b", "Device B", "linux").AccessToken

	for i := int64(1); i <= 3; i++ {
		rec := srv.send(t, http.MethodPost, "/api/v2/changes/",
			[]byte(fmt.Sprintf("blob-%d", i)), uploadHeaders(tokenA, "device-a", i))
		requireStatus(t, rec, http.StatusCreated)
	}

	// B already holds counters 1-2 of device-a: only counter 3 comes back.
	rec := srv.send(t, http.MethodGet, pullPath(map[string]int64{"device-a": 2}, 0), nil, bearer(tokenB))
	requireStatus(t, rec, http.StatusOK)

	var pull pullResponse
	decode(t, rec, &pull)
	if len(pull.Changes) != 1 || pull.Changes[0].Counter != 3 {
		t.Fatalf("changes = %+v, want only counter 3", pull.Changes)
	}
}

func TestPullHasMoreAndPerDeviceOrder(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "jack", "device-a", "Device A")
	tokenB := srv.loginDevice(t, "jack", "device-b", "Device B", "linux").AccessToken

	for i := int64(1); i <= 5; i++ {
		rec := srv.send(t, http.MethodPost, "/api/v2/changes/",
			[]byte(fmt.Sprintf("blob-%d", i)), uploadHeaders(tokenA, "device-a", i))
		requireStatus(t, rec, http.StatusCreated)
	}

	rec := srv.send(t, http.MethodGet, pullPath(nil, 3), nil, bearer(tokenB))
	requireStatus(t, rec, http.StatusOK)

	var pull pullResponse
	decode(t, rec, &pull)
	if !pull.HasMore {
		t.Fatal("has_more = false, want true")
	}
	if got := counters(pull); !equal(got, []int64{1, 2, 3}) {
		t.Fatalf("counters = %v, want [1 2 3]: per-device delivery must be ascending", got)
	}

	// Advance the vector as the client would and fetch the rest.
	rec = srv.send(t, http.MethodGet, pullPath(map[string]int64{"device-a": 3}, 0), nil, bearer(tokenB))
	decode(t, rec, &pull)
	if got := counters(pull); !equal(got, []int64{4, 5}) {
		t.Fatalf("counters = %v, want [4 5]", got)
	}
	if pull.HasMore {
		t.Fatal("has_more = true, want false")
	}
}

func counters(p pullResponse) []int64 {
	out := make([]int64, 0, len(p.Changes))
	for _, c := range p.Changes {
		out = append(out, c.Counter)
	}
	return out
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPullInvalidHaveRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "kate", "device-a", "Device A")

	for _, have := range []string{"not-json", "[1,2,3]", `{"device-a":"one"}`} {
		rec := srv.send(t, http.MethodGet, "/api/v2/changes/?have="+url.QueryEscape(have), nil, bearer(token))
		requireStatus(t, rec, http.StatusBadRequest)
	}
}

func TestPullInvalidLimitRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "kevin", "device-a", "Device A")

	for _, limit := range []string{"0", "-1", "1001", "abc"} {
		rec := srv.send(t, http.MethodGet, "/api/v2/changes/?limit="+limit, nil, bearer(token))
		requireStatus(t, rec, http.StatusUnprocessableEntity)
	}
}

func TestListDevices(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "heidi", "device-1", "Heidi's Laptop")

	rec := srv.send(t, http.MethodGet, "/api/v2/devices/", nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)

	var devices []store.Device
	decode(t, rec, &devices)
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	if devices[0].DeviceID != "device-1" || devices[0].DeviceName != "Heidi's Laptop" {
		t.Fatalf("device = %+v", devices[0])
	}
}

func TestDeleteDevice(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "ivan", "device-1", "Device 1")
	srv.loginDevice(t, "ivan", "device-2", "Second Device", "linux")

	rec := srv.send(t, http.MethodDelete, "/api/v2/devices/device-2", nil, bearer(token))
	requireStatus(t, rec, http.StatusNoContent)

	rec = srv.send(t, http.MethodGet, "/api/v2/devices/", nil, bearer(token))
	var devices []store.Device
	decode(t, rec, &devices)
	if len(devices) != 1 || devices[0].DeviceID != "device-1" {
		t.Fatalf("devices = %+v, want only device-1", devices)
	}
}

func TestCannotDeleteOwnDevice(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "judy", "device-1", "Device 1")

	rec := srv.send(t, http.MethodDelete, "/api/v2/devices/device-1", nil, bearer(token))
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestEmptyPayloadRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "karl", "device-1", "Device 1")

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", nil, uploadHeaders(token, "device-1", 1))
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestMissingIdentityHeadersRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "liam", "device-1", "Device 1")

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("blob"), map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/octet-stream",
	})
	requireStatus(t, rec, http.StatusUnprocessableEntity)
}

func TestUnauthorizedAccess(t *testing.T) {
	srv := newServer(t)

	// No credential offered at all: 401 with a challenge, matching FastAPI.
	rec := srv.send(t, http.MethodGet, "/api/v2/changes/", nil, nil)
	requireStatus(t, rec, http.StatusUnauthorized)
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}

	// A malformed credential is reported the same way.
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/", nil,
		map[string]string{"Authorization": "Basic abc"})
	requireStatus(t, rec, http.StatusUnauthorized)

	// A credential that is offered and rejected: 401.
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/", nil, bearer("invalid-token"))
	requireStatus(t, rec, http.StatusUnauthorized)
}

// Two devices uploading their own streams concurrently must both land fully —
// the per-device contiguity check must not cross streams.
func TestConcurrentUploadsFromTwoDevices(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "carol", "device-a", "Device A")
	tokenB := srv.loginDevice(t, "carol", "device-b", "Device B", "windows").AccessToken

	var wg sync.WaitGroup
	statuses := make([][]int, 2)

	for i, stream := range []struct {
		token  string
		device string
	}{{tokenA, "device-a"}, {tokenB, "device-b"}} {
		wg.Add(1)
		go func(slot int, token, device string) {
			defer wg.Done()
			for counter := int64(1); counter <= 5; counter++ {
				rec := srv.send(t, http.MethodPost, "/api/v2/changes/",
					[]byte(fmt.Sprintf("%s-blob-%d", device, counter)),
					uploadHeaders(token, device, counter))
				statuses[slot] = append(statuses[slot], rec.Code)
			}
		}(i, stream.token, stream.device)
	}
	wg.Wait()

	for _, stream := range statuses {
		for _, code := range stream {
			if code != http.StatusCreated {
				t.Fatalf("upload status = %d, want 201", code)
			}
		}
	}

	rec := srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(tokenA))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-a"] != 5 || vector.Vectors["device-b"] != 5 {
		t.Fatalf("vectors = %v, want both streams at 5", vector.Vectors)
	}
}

// After a device is deleted, its access and refresh tokens stop working.
func TestDeletedDeviceTokenIsRevoked(t *testing.T) {
	srv := newServer(t)
	token1 := srv.registerAndLogin(t, "mallory", "device-1", "Device 1")
	stolen := srv.loginDevice(t, "mallory", "device-2", "Stolen Laptop", "linux")

	// device-2's token works before deletion.
	rec := srv.send(t, http.MethodGet, "/api/v2/changes/", nil, bearer(stolen.AccessToken))
	requireStatus(t, rec, http.StatusOK)

	rec = srv.send(t, http.MethodDelete, "/api/v2/devices/device-2", nil, bearer(token1))
	requireStatus(t, rec, http.StatusNoContent)

	// The access token no longer works...
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/", nil, bearer(stolen.AccessToken))
	requireStatus(t, rec, http.StatusUnauthorized)

	// ...and it cannot mint a fresh one via refresh.
	rec = srv.sendJSON(t, http.MethodPost, "/api/v2/auth/refresh", map[string]string{
		"refresh_token": stolen.RefreshToken,
	}, nil)
	requireStatus(t, rec, http.StatusUnauthorized)
}

// A negative admin limit must be rejected, not passed through as no-limit.
func TestAdminNegativeLimitRejected(t *testing.T) {
	srv := newServer(t)
	rec := srv.send(t, http.MethodGet, "/api/v2/admin/users/1/changes?limit=-5", nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusUnprocessableEntity)
}

func TestAdminRequiresToken(t *testing.T) {
	srv := newServer(t)

	// No credential at all is a 401; a credential that is offered and
	// rejected is a 403.
	rec := srv.send(t, http.MethodGet, "/api/v2/admin/stats", nil, nil)
	requireStatus(t, rec, http.StatusUnauthorized)

	rec = srv.send(t, http.MethodGet, "/api/v2/admin/stats", nil, bearer("wrong-token"))
	requireStatus(t, rec, http.StatusForbidden)
}

// The dashboard reads these field names directly, so the shape is a contract.
func TestAdminStatsShape(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "nina", "device-1", "Device 1")
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("blob"), uploadHeaders(token, "device-1", 1))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodGet, "/api/v2/admin/stats", nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusOK)

	var stats map[string]any
	decode(t, rec, &stats)
	for _, field := range []string{
		"user_count", "device_count", "change_count",
		"storage_bytes", "last_change_at", "server_time",
	} {
		if _, ok := stats[field]; !ok {
			t.Fatalf("stats is missing %q: %v", field, stats)
		}
	}
	if stats["change_count"].(float64) != 1 {
		t.Fatalf("change_count = %v, want 1", stats["change_count"])
	}
}

// An oversized Content-Length is rejected before the body is buffered.
// Deleting a user must take the stream marks with it. They outlive the packets
// they describe, so nothing else in the delete would reach them.
func TestAdminDeleteUserRemovesStreamMarks(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "yolanda", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 2)

	var marks int
	row := srv.store.DB().QueryRow("SELECT COUNT(*) FROM stream_marks")
	if err := row.Scan(&marks); err != nil {
		t.Fatalf("count marks: %v", err)
	}
	if marks == 0 {
		t.Fatal("expected a stream mark before the delete")
	}

	var users []store.AdminUser
	rec := srv.send(t, http.MethodGet, "/api/v2/admin/users", nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &users)
	if len(users) != 1 {
		t.Fatalf("users = %+v, want one", users)
	}

	rec = srv.send(t, http.MethodDelete,
		"/api/v2/admin/users/"+strconv.FormatInt(users[0].ID, 10), nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusOK)

	if err := srv.store.DB().QueryRow("SELECT COUNT(*) FROM stream_marks").Scan(&marks); err != nil {
		t.Fatalf("count marks: %v", err)
	}
	if marks != 0 {
		t.Fatalf("stream_marks rows = %d after the delete, want 0", marks)
	}
}

func TestOversizedContentLengthRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "nancy", "device-1", "Device 1")

	req := httptest.NewRequest(http.MethodPost, "/api/v2/changes/", bytes.NewReader([]byte("x")))
	for k, v := range uploadHeaders(token, "device-1", 1) {
		req.Header.Set(k, v)
	}
	req.ContentLength = srv.cfg.MaxPayloadSize + 1

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
}

// Clients in the field use both the bare and the trailing-slash form of every
// route, and Go's ServeMux treats them as distinct patterns.
func TestSlashVariants(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "olive", "device-1", "Device 1")

	for _, path := range []string{
		"/api/v2/devices", "/api/v2/devices/",
		"/api/v2/changes", "/api/v2/changes/",
		"/api/v2/changes/vector", "/api/v2/changes/vector/",
	} {
		rec := srv.send(t, http.MethodGet, path, nil, bearer(token))
		requireStatus(t, rec, http.StatusOK)
	}

	for _, path := range []string{"/api/v2/admin/stats", "/api/v2/admin/stats/",
		"/api/v2/admin/users", "/api/v2/admin/users/"} {
		rec := srv.send(t, http.MethodGet, path, nil, bearer(srv.cfg.AdminToken))
		requireStatus(t, rec, http.StatusOK)
	}
}

// ---------- Compaction (docs/P2P_SYNC_COMPACTION.md) ----------

// snapshotHeaders are upload headers carrying a coverage declaration.
func snapshotHeaders(token, origin string, counter int64, covers map[string]int64) map[string]string {
	headers := uploadHeaders(token, origin, counter)
	encoded, _ := json.Marshal(covers)
	headers["X-Noo-Snapshot-Covers"] = string(encoded)
	return headers
}

func (s *Server) fill(t *testing.T, token, origin string, from, to int64) {
	t.Helper()
	for i := from; i <= to; i++ {
		rec := s.send(t, http.MethodPost, "/api/v2/changes/",
			[]byte(fmt.Sprintf("%s-blob-%d", origin, i)), uploadHeaders(token, origin, i))
		requireStatus(t, rec, http.StatusCreated)
	}
}

func (s *Server) usage(t *testing.T, token string) store.Usage {
	t.Helper()
	rec := s.send(t, http.MethodGet, "/api/v2/changes/usage", nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)

	var usage store.Usage
	decode(t, rec, &usage)
	return usage
}

func TestSnapshotUploadPrunesCoveredPackets(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "nina", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 3)
	srv.fill(t, token, "device-b", 1, 2) // carried for another device

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot-of-everything"),
		snapshotHeaders(token, "device-a", 4, map[string]int64{"device-a": 3, "device-b": 2}))
	requireStatus(t, rec, http.StatusCreated)

	var upload uploadResponse
	decode(t, rec, &upload)
	if upload.Pruned == nil || upload.Pruned.Packets != 5 {
		t.Fatalf("pruned = %+v, want 5 packets", upload.Pruned)
	}
	if upload.Pruned.Bytes == 0 {
		t.Fatal("pruned bytes = 0, want the freed payload size")
	}

	// The snapshot itself survives, and nothing else does.
	usage := srv.usage(t, token)
	if usage.Packets != 1 || len(usage.Devices) != 1 {
		t.Fatalf("usage = %+v, want a single stored packet", usage)
	}
	if d := usage.Devices[0]; d.DeviceID != "device-a" || d.FirstCounter != 4 || d.Snapshots != 1 {
		t.Fatalf("survivor = %+v, want the snapshot (device-a, 4)", d)
	}

	// The vector is unchanged by pruning: it names the top of each stream.
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(token))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-a"] != 4 || vector.Vectors["device-b"] != 2 {
		t.Fatalf("vectors = %v, want {device-a: 4, device-b: 2}", vector.Vectors)
	}
}

// A declaration that reaches over the snapshot's own counter must not delete
// the snapshot — it would leave the account with a pruned log and nothing to
// bootstrap from.
func TestSnapshotNeverPrunesItself(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "oscar", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 3)

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"),
		snapshotHeaders(token, "device-a", 4, map[string]int64{"device-a": 99}))
	requireStatus(t, rec, http.StatusCreated)

	var upload uploadResponse
	decode(t, rec, &upload)
	if upload.Pruned == nil || upload.Pruned.Packets != 3 {
		t.Fatalf("pruned = %+v, want 3 packets", upload.Pruned)
	}
	if usage := srv.usage(t, token); usage.Packets != 1 {
		t.Fatalf("packets = %d, want the snapshot to survive", usage.Packets)
	}
}

// The mark outlives the packets: a stream pruned to nothing still continues
// where it left off rather than restarting at 1 (§4.3, safety rule 4).
func TestPrunedStreamKeepsItsHighWaterMark(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "petra", "device-a", "Device A")
	srv.fill(t, token, "device-b", 1, 2)

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"),
		snapshotHeaders(token, "device-a", 1, map[string]int64{"device-b": 2}))
	requireStatus(t, rec, http.StatusCreated)

	// Nothing of device-b is stored any more...
	if usage := srv.usage(t, token); usage.Packets != 1 {
		t.Fatalf("packets = %d, want only the snapshot", usage.Packets)
	}
	// ...yet its next counter is 3, and re-offering a pruned one is a no-op.
	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("b-1-again"),
		uploadHeaders(token, "device-b", 1))
	requireStatus(t, rec, http.StatusOK)

	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("b-3"),
		uploadHeaders(token, "device-b", 3))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(token))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-b"] != 3 {
		t.Fatalf("vectors = %v, want device-b at 3", vector.Vectors)
	}
}

// A retried upload whose 201 was lost still prunes, so the space is reclaimed
// on the second attempt rather than never.
func TestSnapshotRetryStillPrunes(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "quinn", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 2)

	headers := snapshotHeaders(token, "device-a", 3, map[string]int64{"device-a": 2})
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"), uploadHeaders(token, "device-a", 3))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"), headers)
	requireStatus(t, rec, http.StatusOK)

	var upload uploadResponse
	decode(t, rec, &upload)
	if upload.Stored || upload.Pruned == nil || upload.Pruned.Packets != 2 {
		t.Fatalf("upload = %+v, want a no-op that pruned 2 packets", upload)
	}
}

// A snapshot must not sit behind packets the requester could not otherwise
// accept — including behind a page boundary (§4.2).
func TestPullReturnsSnapshotsFirst(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "rosa", "device-a", "Device A")
	tokenC := srv.loginDevice(t, "rosa", "device-c", "Device C", "linux").AccessToken
	srv.fill(t, token, "device-a", 1, 3)

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot-from-b"),
		snapshotHeaders(token, "device-b", 1, map[string]int64{}))
	requireStatus(t, rec, http.StatusCreated)

	// device-a sorts first alphabetically; the snapshot still leads the page.
	rec = srv.send(t, http.MethodGet, pullPath(nil, 1), nil, bearer(tokenC))
	requireStatus(t, rec, http.StatusOK)

	var pull pullResponse
	decode(t, rec, &pull)
	if len(pull.Changes) != 1 || pull.Changes[0].OriginDeviceID != "device-b" {
		t.Fatalf("first page = %+v, want the snapshot from device-b", pull.Changes)
	}
	if !pull.HasMore {
		t.Fatal("has_more = false, want the remaining packets announced")
	}
}

// A snapshot must not be hoisted above the lower counters of its own device:
// delivery within a stream stays ascending, or a client that advanced its
// vector to the snapshot could never ask for what sits below it again.
func TestPullKeepsPerDeviceAscentPastASnapshot(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "ulla", "device-a", "Device A")
	tokenC := srv.loginDevice(t, "ulla", "device-c", "Device C", "linux").AccessToken

	srv.fill(t, token, "device-a", 1, 3)
	// Counter 4 declares coverage, so it is flagged, but prunes nothing of
	// device-a's own stream: 1-3 are still stored underneath it.
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"),
		snapshotHeaders(token, "device-a", 4, map[string]int64{}))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodGet, pullPath(nil, 0), nil, bearer(tokenC))
	requireStatus(t, rec, http.StatusOK)
	var pull pullResponse
	decode(t, rec, &pull)
	if got := counters(pull); !equal(got, []int64{1, 2, 3, 4}) {
		t.Fatalf("counters = %v, want [1 2 3 4]: a snapshot must not jump its own stream", got)
	}

	// And paging past it must not strand anything: walk the pages the way a
	// client does, advancing the vector to the highest counter seen.
	have := map[string]int64{}
	var seen []int64
	for page := 0; page < 5; page++ {
		rec = srv.send(t, http.MethodGet, pullPath(have, 2), nil, bearer(tokenC))
		requireStatus(t, rec, http.StatusOK)
		decode(t, rec, &pull)
		seen = append(seen, counters(pull)...)
		for _, c := range pull.Changes {
			if c.Counter > have[c.OriginDeviceID] {
				have[c.OriginDeviceID] = c.Counter
			}
		}
		if !pull.HasMore {
			break
		}
	}
	if !equal(seen, []int64{1, 2, 3, 4}) {
		t.Fatalf("paged delivery = %v, want every packet exactly once", seen)
	}
}

// A stream that holds a snapshot still leads the page, so the per-device
// ascent above does not cost the cross-device hoist §4.2 asks for.
func TestPullHoistsTheStreamHoldingASnapshot(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "vera", "device-a", "Device A")
	tokenC := srv.loginDevice(t, "vera", "device-c", "Device C", "linux").AccessToken

	srv.fill(t, token, "device-a", 1, 3)
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot-from-b"),
		snapshotHeaders(token, "device-b", 1, map[string]int64{}))
	requireStatus(t, rec, http.StatusCreated)

	rec = srv.send(t, http.MethodGet, pullPath(nil, 2), nil, bearer(tokenC))
	requireStatus(t, rec, http.StatusOK)
	var pull pullResponse
	decode(t, rec, &pull)
	// device-a sorts first alphabetically and has three packets waiting; the
	// snapshot-bearing stream still comes first.
	if len(pull.Changes) == 0 || pull.Changes[0].OriginDeviceID != "device-b" {
		t.Fatalf("first page = %+v, want device-b's snapshot leading", pull.Changes)
	}
}

// Under gossip a peer carries a packet for its origin device, and a carrier
// has no coverage declaration to send with it. When the origin later uploads
// the same packet with one, the stored row must adopt the flag — the 200 path
// already runs the prune, and pull ordering keys on the flag.
func TestSnapshotFlagAdoptedOnAlreadyHeldSlot(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "wim", "device-a", "Device A")

	srv.fill(t, token, "device-b", 1, 1)
	if usage := srv.usage(t, token); usage.Devices[0].Snapshots != 0 {
		t.Fatalf("snapshots = %d before the declaration, want 0", usage.Devices[0].Snapshots)
	}

	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("device-b-blob-1"),
		snapshotHeaders(token, "device-b", 1, map[string]int64{}))
	requireStatus(t, rec, http.StatusOK)

	usage := srv.usage(t, token)
	if usage.Packets != 1 {
		t.Fatalf("packets = %d, want the re-upload to stay a no-op", usage.Packets)
	}
	if usage.Devices[0].Snapshots != 1 {
		t.Fatalf("snapshots = %d, want the already-held row flagged", usage.Devices[0].Snapshots)
	}
}

// A gap must not be mistaken for an already-held slot and flagged.
func TestSnapshotFlagNotAdoptedAcrossAGap(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "xenia", "device-a", "Device A")

	srv.fill(t, token, "device-a", 1, 1)
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"),
		snapshotHeaders(token, "device-a", 5, map[string]int64{}))
	requireStatus(t, rec, http.StatusConflict)

	usage := srv.usage(t, token)
	if usage.Packets != 1 || usage.Devices[0].Snapshots != 0 {
		t.Fatalf("usage = %+v, want the rejected upload to change nothing", usage)
	}
}

func TestUsageBreaksDownPerDevice(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "sofia", "device-a", "Device A")
	srv.fill(t, token, "device-a", 1, 2)
	srv.fill(t, token, "device-b", 1, 1)

	usage := srv.usage(t, token)
	if usage.Packets != 3 || len(usage.Devices) != 2 {
		t.Fatalf("usage = %+v, want 3 packets over 2 devices", usage)
	}
	var total int64
	for _, d := range usage.Devices {
		total += d.Bytes
		if d.DeviceID == "device-a" {
			if d.Packets != 2 || d.FirstCounter != 1 || d.LastCounter != 2 {
				t.Fatalf("device-a = %+v, want 2 packets spanning 1-2", d)
			}
			if d.DeviceName != "Device A" {
				t.Fatalf("device name = %q, want the registered name", d.DeviceName)
			}
		}
	}
	if total != usage.Bytes || usage.Bytes == 0 {
		t.Fatalf("bytes = %d, per-device total = %d", usage.Bytes, total)
	}
}

func TestInvalidSnapshotCoversRejected(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "tomas", "device-a", "Device A")

	// "null" is well-formed JSON that declares nothing; it must be rejected
	// rather than read as an absent header.
	for _, covers := range []string{"not-json", "null", "123", `["device-a"]`} {
		headers := uploadHeaders(token, "device-a", 1)
		headers["X-Noo-Snapshot-Covers"] = covers
		rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"), headers)
		requireStatus(t, rec, statusValidation)
	}

	// Nothing was stored, so the stream still starts at 1.
	if usage := srv.usage(t, token); usage.Packets != 0 {
		t.Fatalf("packets = %d, want the rejected upload not stored", usage.Packets)
	}
}

// hashesPath builds a stream-hash query for one device's counter range.
func hashesPath(device string, from, to int64) string {
	return fmt.Sprintf("/api/v2/changes/hashes?device=%s&from=%d&to=%d",
		url.QueryEscape(device), from, to)
}

func TestStreamHashesMatchStoredPayloads(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "hana", "device-a", "Device A")

	first := []byte("packet-1")
	second := []byte("packet-2")
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", first,
		uploadHeaders(token, "device-a", 1)), http.StatusCreated)
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", second,
		uploadHeaders(token, "device-a", 2)), http.StatusCreated)

	rec := srv.send(t, http.MethodGet, hashesPath("device-a", 1, 2), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)

	var got hashesResponse
	decode(t, rec, &got)
	if got.Hashes["1"] != store.PayloadHash(first) {
		t.Fatalf("hash[1] = %q, want %q", got.Hashes["1"], store.PayloadHash(first))
	}
	if got.Hashes["2"] != store.PayloadHash(second) {
		t.Fatalf("hash[2] = %q, want %q", got.Hashes["2"], store.PayloadHash(second))
	}
}

// A counter the relay does not store is absent rather than empty: the client
// reads that as "cannot say", which must never look like a mismatch.
func TestStreamHashesOmitCountersNotHeld(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "ivan", "device-a", "Device A")

	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"),
		uploadHeaders(token, "device-a", 1)), http.StatusCreated)

	rec := srv.send(t, http.MethodGet, hashesPath("device-a", 1, 5), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)

	var got hashesResponse
	decode(t, rec, &got)
	if len(got.Hashes) != 1 {
		t.Fatalf("hashes = %v, want only counter 1", got.Hashes)
	}
}

// The whole point: two different packets under one identity are two different
// hashes, so a client can tell a fork from the duplicate the slot rule assumes.
func TestStreamHashesDistinguishReissuedIdentity(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "jane", "device-a", "Device A")

	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("original"),
		uploadHeaders(token, "device-a", 1)), http.StatusCreated)

	// A restored device re-issues counter 1 with different content. The slot
	// rule refuses it (200, not stored) — correctly, since the relay was there
	// first — and the hash is what lets the client discover that happened.
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("re-issued"),
		uploadHeaders(token, "device-a", 1))
	requireStatus(t, rec, http.StatusOK)

	rec = srv.send(t, http.MethodGet, hashesPath("device-a", 1, 1), nil, bearer(token))
	var got hashesResponse
	decode(t, rec, &got)
	if got.Hashes["1"] != store.PayloadHash([]byte("original")) {
		t.Fatal("the relay kept the wrong packet under device-a:1")
	}
	if got.Hashes["1"] == store.PayloadHash([]byte("re-issued")) {
		t.Fatal("a re-issued identity is indistinguishable from the original")
	}
}

func TestStreamHashesScopedToCaller(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "kara", "device-a", "Device A")
	tokenB := srv.registerAndLogin(t, "liam", "device-b", "Device B")

	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("kara-packet"),
		uploadHeaders(tokenA, "device-a", 1)), http.StatusCreated)

	// Another account asking about device-a learns nothing, even knowing the id.
	rec := srv.send(t, http.MethodGet, hashesPath("device-a", 1, 1), nil, bearer(tokenB))
	requireStatus(t, rec, http.StatusOK)

	var got hashesResponse
	decode(t, rec, &got)
	if len(got.Hashes) != 0 {
		t.Fatalf("hashes = %v, want nothing across accounts", got.Hashes)
	}
}

func TestStreamHashesValidation(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "mira", "device-a", "Device A")

	cases := []struct {
		name string
		path string
		want int
	}{
		{"no device", "/api/v2/changes/hashes?from=1&to=2", statusValidation},
		{"from below 1", hashesPath("device-a", 0, 2), http.StatusBadRequest},
		{"to below from", hashesPath("device-a", 5, 2), http.StatusBadRequest},
		{"from not a number", "/api/v2/changes/hashes?device=device-a&from=x&to=2", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireStatus(t, srv.send(t, http.MethodGet, tc.path, nil, bearer(token)), tc.want)
		})
	}
}

func TestStreamHashesRequireAuth(t *testing.T) {
	srv := newServer(t)
	requireStatus(t, srv.send(t, http.MethodGet, hashesPath("device-a", 1, 1), nil, nil),
		http.StatusUnauthorized)
}

// The range cap bounds one request; it must clamp rather than reject, so a
// client asking for a wide window still gets the part the relay will serve.
func TestStreamHashesRangeIsClamped(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "nina", "device-a", "Device A")

	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"),
		uploadHeaders(token, "device-a", 1)), http.StatusCreated)

	rec := srv.send(t, http.MethodGet, hashesPath("device-a", 1, maxHashRange*10), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)

	var got hashesResponse
	decode(t, rec, &got)
	if got.Hashes["1"] == "" {
		t.Fatal("clamping dropped the counters the relay does hold")
	}
}

// blobPath is the blob endpoint for one content id.
func blobPath(id string) string { return "/api/v2/blobs/" + id }

// fakeBlobID is a syntactically valid content id; the relay never checks that
// the bytes hash to it (it cannot — they are ciphertext).
func fakeBlobID(seed byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", seed), 32)
}

func TestBlobPutHeadGet(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "olga", "device-a", "Device A")
	id := fakeBlobID(0xab)

	// Absent: HEAD and GET both 404.
	requireStatus(t, srv.send(t, http.MethodHead, blobPath(id), nil, bearer(token)), http.StatusNotFound)
	requireStatus(t, srv.send(t, http.MethodGet, blobPath(id), nil, bearer(token)), http.StatusNotFound)

	payload := []byte("encrypted-attachment-bytes")
	rec := srv.send(t, http.MethodPut, blobPath(id), payload, bearer(token))
	requireStatus(t, rec, http.StatusCreated)

	// A second PUT is a no-op, whatever the body: the id fixes the bytes.
	rec = srv.send(t, http.MethodPut, blobPath(id), []byte("different"), bearer(token))
	requireStatus(t, rec, http.StatusOK)

	requireStatus(t, srv.send(t, http.MethodHead, blobPath(id), nil, bearer(token)), http.StatusOK)

	rec = srv.send(t, http.MethodGet, blobPath(id), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("blob = %q, want the first upload %q", rec.Body.Bytes(), payload)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestBlobValidation(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "pavel", "device-a", "Device A")

	requireStatus(t, srv.send(t, http.MethodPut, blobPath("not-a-hash"), []byte("x"), bearer(token)), statusValidation)
	requireStatus(t, srv.send(t, http.MethodGet, blobPath(strings.Repeat("A", 64)), nil, bearer(token)), statusValidation)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(fakeBlobID(1)), nil, bearer(token)), http.StatusBadRequest)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(fakeBlobID(1)), []byte("x"), nil), http.StatusUnauthorized)
}

func TestBlobTooLarge(t *testing.T) {
	srv := newServer(t)
	srv.cfg.MaxBlobSize = 16
	token := srv.registerAndLogin(t, "rita", "device-a", "Device A")

	rec := srv.send(t, http.MethodPut, blobPath(fakeBlobID(2)), bytes.Repeat([]byte("x"), 17), bearer(token))
	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
	requireStatus(t, srv.send(t, http.MethodHead, blobPath(fakeBlobID(2)), nil, bearer(token)), http.StatusNotFound)
}

func TestBlobsScopedToAccount(t *testing.T) {
	srv := newServer(t)
	tokenA := srv.registerAndLogin(t, "sara", "device-a", "Device A")
	tokenB := srv.registerAndLogin(t, "tom", "device-b", "Device B")
	id := fakeBlobID(3)

	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("sara's"), bearer(tokenA)), http.StatusCreated)
	// The same id under another account is a different blob.
	requireStatus(t, srv.send(t, http.MethodGet, blobPath(id), nil, bearer(tokenB)), http.StatusNotFound)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("tom's"), bearer(tokenB)), http.StatusCreated)
	rec := srv.send(t, http.MethodGet, blobPath(id), nil, bearer(tokenA))
	if !bytes.Equal(rec.Body.Bytes(), []byte("sara's")) {
		t.Fatalf("accounts leaked into each other: %q", rec.Body.Bytes())
	}
}

// The invariant: a packet declaring blobs is refused until they are held, so
// a pulled packet's references always resolve and undeclared blobs are safe to
// collect.
func TestPacketDeclaringMissingBlobRefused(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "uma", "device-a", "Device A")
	id := fakeBlobID(4)

	headers := uploadHeaders(token, "device-a", 1)
	headers["X-Noo-Blobs"] = id
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), headers)
	requireStatus(t, rec, http.StatusConflict)

	// Nothing was stored: the stream did not advance past a refused packet.
	rec = srv.send(t, http.MethodGet, "/api/v2/changes/vector", nil, bearer(token))
	var vector vectorResponse
	decode(t, rec, &vector)
	if vector.Vectors["device-a"] != 0 {
		t.Fatalf("vectors = %v, want nothing for device-a", vector.Vectors)
	}

	// Blob first, then the packet: accepted.
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("bytes"), bearer(token)), http.StatusCreated)
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), headers), http.StatusCreated)
}

func TestPacketBlobHeaderValidation(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "vera", "device-a", "Device A")

	headers := uploadHeaders(token, "device-a", 1)
	headers["X-Noo-Blobs"] = "not-a-hash"
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), headers), statusValidation)
}

// Pruning releases the pruned packets' references, and a blob nothing
// references any more goes with them — while a blob the snapshot declared
// survives, since that is what keeps the current attachments reachable.
func TestPruneCollectsUnreferencedBlobs(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "wanda", "device-a", "Device A")
	old := fakeBlobID(5)
	live := fakeBlobID(6)

	for _, id := range []string{old, live} {
		requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("b-"+id[:4]), bearer(token)), http.StatusCreated)
	}
	// Packet 1 references the old blob; packet 2 replaces it with the live one.
	h1 := uploadHeaders(token, "device-a", 1)
	h1["X-Noo-Blobs"] = old
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), h1), http.StatusCreated)
	h2 := uploadHeaders(token, "device-a", 2)
	h2["X-Noo-Blobs"] = live
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-2"), h2), http.StatusCreated)

	// Snapshot at 3 covering 1..2, declaring only the live blob.
	h3 := uploadHeaders(token, "device-a", 3)
	h3["X-Noo-Blobs"] = live
	h3["X-Noo-Snapshot-Covers"] = `{"device-a": 2}`
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"), h3)
	requireStatus(t, rec, http.StatusCreated)

	var upload uploadResponse
	decode(t, rec, &upload)
	if upload.Pruned == nil || upload.Pruned.Packets != 2 {
		t.Fatalf("pruned = %+v, want 2 packets", upload.Pruned)
	}
	if upload.Pruned.Blobs != 1 {
		t.Fatalf("pruned blobs = %d, want the one nothing references", upload.Pruned.Blobs)
	}
	requireStatus(t, srv.send(t, http.MethodHead, blobPath(old), nil, bearer(token)), http.StatusNotFound)
	requireStatus(t, srv.send(t, http.MethodHead, blobPath(live), nil, bearer(token)), http.StatusOK)
}

// A carrier may deliver a packet before its origin does, without a
// declaration; the origin's later declaration must still attach to the slot,
// or the blob would be collectable while a stored packet references it.
func TestLaterDeclarationAttachesToHeldSlot(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "xena", "device-a", "Device A")
	id := fakeBlobID(7)
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(id), []byte("bytes"), bearer(token)), http.StatusCreated)

	// Carried: no declaration.
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"),
		uploadHeaders(token, "device-a", 1)), http.StatusCreated)
	// Origin: same slot, declaring the blob. Already held → 200, refs recorded.
	h := uploadHeaders(token, "device-a", 1)
	h["X-Noo-Blobs"] = id
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("packet-1"), h), http.StatusOK)

	// A prune of something else must not collect it.
	h2 := uploadHeaders(token, "device-a", 2)
	h2["X-Noo-Snapshot-Covers"] = `{"device-b": 5}`
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snap"), h2), http.StatusCreated)
	requireStatus(t, srv.send(t, http.MethodHead, blobPath(id), nil, bearer(token)), http.StatusOK)
}

func TestUsageCountsBlobs(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "yuri", "device-a", "Device A")
	requireStatus(t, srv.send(t, http.MethodPut, blobPath(fakeBlobID(8)), bytes.Repeat([]byte("x"), 100), bearer(token)), http.StatusCreated)

	rec := srv.send(t, http.MethodGet, "/api/v2/changes/usage", nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)
	var usage store.Usage
	decode(t, rec, &usage)
	if usage.Blobs != 1 || usage.BlobBytes != 100 {
		t.Fatalf("usage blobs = %d/%d bytes, want 1/100", usage.Blobs, usage.BlobBytes)
	}
}

// ---------- Resource bounds ----------

// The /auth endpoints take no credential, so a JSON body must be bounded
// before it is decoded — whether or not the client declares its length.
func TestOversizedJSONBodyRejected(t *testing.T) {
	srv := newServer(t)
	huge := []byte(`{"username":"abc","password":"` + strings.Repeat("x", maxJSONBody) + `"}`)

	rec := srv.send(t, http.MethodPost, "/api/v2/auth/register", huge,
		map[string]string{"Content-Type": "application/json"})
	requireStatus(t, rec, http.StatusRequestEntityTooLarge)

	// Chunked: no Content-Length to reject up front, so the reader must stop it.
	req := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", bytes.NewReader(huge))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
}

// A pull page stops at the byte budget, and paging on has_more still delivers
// every packet, in per-device ascending order.
func TestPullPageRespectsByteBudget(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "bea", "device-a", "Device A")

	// Three packets of just over a third of the budget each: two fit, and
	// reaching the budget ends the page after the third.
	payload := bytes.Repeat([]byte("p"), pullPageBytes/3+1)
	for i := int64(1); i <= 4; i++ {
		rec := srv.send(t, http.MethodPost, "/api/v2/changes/", payload, uploadHeaders(token, "device-a", i))
		requireStatus(t, rec, http.StatusCreated)
	}

	var page pullResponse
	rec := srv.send(t, http.MethodGet, pullPath(nil, 1000), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &page)
	if got := counters(page); !equal(got, []int64{1, 2, 3}) || !page.HasMore {
		t.Fatalf("first page = %v has_more=%v, want [1 2 3] and more", got, page.HasMore)
	}

	rec = srv.send(t, http.MethodGet, pullPath(map[string]int64{"device-a": 3}, 1000), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &page)
	if got := counters(page); !equal(got, []int64{4}) || page.HasMore {
		t.Fatalf("second page = %v has_more=%v, want [4] and no more", got, page.HasMore)
	}
}

// A packet bigger than the whole budget is still served — alone — or a client
// could never get past it.
func TestPullServesOversizedPacketAlone(t *testing.T) {
	srv := newServer(t)
	srv.cfg.MaxPayloadSize = pullPageBytes + 1024
	token := srv.registerAndLogin(t, "cleo", "device-a", "Device A")

	big := bytes.Repeat([]byte("b"), pullPageBytes+1)
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", big, uploadHeaders(token, "device-a", 1)), http.StatusCreated)
	requireStatus(t, srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("small"), uploadHeaders(token, "device-a", 2)), http.StatusCreated)

	var page pullResponse
	rec := srv.send(t, http.MethodGet, pullPath(nil, 100), nil, bearer(token))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &page)
	if got := counters(page); !equal(got, []int64{1}) || !page.HasMore {
		t.Fatalf("page = %v has_more=%v, want [1] and more", got, page.HasMore)
	}
}

// The dashboard's stream counter is the stream's mark: a stream pruned to
// nothing still stands where it stopped, not at 0.
func TestAdminStreamCounterSurvivesPrune(t *testing.T) {
	srv := newServer(t)
	token := srv.registerAndLogin(t, "dora", "device-a", "Device A")
	srv.loginDevice(t, "dora", "device-b", "Device B", "linux")
	srv.fill(t, token, "device-b", 1, 3)

	// device-a's snapshot covers all of device-b, leaving its stream empty.
	rec := srv.send(t, http.MethodPost, "/api/v2/changes/", []byte("snapshot"),
		snapshotHeaders(token, "device-a", 1, map[string]int64{"device-b": 3}))
	requireStatus(t, rec, http.StatusCreated)

	var users []store.AdminUser
	rec = srv.send(t, http.MethodGet, "/api/v2/admin/users", nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &users)

	var devices []store.AdminDevice
	rec = srv.send(t, http.MethodGet,
		"/api/v2/admin/users/"+strconv.FormatInt(users[0].ID, 10)+"/devices", nil, bearer(srv.cfg.AdminToken))
	requireStatus(t, rec, http.StatusOK)
	decode(t, rec, &devices)

	got := map[string]int64{}
	for _, d := range devices {
		got[d.DeviceID] = d.StreamCounter
	}
	if got["device-a"] != 1 || got["device-b"] != 3 {
		t.Fatalf("stream counters = %v, want device-a:1 device-b:3", got)
	}
}
