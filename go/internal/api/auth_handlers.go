package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lab517/noo-relay/internal/auth"
	"github.com/lab517/noo-relay/internal/store"
)

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// credentialRules are the Pydantic constraints from the Python RegisterRequest.
func credentialRules(username, password string) []fieldRule {
	return []fieldRule{
		{name: "username", value: username, required: true, min: 3, max: 50},
		{name: "password", value: password, required: true, min: 8, max: 128},
	}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	// Closed is the default: accounts come from the admin dashboard, and
	// nothing about the request matters — not even whether the name is free.
	if !s.cfg.OpenRegistration {
		writeError(w, http.StatusForbidden, "Registration is closed")
		return
	}
	if !s.allowAuth(w, r) {
		return
	}
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
	_, err := s.createUser(r, body.Username, body.Password)
	release()
	if err != nil {
		if errors.Is(err, store.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "Username already exists")
			return
		}
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "User registered successfully"})
}

// createUser hashes and stores a new account. The caller holds a hash slot.
func (s *Server) createUser(r *http.Request, username, password string) (int64, error) {
	hash, err := auth.HashPassword(password, s.cfg.BcryptCost)
	if err != nil {
		return 0, err
	}
	return s.store.CreateUser(r.Context(), username, hash, store.Now())
}

// login verifies the credentials and registers (or refreshes) the calling
// device in one step, so a client only needs this one call to come online.
//
// Guessing is bounded three ways: per client IP (allowAuth), per username
// (a backoff that doubles after five failures, which spreading guesses over
// many addresses does not escape), and by the bcrypt slots every
// verification must take. The backoff is keyed on the name as sent, whether
// or not it exists, so a 429 says nothing about which usernames are real.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowAuth(w, r) {
		return
	}
	var body loginRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if !validateFields(w,
		fieldRule{name: "username", value: body.Username, required: true},
		fieldRule{name: "password", value: body.Password, required: true},
		fieldRule{name: "device_id", value: body.DeviceID, required: true},
		fieldRule{name: "device_name", value: body.DeviceName, required: true},
	) {
		return
	}

	if wait := s.limits.login.Wait(body.Username, time.Now()); wait > 0 {
		writeTooMany(w, wait)
		return
	}

	user, err := s.store.UserByUsername(r.Context(), body.Username)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	// A missing user and a wrong password are reported identically, and must
	// also take the same time to report: returning before bcrypt runs would
	// make the response time disclose which usernames exist, whatever the body
	// says. The dummy verification is there to be paid for, and never succeeds.
	release, ok := s.acquireHash(w, r)
	if !ok {
		return
	}
	authenticated := false
	if user != nil {
		authenticated = auth.VerifyPassword(body.Password, user.PasswordHash)
	} else {
		auth.VerifyPassword(body.Password, s.dummyHash)
	}
	release()
	if !authenticated {
		s.limits.login.Fail(body.Username, time.Now())
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	s.limits.login.Succeed(body.Username)

	if err := s.store.UpsertDevice(r.Context(), user.ID, body.DeviceID, body.DeviceName, body.Platform, store.Now()); err != nil {
		writeServerError(w, r, err)
		return
	}
	s.issueTokens(w, r, user.ID, body.DeviceID)
}

// refresh mints a new token pair. It re-checks that the token's device still
// exists, so a deleted device cannot keep minting fresh tokens forever.
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var body refreshRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if !validateFields(w, fieldRule{name: "refresh_token", value: body.RefreshToken, required: true}) {
		return
	}

	claims, err := s.issuer.Decode(body.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}
	if claims.Type != auth.TypeRefresh {
		writeError(w, http.StatusUnauthorized, "Invalid token type")
		return
	}

	known, err := s.store.DeviceBelongsToUser(r.Context(), claims.UserID, claims.DeviceID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	if !known {
		writeError(w, http.StatusUnauthorized, "User or device no longer exists")
		return
	}
	s.issueTokens(w, r, claims.UserID, claims.DeviceID)
}

func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, userID int64, deviceID string) {
	access, err := s.issuer.AccessToken(userID, deviceID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	refreshToken, err := s.issuer.RefreshToken(userID, deviceID)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
	})
}
