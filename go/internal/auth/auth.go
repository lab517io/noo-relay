// Package auth issues and validates the relay's JWTs and hashes passwords.
//
// Both are wire-compatible with the Python implementation: the same secret
// validates tokens minted by either service, and a bcrypt hash written by one
// verifies under the other.
package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// bcrypt considers only the first 72 bytes of its input and errors on longer
// ones. Truncating explicitly — on bytes, exactly as Python's
// password.encode("utf-8")[:72] does — keeps hashing and verifying consistent
// and never fails on a long passphrase.
const bcryptMaxBytes = 72

func bcryptInput(password string) []byte {
	b := []byte(password)
	if len(b) > bcryptMaxBytes {
		b = b[:bcryptMaxBytes]
	}
	return b
}

func HashPassword(password string, cost int) (string, error) {
	h, err := bcrypt.GenerateFromPassword(bcryptInput(password), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), bcryptInput(password)) == nil
}

// DummyHash is a hash of an unguessable value at the given cost, for logins
// against a username that does not exist.
//
// Answering those with the same body as a wrong password is not enough on its
// own: skipping bcrypt when there is no user to verify against turns the
// response time into a username oracle — microseconds against the ~200ms a
// real verification costs at cost 12. Verifying the supplied password against
// this hash instead always fails, and fails at the same price.
func DummyHash(cost int) string {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Only reachable if the system CSPRNG is broken. The value never
		// needs to be secret — it needs to be one no password can match, and
		// a hash of a fixed string is still that.
		secret = []byte("noo-relay-dummy-credential")
	}
	h, err := HashPassword(string(secret), cost)
	if err != nil {
		// An out-of-range cost; config rejects those at startup, so this is
		// belt and braces. A hash at the default cost still runs bcrypt.
		h, _ = HashPassword(string(secret), bcrypt.DefaultCost)
	}
	return h
}

// Token types. A refresh token is not accepted where an access token is
// required, and vice versa.
const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

var ErrInvalidToken = errors.New("invalid or expired token")

type Claims struct {
	UserID   int64
	DeviceID string
	Type     string
}

type Issuer struct {
	secret        []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func NewIssuer(secret string, accessMinutes, refreshDays int) *Issuer {
	return &Issuer{
		secret:        []byte(secret),
		accessExpiry:  time.Duration(accessMinutes) * time.Minute,
		refreshExpiry: time.Duration(refreshDays) * 24 * time.Hour,
	}
}

func (i *Issuer) AccessToken(userID int64, deviceID string) (string, error) {
	return i.sign(userID, deviceID, TypeAccess, i.accessExpiry)
}

func (i *Issuer) RefreshToken(userID int64, deviceID string) (string, error) {
	return i.sign(userID, deviceID, TypeRefresh, i.refreshExpiry)
}

func (i *Issuer) sign(userID int64, deviceID, tokenType string, expiry time.Duration) (string, error) {
	// "sub" is a string: python-jose rejects a numeric subject, and tokens
	// must stay readable by both implementations.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       fmt.Sprintf("%d", userID),
		"device_id": deviceID,
		"type":      tokenType,
		"exp":       time.Now().Add(expiry).Unix(),
	})
	return token.SignedString(i.secret)
}

// Decode validates the signature and expiry and returns the claims.
func (i *Issuer) Decode(raw string) (*Claims, error) {
	var claims jwt.MapClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		return i.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, ErrInvalidToken
	}

	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return nil, ErrInvalidToken
	}
	// ParseInt, not Sscanf: Sscanf("%d") stops at the first non-digit and
	// would read "12abc" as user 12.
	userID, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	deviceID, _ := claims["device_id"].(string)
	if deviceID == "" {
		return nil, ErrInvalidToken
	}
	tokenType, _ := claims["type"].(string)

	return &Claims{UserID: userID, DeviceID: deviceID, Type: tokenType}, nil
}
