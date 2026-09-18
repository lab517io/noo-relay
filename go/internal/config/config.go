// Package config carries the relay's settings, read once from NOO_-prefixed
// environment variables. The names and defaults are part of the deployment
// contract — they are what /etc/noo-sync.env on the server sets — and must not
// drift.
package config

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

// Sentinel values shipped in the defaults. Running with either of these means
// anyone who reads the source can forge tokens or reach the admin API, so
// FromEnv refuses them unless NOO_INSECURE_DEV is set.
const (
	DefaultJWTSecret  = "change-me-in-production"
	DefaultAdminToken = "change-me-admin-token"
)

// MinSecretLength is the shortest NOO_JWT_SECRET or NOO_ADMIN_TOKEN accepted:
// 32 characters, the length of 16 random bytes in hex. Anything shorter is a
// password someone typed, not a secret, and HS256 tokens signed with a short
// key can be brute-forced offline from any one token.
const MinSecretLength = 32

type Config struct {
	DatabaseURL              string
	JWTSecret                string
	JWTAlgorithm             string
	AccessTokenExpireMinutes int
	RefreshTokenExpireDays   int
	MaxPayloadSize           int64
	// MaxBlobSize bounds one attachment blob (docs/P2P_SYNC.md §3.5).
	// Separate from MaxPayloadSize: packets are now small by construction,
	// while a blob is a whole voice memo or image.
	MaxBlobSize int64
	AdminToken  string

	// InsecureDev accepts the shipped sentinel secrets, for running locally.
	// Never set on a reachable server.
	InsecureDev bool

	// BcryptCost is the work factor for password hashing. 12 matches Python's
	// bcrypt.gensalt() default, so hashes stay verifiable by either
	// implementation against the same database. Tests lower it for speed.
	BcryptCost int

	// StaticDir holds the admin dashboard. It lives at the repository root,
	// outside this module, so it is a path rather than an embedded FS.
	StaticDir string

	ListenAddr  string
	TLSCertFile string
	TLSKeyFile  string
}

func Default() *Config {
	return &Config{
		DatabaseURL:              "noo_sync.db",
		JWTSecret:                DefaultJWTSecret,
		JWTAlgorithm:             "HS256",
		AccessTokenExpireMinutes: 15,
		RefreshTokenExpireDays:   30,
		MaxPayloadSize:           10 * 1024 * 1024,
		MaxBlobSize:              64 * 1024 * 1024,
		AdminToken:               DefaultAdminToken,
		BcryptCost:               12,
		StaticDir:                "static",
		ListenAddr:               "0.0.0.0:8080",
	}
}

// FromEnv layers the NOO_* environment over the defaults.
func FromEnv() (*Config, error) {
	c := Default()

	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	num := func(key string, set func(int64)) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: %q is not an integer", key, v)
		}
		set(n)
		return nil
	}

	str("NOO_DATABASE_URL", &c.DatabaseURL)
	str("NOO_JWT_SECRET", &c.JWTSecret)
	str("NOO_JWT_ALGORITHM", &c.JWTAlgorithm)
	str("NOO_ADMIN_TOKEN", &c.AdminToken)
	str("NOO_STATIC_DIR", &c.StaticDir)
	str("NOO_LISTEN_ADDR", &c.ListenAddr)
	str("NOO_TLS_CERT_FILE", &c.TLSCertFile)
	str("NOO_TLS_KEY_FILE", &c.TLSKeyFile)

	for _, f := range []func() error{
		func() error {
			return num("NOO_ACCESS_TOKEN_EXPIRE_MINUTES", func(n int64) { c.AccessTokenExpireMinutes = int(n) })
		},
		func() error {
			return num("NOO_REFRESH_TOKEN_EXPIRE_DAYS", func(n int64) { c.RefreshTokenExpireDays = int(n) })
		},
		func() error { return num("NOO_MAX_PAYLOAD_SIZE", func(n int64) { c.MaxPayloadSize = n }) },
		func() error { return num("NOO_MAX_BLOB_SIZE", func(n int64) { c.MaxBlobSize = n }) },
		func() error { return num("NOO_BCRYPT_COST", func(n int64) { c.BcryptCost = int(n) }) },
	} {
		if err := f(); err != nil {
			return nil, err
		}
	}

	if c.JWTAlgorithm != "HS256" {
		return nil, fmt.Errorf("NOO_JWT_ALGORITHM: only HS256 is supported, got %q", c.JWTAlgorithm)
	}
	// bcrypt silently substitutes its default (10) for any cost below MinCost,
	// so an out-of-range setting would quietly hash weaker than the 12 this
	// deployment expects instead of saying so.
	if c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost {
		return nil, fmt.Errorf("NOO_BCRYPT_COST: must be between %d and %d, got %d",
			bcrypt.MinCost, bcrypt.MaxCost, c.BcryptCost)
	}
	if c.MaxPayloadSize < 1 {
		return nil, fmt.Errorf("NOO_MAX_PAYLOAD_SIZE: must be positive, got %d", c.MaxPayloadSize)
	}
	if c.MaxBlobSize < 1 {
		return nil, fmt.Errorf("NOO_MAX_BLOB_SIZE: must be positive, got %d", c.MaxBlobSize)
	}

	c.InsecureDev = os.Getenv("NOO_INSECURE_DEV") == "1"
	if err := c.checkSecrets(); err != nil {
		return nil, err
	}
	return c, nil
}

// checkSecrets fails closed on the shipped sentinels and on short secrets. A
// warning in the log is not enough: a relay started from a copied command line
// without its env file would otherwise accept forged tokens for every account
// until someone happened to read the log.
func (c *Config) checkSecrets() error {
	if c.InsecureDev {
		return nil
	}
	for _, s := range []struct{ name, value, sentinel string }{
		{"NOO_JWT_SECRET", c.JWTSecret, DefaultJWTSecret},
		{"NOO_ADMIN_TOKEN", c.AdminToken, DefaultAdminToken},
	} {
		if s.value == s.sentinel {
			return fmt.Errorf("%s is unset or still the shipped default; generate one "+
				"(openssl rand -hex 32), or set NOO_INSECURE_DEV=1 for local development", s.name)
		}
		if len(s.value) < MinSecretLength {
			return fmt.Errorf("%s must be at least %d characters, got %d",
				s.name, MinSecretLength, len(s.value))
		}
	}
	return nil
}

// UsesDefaultSecrets reports which shipped defaults are still in place.
func (c *Config) UsesDefaultSecrets() (jwt, admin bool) {
	return c.JWTSecret == DefaultJWTSecret, c.AdminToken == DefaultAdminToken
}
