// Package config carries the relay's settings, read once from NOO_-prefixed
// environment variables. The names and defaults are part of the deployment
// contract — they are what /etc/noo-sync.env on the server sets — and must not
// drift.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

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

	// OpenRegistration lets anyone who can reach the relay create an account
	// through POST /auth/register. Off by default (NOO_REGISTRATION=closed):
	// accounts are then created by the operator, from the admin dashboard.
	OpenRegistration bool

	// Storage limits, all enforced on new data only — a re-upload of what
	// is already held is never refused. 0 disables each.
	//
	// UserQuotaBytes caps one account's packets plus blobs.
	UserQuotaBytes int64
	// MaxStreamsPerUser caps the distinct origin-device streams in one
	// account. Origins need not be registered devices (gossip), so without
	// a cap a client could open streams without end.
	MaxStreamsPerUser int64
	// MinFreeDiskBytes refuses uploads that would leave less than this free
	// on the database's filesystem, so one account cannot fill the disk
	// the database itself needs to keep working.
	MinFreeDiskBytes int64

	// AuthRatePerMinute is the per-client-IP budget for /auth/login and
	// /auth/register together. 0 disables it.
	AuthRatePerMinute int
	// MaxConcurrentHashes bounds bcrypt work in flight, so a flood of logins
	// cannot take every CPU from sync traffic.
	MaxConcurrentHashes int
	// TrustedProxies are the peers whose X-Forwarded-For is believed when
	// working out a client's IP for rate limiting. Empty: the TCP peer is
	// the client.
	TrustedProxies []netip.Prefix
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
		MaxStreamsPerUser:        256,
		MinFreeDiskBytes:         256 * 1024 * 1024,
		AuthRatePerMinute:        20,
		MaxConcurrentHashes:      runtime.NumCPU(),
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
		func() error { return num("NOO_USER_QUOTA_BYTES", func(n int64) { c.UserQuotaBytes = n }) },
		func() error { return num("NOO_MAX_STREAMS_PER_USER", func(n int64) { c.MaxStreamsPerUser = n }) },
		func() error { return num("NOO_MIN_FREE_DISK_BYTES", func(n int64) { c.MinFreeDiskBytes = n }) },
		func() error {
			return num("NOO_AUTH_RATE_PER_MINUTE", func(n int64) { c.AuthRatePerMinute = int(n) })
		},
		func() error {
			return num("NOO_MAX_CONCURRENT_HASHES", func(n int64) { c.MaxConcurrentHashes = int(n) })
		},
	} {
		if err := f(); err != nil {
			return nil, err
		}
	}

	switch v := os.Getenv("NOO_REGISTRATION"); v {
	case "", "closed":
		c.OpenRegistration = false
	case "open":
		c.OpenRegistration = true
	default:
		return nil, fmt.Errorf("NOO_REGISTRATION: must be open or closed, got %q", v)
	}

	if raw := os.Getenv("NOO_TRUSTED_PROXIES"); raw != "" {
		proxies, err := parsePrefixes(raw)
		if err != nil {
			return nil, fmt.Errorf("NOO_TRUSTED_PROXIES: %w", err)
		}
		c.TrustedProxies = proxies
	}

	for _, lim := range []struct {
		name  string
		value int64
	}{
		{"NOO_USER_QUOTA_BYTES", c.UserQuotaBytes},
		{"NOO_MAX_STREAMS_PER_USER", c.MaxStreamsPerUser},
		{"NOO_MIN_FREE_DISK_BYTES", c.MinFreeDiskBytes},
		{"NOO_AUTH_RATE_PER_MINUTE", int64(c.AuthRatePerMinute)},
	} {
		if lim.value < 0 {
			return nil, fmt.Errorf("%s: must be 0 (off) or positive, got %d", lim.name, lim.value)
		}
	}
	if c.MaxConcurrentHashes < 1 {
		return nil, fmt.Errorf("NOO_MAX_CONCURRENT_HASHES: must be positive, got %d", c.MaxConcurrentHashes)
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

// parsePrefixes reads a comma-separated list of IPs and CIDR prefixes. A bare
// IP is a single-address prefix.
func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP or CIDR prefix", item)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR prefix", item)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}
