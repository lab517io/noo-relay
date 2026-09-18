package config

import (
	"strings"
	"testing"
)

const (
	goodJWT   = "0123456789abcdef0123456789abcdef"
	goodAdmin = "fedcba9876543210fedcba9876543210"
)

func TestFromEnvRefusesShippedSecrets(t *testing.T) {
	t.Setenv("NOO_ADMIN_TOKEN", goodAdmin)
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "NOO_JWT_SECRET") {
		t.Fatalf("default JWT secret: err = %v, want a NOO_JWT_SECRET error", err)
	}

	t.Setenv("NOO_JWT_SECRET", goodJWT)
	t.Setenv("NOO_ADMIN_TOKEN", DefaultAdminToken)
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "NOO_ADMIN_TOKEN") {
		t.Fatalf("default admin token: err = %v, want a NOO_ADMIN_TOKEN error", err)
	}
}

func TestFromEnvRefusesShortSecrets(t *testing.T) {
	t.Setenv("NOO_JWT_SECRET", "too-short")
	t.Setenv("NOO_ADMIN_TOKEN", goodAdmin)
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short secret: err = %v, want a length error", err)
	}

	// An empty value is set, so it is not the sentinel — but it is short.
	t.Setenv("NOO_JWT_SECRET", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestFromEnvAcceptsRealSecrets(t *testing.T) {
	t.Setenv("NOO_JWT_SECRET", goodJWT)
	t.Setenv("NOO_ADMIN_TOKEN", goodAdmin)
	if _, err := FromEnv(); err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
}

func TestInsecureDevAllowsDefaults(t *testing.T) {
	t.Setenv("NOO_INSECURE_DEV", "1")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if jwt, admin := c.UsesDefaultSecrets(); !jwt || !admin {
		t.Fatal("expected the shipped defaults in insecure dev mode")
	}
}

func withSecrets(t *testing.T) {
	t.Setenv("NOO_JWT_SECRET", goodJWT)
	t.Setenv("NOO_ADMIN_TOKEN", goodAdmin)
}

func TestRegistrationSetting(t *testing.T) {
	withSecrets(t)
	c, err := FromEnv()
	if err != nil || c.OpenRegistration {
		t.Fatalf("default: open=%v err=%v, want closed", c != nil && c.OpenRegistration, err)
	}
	t.Setenv("NOO_REGISTRATION", "open")
	if c, err = FromEnv(); err != nil || !c.OpenRegistration {
		t.Fatalf("open: err=%v", err)
	}
	t.Setenv("NOO_REGISTRATION", "yes")
	if _, err = FromEnv(); err == nil {
		t.Fatal("NOO_REGISTRATION=yes accepted")
	}
}

func TestTrustedProxiesParse(t *testing.T) {
	withSecrets(t)
	t.Setenv("NOO_TRUSTED_PROXIES", "127.0.0.1, ::1,10.0.0.0/8")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if len(c.TrustedProxies) != 3 || c.TrustedProxies[0].String() != "127.0.0.1/32" ||
		c.TrustedProxies[1].String() != "::1/128" || c.TrustedProxies[2].String() != "10.0.0.0/8" {
		t.Fatalf("TrustedProxies = %v", c.TrustedProxies)
	}
	t.Setenv("NOO_TRUSTED_PROXIES", "not-an-ip")
	if _, err := FromEnv(); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestNegativeLimitsRejected(t *testing.T) {
	withSecrets(t)
	t.Setenv("NOO_USER_QUOTA_BYTES", "-1")
	if _, err := FromEnv(); err == nil {
		t.Fatal("negative quota accepted")
	}
}
