package config

import (
	"reflect"
	"testing"
	"time"
)

func TestLoadOIDCConfiguration(t *testing.T) {
	t.Setenv("ARGUS_OIDC_ISSUER_URL", "https://identity.example.test/realms/argus/")
	t.Setenv("ARGUS_OIDC_AUDIENCE", "payments-control-plane")
	t.Setenv("ARGUS_OIDC_JWKS_URL", "https://identity.example.test/certs")
	t.Setenv("ARGUS_OIDC_ROLE_CLAIM", "groups")
	t.Setenv("ARGUS_OIDC_ROLE_MAPPINGS", "sre-admin=admin,sre-oncall=operator")
	t.Setenv("ARGUS_OIDC_SIGNING_ALGS", "RS256, ES256")
	t.Setenv("ARGUS_OIDC_DISCOVERY_TIMEOUT", "7s")
	t.Setenv("ARGUS_OIDC_PROVIDER_TIMEOUT", "2s")

	cfg := Load()
	if cfg.OIDCIssuerURL != "https://identity.example.test/realms/argus" {
		t.Fatalf("issuer=%q", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCAudience != "payments-control-plane" || cfg.OIDCRoleClaim != "groups" {
		t.Fatalf("unexpected OIDC config: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.OIDCSigningAlgs, []string{"RS256", "ES256"}) {
		t.Fatalf("signing algorithms=%v", cfg.OIDCSigningAlgs)
	}
	if cfg.OIDCDiscoveryTimeout != 7*time.Second || cfg.OIDCProviderTimeout != 2*time.Second {
		t.Fatalf("unexpected OIDC timeouts: discovery=%s provider=%s", cfg.OIDCDiscoveryTimeout, cfg.OIDCProviderTimeout)
	}
}
