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

func TestAIServiceIsOptInAndNeedsAToken(t *testing.T) {
	t.Setenv("ARGUS_AI_SERVICE_URL", "")
	t.Setenv("ARGUS_AI_SERVICE_TOKEN", "")
	cfg := Load()
	if cfg.AIServiceURL != "" || cfg.AIServiceToken != "" {
		t.Fatalf("AI defaults url=%q token=%q; want both empty", cfg.AIServiceURL, cfg.AIServiceToken)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("AI disabled should be valid: %v", err)
	}
	t.Setenv("ARGUS_AI_SERVICE_URL", "http://argus-ai:8090/")
	if err := Load().Validate(); err == nil {
		t.Fatal("an AI URL without a token was accepted")
	}
	t.Setenv("ARGUS_AI_SERVICE_TOKEN", "secret")
	cfg = Load()
	if err := cfg.Validate(); err != nil || cfg.AIServiceURL != "http://argus-ai:8090" {
		t.Fatalf("url=%q err=%v", cfg.AIServiceURL, err)
	}
}
