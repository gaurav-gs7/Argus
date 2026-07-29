package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	testIssuer   = "https://identity.example.test/realms/argus"
	testAudience = "argus-api"
)

func TestOIDCAuthenticatorValidatesJWTAndMapsNestedRoleClaim(t *testing.T) {
	authn, privateKey := newTestAuthenticator(t)
	token := signToken(t, privateKey, map[string]any{
		"iss":                testIssuer,
		"sub":                "user-123",
		"aud":                testAudience,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"email":              "viewer@example.test",
		"preferred_username": "viewer",
		"realm_access": map[string]any{
			"roles": []string{"offline_access", "argus-viewer"},
		},
	})

	principal, err := authn.Authenticate(context.Background(), "bearer "+token)
	if err != nil {
		t.Fatalf("expected token to authenticate: %v", err)
	}
	if principal.Role != RoleViewer || principal.Email != "viewer@example.test" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if principal.ID != testIssuer+"#user-123" {
		t.Fatalf("principal ID must be issuer-scoped subject, got %q", principal.ID)
	}
}

func TestOIDCDiscoveryAndJWKSKeyRotation(t *testing.T) {
	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu        sync.RWMutex
		activeKey = &firstKey.PublicKey
		activeKID = "key-1"
		issuer    string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/keys",
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			mu.RLock()
			key, kid := activeKey, activeKID
			mu.RUnlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{rsaJWK(key, kid)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	authn, err := NewOIDCAuthenticator(context.Background(), OIDCConfig{
		IssuerURL:         issuer,
		Audience:          testAudience,
		RoleMappings:      "argus-operator=operator",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("OIDC discovery failed: %v", err)
	}
	firstToken := signTokenWithKID(t, firstKey, "key-1", validClaims(map[string]any{"iss": issuer}))
	if _, err := authn.Authenticate(context.Background(), "Bearer "+firstToken); err != nil {
		t.Fatalf("first JWKS key should verify: %v", err)
	}

	mu.Lock()
	activeKey = &secondKey.PublicKey
	activeKID = "key-2"
	mu.Unlock()
	rotatedToken := signTokenWithKID(t, secondKey, "key-2", validClaims(map[string]any{"iss": issuer}))
	if _, err := authn.Authenticate(context.Background(), "Bearer "+rotatedToken); err != nil {
		t.Fatalf("rotated JWKS key should be fetched and verify: %v", err)
	}
}

func TestOIDCAuthenticatorRejectsInvalidSecurityClaims(t *testing.T) {
	authn, privateKey := newTestAuthenticator(t)
	now := time.Now()
	missingExpiry := validClaims(nil)
	delete(missingExpiry, "exp")
	tests := []struct {
		name   string
		claims map[string]any
		reason string
	}{
		{
			name: "wrong issuer",
			claims: validClaims(map[string]any{
				"iss": "https://attacker.example.test",
			}),
			reason: "invalid_token",
		},
		{
			name: "wrong audience",
			claims: validClaims(map[string]any{
				"aud": "different-api",
			}),
			reason: "invalid_token",
		},
		{
			name: "expired",
			claims: validClaims(map[string]any{
				"exp": now.Add(-time.Minute).Unix(),
			}),
			reason: "invalid_token",
		},
		{
			name:   "missing expiry",
			claims: missingExpiry,
			reason: "invalid_token",
		},
		{
			name: "not valid yet",
			claims: validClaims(map[string]any{
				"nbf": now.Add(10 * time.Minute).Unix(),
			}),
			reason: "invalid_token",
		},
		{
			name: "issued in the future",
			claims: validClaims(map[string]any{
				"iat": now.Add(10 * time.Minute).Unix(),
			}),
			reason: "invalid_token",
		},
		{
			name: "missing subject",
			claims: validClaims(map[string]any{
				"sub": "",
			}),
			reason: "missing_subject",
		},
		{
			name: "unmapped role",
			claims: validClaims(map[string]any{
				"realm_access": map[string]any{"roles": []string{"finance-admin"}},
			}),
			reason: "unmapped_role",
		},
		{
			name: "conflicting roles",
			claims: validClaims(map[string]any{
				"realm_access": map[string]any{"roles": []string{"argus-admin", "argus-viewer"}},
			}),
			reason: "ambiguous_role",
		},
		{
			name: "missing role claim",
			claims: validClaims(map[string]any{
				"realm_access": map[string]any{},
			}),
			reason: "missing_role_claim",
		},
		{
			name: "empty role list",
			claims: validClaims(map[string]any{
				"realm_access": map[string]any{"roles": []string{}},
			}),
			reason: "missing_role_claim",
		},
		{
			name: "mixed-type role list",
			claims: validClaims(map[string]any{
				"realm_access": map[string]any{"roles": []any{"argus-operator", 7}},
			}),
			reason: "missing_role_claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signToken(t, privateKey, tt.claims)
			_, err := authn.Authenticate(context.Background(), "Bearer "+token)
			if err == nil {
				t.Fatal("expected authentication to fail")
			}
			if got := FailureReason(err); got != tt.reason {
				t.Fatalf("failure reason=%q, want %q (error=%v)", got, tt.reason, err)
			}
		})
	}
}

func TestOIDCAuthenticatorSupportsStandardAudienceAndRoleClaimShapes(t *testing.T) {
	authn, privateKey := newTestAuthenticator(t)
	tests := []struct {
		name       string
		audience   any
		roleClaims any
	}{
		{name: "audience array and role array", audience: []string{"another-api", testAudience}, roleClaims: []string{"argus-operator"}},
		{name: "single audience and role string", audience: testAudience, roleClaims: "argus-operator"},
		{name: "multiple external roles mapping to one role", audience: testAudience, roleClaims: []string{"argus-operator", "sre-oncall"}},
	}

	verifier := oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&privateKey.PublicKey},
	}, &oidc.Config{
		ClientID:             testAudience,
		SupportedSigningAlgs: []string{"RS256"},
	})
	authn, err := newOIDCAuthenticator(verifier, OIDCConfig{
		RoleClaim:    "realm_access.roles",
		RoleMappings: "argus-operator=operator,sre-oncall=operator",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signToken(t, privateKey, validClaims(map[string]any{
				"aud": tt.audience,
				"realm_access": map[string]any{
					"roles": tt.roleClaims,
				},
			}))
			principal, err := authn.Authenticate(context.Background(), "Bearer "+token)
			if err != nil {
				t.Fatalf("expected supported claim shape to authenticate: %v", err)
			}
			if principal.Role != RoleOperator {
				t.Fatalf("role=%q, want operator", principal.Role)
			}
		})
	}
}

func TestOIDCAuthenticatorUsesConfiguredClaimsAndSafePresentationFallbacks(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&privateKey.PublicKey},
	}, &oidc.Config{ClientID: testAudience, SupportedSigningAlgs: []string{"RS256"}})
	authn, err := newOIDCAuthenticator(verifier, OIDCConfig{
		RoleClaim:        "groups",
		RoleMappings:     "platform-oncall=operator",
		EmailClaim:       "work_email",
		DisplayNameClaim: "full_name",
	})
	if err != nil {
		t.Fatal(err)
	}

	token := signToken(t, privateKey, validClaims(map[string]any{
		"groups":     []string{"platform-oncall"},
		"work_email": "  oncall@example.test  ",
		"full_name":  42,
	}))
	principal, err := authn.Authenticate(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("expected custom claims to authenticate: %v", err)
	}
	if principal.Email != "oncall@example.test" || principal.DisplayName != "oncall@example.test" {
		t.Fatalf("unexpected presentation claims: %+v", principal)
	}
	if principal.ID != testIssuer+"#user-123" {
		t.Fatalf("presentation claims must not affect principal ID: %+v", principal)
	}
}

func TestOIDCAuthenticatorRejectsTokenSignedByUnknownKey(t *testing.T) {
	authn, _ := newTestAuthenticator(t)
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, attackerKey, validClaims(nil))
	if _, err := authn.Authenticate(context.Background(), "Bearer "+token); FailureReason(err) != "invalid_token" {
		t.Fatalf("unknown signing key must fail token verification, got %v", err)
	}
}

func TestOIDCAuthenticatorRequiresBearerScheme(t *testing.T) {
	authn, _ := newTestAuthenticator(t)
	for _, header := range []string{"", "Basic abc", "Bearer", "Bearer one two"} {
		if _, err := authn.Authenticate(context.Background(), header); FailureReason(err) != "missing_bearer_token" {
			t.Fatalf("header %q must fail closed, got %v", header, err)
		}
	}
}

func TestBearerSchemeIsCaseInsensitiveAndWhitespaceTolerant(t *testing.T) {
	for _, header := range []string{"Bearer token", "bearer token", "BEARER token", "\tBearer\ttoken  "} {
		token, err := parseBearerToken(header)
		if err != nil || token != "token" {
			t.Fatalf("header %q parsed as token=%q err=%v", header, token, err)
		}
	}
}

func FuzzBearerTokenParser(f *testing.F) {
	for _, seed := range []string{
		"",
		"Bearer",
		"Bearer token",
		"bearer token",
		"Basic token",
		"Bearer one two",
		"Bearer token\nInjected: value",
		string([]byte{0x00, 0xff, 0x7f}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		token, err := parseBearerToken(header)
		if err != nil {
			return
		}
		fields := strings.Fields(header)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" || token != fields[1] {
			t.Fatalf("parser accepted malformed header %q as %q", header, token)
		}
	})
}

func FuzzRoleMappingParser(f *testing.F) {
	for _, seed := range []string{
		"",
		"argus-admin=admin",
		"argus-admin=owner",
		"argus-admin=admin,argus-viewer=viewer",
		"duplicate=viewer,duplicate=admin",
		"provider-role=",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		mappings, err := parseRoleMappings(raw)
		if err != nil {
			return
		}
		if len(mappings) == 0 {
			t.Fatal("parser accepted an empty mapping")
		}
		for externalRole, role := range mappings {
			if strings.TrimSpace(externalRole) == "" || !validRole(role) {
				t.Fatalf("parser returned invalid mapping %q=%q", externalRole, role)
			}
		}
	})
}

func TestRoleMappingsMustBeExplicitAndUnambiguous(t *testing.T) {
	verifier := oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: testAudience})
	for _, mappings := range []string{"", "argus-admin", "argus-admin=owner", "argus-admin=admin,argus-admin=viewer"} {
		if _, err := newOIDCAuthenticator(verifier, OIDCConfig{RoleMappings: mappings}); err == nil {
			t.Fatalf("mapping %q should be rejected", mappings)
		}
	}
}

func TestOIDCConfigurationRequiresSecureURLsAndAsymmetricAlgorithms(t *testing.T) {
	base := OIDCConfig{
		IssuerURL:    "https://identity.example.test/realms/argus",
		Audience:     testAudience,
		JWKSURL:      "https://identity.example.test/realms/argus/certs",
		RoleMappings: "argus-viewer=viewer",
	}

	insecure := base
	insecure.IssuerURL = "http://identity.example.test/realms/argus"
	if _, err := NewOIDCAuthenticator(context.Background(), insecure); err == nil {
		t.Fatal("non-local HTTP issuer must be rejected")
	}

	insecure.AllowInsecureHTTP = true
	insecure.JWKSURL = "http://identity.example.test/realms/argus/certs"
	if _, err := NewOIDCAuthenticator(context.Background(), insecure); err != nil {
		t.Fatalf("explicit local HTTP mode should be accepted: %v", err)
	}

	symmetric := base
	symmetric.SigningAlgs = []string{"HS256"}
	if _, err := NewOIDCAuthenticator(context.Background(), symmetric); err == nil {
		t.Fatal("symmetric JWT algorithms must be rejected")
	}

	none := base
	none.SigningAlgs = []string{"none"}
	if _, err := NewOIDCAuthenticator(context.Background(), none); err == nil {
		t.Fatal("unsigned JWTs must be rejected")
	}
}

func TestOIDCConfigurationRejectsMalformedRoleClaimPath(t *testing.T) {
	verifier := oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: testAudience})
	if _, err := newOIDCAuthenticator(verifier, OIDCConfig{
		RoleClaim:    "realm_access..roles",
		RoleMappings: "argus-viewer=viewer",
	}); err == nil {
		t.Fatal("empty claim path segment must be rejected")
	}
}

func TestOIDCConfigurationFailsClosedForMissingAndMalformedValues(t *testing.T) {
	base := OIDCConfig{
		IssuerURL:    "https://identity.example.test/realms/argus",
		Audience:     testAudience,
		JWKSURL:      "https://identity.example.test/realms/argus/certs",
		RoleMappings: "argus-viewer=viewer",
	}
	tests := []struct {
		name   string
		mutate func(*OIDCConfig)
	}{
		{name: "missing issuer", mutate: func(cfg *OIDCConfig) { cfg.IssuerURL = "" }},
		{name: "missing audience", mutate: func(cfg *OIDCConfig) { cfg.Audience = "" }},
		{name: "issuer user info", mutate: func(cfg *OIDCConfig) { cfg.IssuerURL = "https://user@identity.example.test/argus" }},
		{name: "issuer query", mutate: func(cfg *OIDCConfig) { cfg.IssuerURL += "?tenant=other" }},
		{name: "issuer fragment", mutate: func(cfg *OIDCConfig) { cfg.IssuerURL += "#other" }},
		{name: "JWKS without host", mutate: func(cfg *OIDCConfig) { cfg.JWKSURL = "https:///certs" }},
		{name: "unknown signing algorithm", mutate: func(cfg *OIDCConfig) { cfg.SigningAlgs = []string{"RS256", "X25519"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if _, err := NewOIDCAuthenticator(context.Background(), cfg); err == nil {
				t.Fatal("malformed OIDC configuration should fail closed")
			}
		})
	}
}

func TestClaimParsingIsStrict(t *testing.T) {
	claims := map[string]any{"realm": map[string]any{"roles": []any{" viewer ", "operator"}}}
	if got := claimAtPath(claims, []string{"realm", "roles"}); got == nil {
		t.Fatal("nested claim should be found")
	}
	if got := claimAtPath(claims, []string{"realm", "missing"}); got != nil {
		t.Fatalf("missing nested claim=%v, want nil", got)
	}
	if got := claimAtPath(claims, []string{"realm", "roles", "nested"}); got != nil {
		t.Fatalf("non-object intermediate claim=%v, want nil", got)
	}

	tests := []struct {
		name  string
		value any
		ok    bool
		want  []string
	}{
		{name: "string", value: " viewer ", ok: true, want: []string{"viewer"}},
		{name: "string slice", value: []string{" viewer ", "operator"}, ok: true, want: []string{"viewer", "operator"}},
		{name: "empty string slice item", value: []string{"viewer", ""}, ok: false},
		{name: "any slice", value: []any{"viewer", "operator"}, ok: true, want: []string{"viewer", "operator"}},
		{name: "mixed any slice", value: []any{"viewer", true}, ok: false},
		{name: "empty string", value: " ", ok: false},
		{name: "empty any slice", value: []any{}, ok: false},
		{name: "number", value: 7, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claimStrings(tt.value)
			if ok != tt.ok || !slicesEqual(got, tt.want) {
				t.Fatalf("claimStrings(%v)=(%v,%t), want (%v,%t)", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestAuthenticationErrorAndRequestContextHelpers(t *testing.T) {
	cause := errors.New("signature mismatch")
	err := authError("invalid_token", cause)
	if err.Error() != "authentication failed: invalid_token" {
		t.Fatalf("unexpected safe error message %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("authentication error should retain its internal cause")
	}
	if FailureReason(err) != "invalid_token" || FailureReason(cause) != "internal_error" {
		t.Fatal("failure reasons must be categorized without exposing internal errors")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-for-helper-test")
	if got := BearerToken(req); got != "Bearer opaque-for-helper-test" {
		t.Fatalf("BearerToken=%q", got)
	}
	req.Header.Add("Authorization", "Bearer second-token")
	if got := BearerToken(req); got != "" {
		t.Fatalf("duplicate Authorization headers must fail closed, got %q", got)
	}
	principal := Principal{ID: "issuer#subject", Role: RoleViewer}
	ctx := WithPrincipal(context.Background(), principal)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != principal {
		t.Fatalf("context principal=%+v ok=%t", got, ok)
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context must not contain a principal")
	}
}

func TestViewerIsReadOnly(t *testing.T) {
	viewer := Principal{Role: RoleViewer}
	if !viewer.Can(PermissionView) {
		t.Fatalf("viewer should be allowed to read")
	}
	if viewer.Can(PermissionExecuteRemediation) {
		t.Fatalf("viewer must not execute remediation")
	}
}

func TestOperatorCannotManageServices(t *testing.T) {
	operator := Principal{Role: RoleOperator}
	if !operator.Can(PermissionApproveRemediation) {
		t.Fatalf("operator should approve remediation")
	}
	if operator.Can(PermissionManageService) {
		t.Fatalf("operator must not manage service catalog")
	}
}

func TestRolePermissionMatrix(t *testing.T) {
	permissions := []Permission{
		PermissionView,
		PermissionIngestSignal,
		PermissionManageIncident,
		PermissionGenerateRCA,
		PermissionProposeRemediation,
		PermissionApproveRemediation,
		PermissionExecuteRemediation,
		PermissionViewAudit,
		PermissionManageService,
		PermissionReindexRunbook,
	}
	operatorPermissions := map[Permission]bool{
		PermissionView:               true,
		PermissionIngestSignal:       true,
		PermissionManageIncident:     true,
		PermissionGenerateRCA:        true,
		PermissionProposeRemediation: true,
		PermissionApproveRemediation: true,
		PermissionExecuteRemediation: true,
		PermissionReindexRunbook:     true,
	}

	for _, role := range []Role{RoleViewer, RoleOperator, RoleAdmin, Role("unknown")} {
		t.Run(string(role), func(t *testing.T) {
			for _, permission := range permissions {
				want := role == RoleAdmin ||
					(role == RoleViewer && permission == PermissionView) ||
					(role == RoleOperator && operatorPermissions[permission])
				if got := (Principal{Role: role}).Can(permission); got != want {
					t.Errorf("role=%q permission=%q allowed=%t, want %t", role, permission, got, want)
				}
			}
		})
	}
}

func newTestAuthenticator(t *testing.T) (*OIDCAuthenticator, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&privateKey.PublicKey},
	}, &oidc.Config{
		ClientID:             testAudience,
		SupportedSigningAlgs: []string{"RS256"},
	})
	authn, err := newOIDCAuthenticator(verifier, OIDCConfig{
		RoleClaim:    "realm_access.roles",
		RoleMappings: "argus-admin=admin,argus-operator=operator,argus-viewer=viewer",
	})
	if err != nil {
		t.Fatal(err)
	}
	return authn, privateKey
}

func validClaims(overrides map[string]any) map[string]any {
	claims := map[string]any{
		"iss": testIssuer,
		"sub": "user-123",
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"realm_access": map[string]any{
			"roles": []string{"argus-operator"},
		},
	}
	for key, value := range overrides {
		claims[key] = value
	}
	return claims
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	return signTokenWithKID(t, privateKey, "test-key", claims)
}

func signTokenWithKID(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	encodedHeader := encodeJSON(t, header)
	encodedClaims := encodeJSON(t, claims)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaJWK(publicKey *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
