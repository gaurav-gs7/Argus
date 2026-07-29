package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

type Permission string

const (
	PermissionView               Permission = "view"
	PermissionIngestSignal       Permission = "ingest_signal"
	PermissionManageIncident     Permission = "manage_incident"
	PermissionGenerateRCA        Permission = "generate_rca"
	PermissionProposeRemediation Permission = "propose_remediation"
	PermissionApproveRemediation Permission = "approve_remediation"
	PermissionExecuteRemediation Permission = "execute_remediation"
	PermissionViewAudit          Permission = "view_audit"
	PermissionManageService      Permission = "manage_service"
	PermissionReindexRunbook     Permission = "reindex_runbook"
)

type Principal struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Role        Role   `json:"role"`
}

type Authenticator interface {
	Authenticate(ctx context.Context, authorizationHeader string) (Principal, error)
}

type OIDCConfig struct {
	IssuerURL         string
	Audience          string
	JWKSURL           string
	RoleClaim         string
	RoleMappings      string
	EmailClaim        string
	DisplayNameClaim  string
	SigningAlgs       []string
	DiscoveryTimeout  time.Duration
	ProviderTimeout   time.Duration
	AllowInsecureHTTP bool
}

type tokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type OIDCAuthenticator struct {
	verifier         tokenVerifier
	roleClaimPath    []string
	roleMappings     map[string]Role
	emailClaim       string
	displayNameClaim string
}

type AuthenticationError struct {
	Reason string
	err    error
}

func (e *AuthenticationError) Error() string {
	return "authentication failed: " + e.Reason
}

func (e *AuthenticationError) Unwrap() error {
	return e.err
}

func NewOIDCAuthenticator(ctx context.Context, cfg OIDCConfig) (*OIDCAuthenticator, error) {
	cfg.IssuerURL = strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("ARGUS_OIDC_ISSUER_URL is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("ARGUS_OIDC_AUDIENCE is required")
	}
	if err := validateOIDCURL("issuer", cfg.IssuerURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}

	signingAlgs := cfg.SigningAlgs
	if len(signingAlgs) == 0 {
		signingAlgs = []string{"RS256"}
	}
	for _, alg := range signingAlgs {
		if !allowedSigningAlgorithm(alg) {
			return nil, fmt.Errorf("OIDC signing algorithm %q is not an approved asymmetric algorithm", alg)
		}
	}
	verifierConfig := &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: signingAlgs,
	}

	providerTimeout := cfg.ProviderTimeout
	if providerTimeout <= 0 {
		providerTimeout = 3 * time.Second
	}
	providerCtx := oidc.ClientContext(ctx, &http.Client{Timeout: providerTimeout})

	var verifier tokenVerifier
	if jwksURL := strings.TrimSpace(cfg.JWKSURL); jwksURL != "" {
		if err := validateOIDCURL("JWKS", jwksURL, cfg.AllowInsecureHTTP); err != nil {
			return nil, err
		}
		keySet := oidc.NewRemoteKeySet(providerCtx, jwksURL)
		verifier = oidc.NewVerifier(cfg.IssuerURL, keySet, verifierConfig)
	} else {
		discoveryTimeout := cfg.DiscoveryTimeout
		if discoveryTimeout <= 0 {
			discoveryTimeout = 5 * time.Second
		}
		discoveryCtx, cancel := context.WithTimeout(providerCtx, discoveryTimeout)
		provider, err := oidc.NewProvider(discoveryCtx, cfg.IssuerURL)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("discover OIDC provider: %w", err)
		}
		verifier = provider.VerifierContext(providerCtx, verifierConfig)
	}

	return newOIDCAuthenticator(verifier, cfg)
}

func newOIDCAuthenticator(verifier tokenVerifier, cfg OIDCConfig) (*OIDCAuthenticator, error) {
	if verifier == nil {
		return nil, fmt.Errorf("OIDC verifier is required")
	}
	roleClaim := strings.TrimSpace(cfg.RoleClaim)
	if roleClaim == "" {
		roleClaim = "realm_access.roles"
	}
	for _, part := range strings.Split(roleClaim, ".") {
		if strings.TrimSpace(part) == "" {
			return nil, fmt.Errorf("invalid OIDC role claim path %q", roleClaim)
		}
	}
	roleMappings, err := parseRoleMappings(cfg.RoleMappings)
	if err != nil {
		return nil, err
	}
	emailClaim := strings.TrimSpace(cfg.EmailClaim)
	if emailClaim == "" {
		emailClaim = "email"
	}
	displayNameClaim := strings.TrimSpace(cfg.DisplayNameClaim)
	if displayNameClaim == "" {
		displayNameClaim = "preferred_username"
	}

	return &OIDCAuthenticator{
		verifier:         verifier,
		roleClaimPath:    strings.Split(roleClaim, "."),
		roleMappings:     roleMappings,
		emailClaim:       emailClaim,
		displayNameClaim: displayNameClaim,
	}, nil
}

func (a *OIDCAuthenticator) Authenticate(ctx context.Context, authorizationHeader string) (Principal, error) {
	rawToken, err := parseBearerToken(authorizationHeader)
	if err != nil {
		return Principal{}, err
	}
	token, err := a.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Principal{}, authError("invalid_token", err)
	}
	if strings.TrimSpace(token.Subject) == "" {
		return Principal{}, authError("missing_subject", nil)
	}
	if !token.IssuedAt.IsZero() && token.IssuedAt.After(time.Now().Add(5*time.Minute)) {
		return Principal{}, authError("invalid_token", fmt.Errorf("token issued-at time is in the future"))
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Principal{}, authError("invalid_claims", err)
	}
	roleValues, ok := claimStrings(claimAtPath(claims, a.roleClaimPath))
	if !ok {
		return Principal{}, authError("missing_role_claim", nil)
	}

	mappedRoles := make(map[Role]struct{})
	for _, value := range roleValues {
		if role, exists := a.roleMappings[value]; exists {
			mappedRoles[role] = struct{}{}
		}
	}
	if len(mappedRoles) == 0 {
		return Principal{}, authError("unmapped_role", nil)
	}
	if len(mappedRoles) > 1 {
		return Principal{}, authError("ambiguous_role", nil)
	}

	var role Role
	for mapped := range mappedRoles {
		role = mapped
	}
	email, _ := claimString(claims[a.emailClaim])
	displayName, _ := claimString(claims[a.displayNameClaim])
	if displayName == "" {
		displayName = email
	}
	if displayName == "" {
		displayName = token.Subject
	}

	return Principal{
		ID:          token.Issuer + "#" + token.Subject,
		Subject:     token.Subject,
		Issuer:      token.Issuer,
		Email:       email,
		DisplayName: displayName,
		Role:        role,
	}, nil
}

func FailureReason(err error) string {
	var authErr *AuthenticationError
	if errors.As(err, &authErr) {
		return authErr.Reason
	}
	return "internal_error"
}

func (p Principal) Can(permission Permission) bool {
	if p.Role == RoleAdmin {
		return true
	}
	allowed := permissionsByRole[p.Role]
	return allowed[permission]
}

func BearerToken(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func parseBearerToken(header string) (string, error) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", authError("missing_bearer_token", nil)
	}
	return fields[1], nil
}

func parseRoleMappings(raw string) (map[string]Role, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("ARGUS_OIDC_ROLE_MAPPINGS is required")
	}
	mappings := make(map[string]Role)
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid OIDC role mapping %q; want provider-role=argus-role", entry)
		}
		externalRole := strings.TrimSpace(parts[0])
		argusRole := Role(strings.TrimSpace(parts[1]))
		if externalRole == "" || !validRole(argusRole) {
			return nil, fmt.Errorf("invalid OIDC role mapping %q", entry)
		}
		if _, exists := mappings[externalRole]; exists {
			return nil, fmt.Errorf("duplicate OIDC role mapping for %q", externalRole)
		}
		mappings[externalRole] = argusRole
	}
	return mappings, nil
}

func claimAtPath(claims map[string]any, path []string) any {
	var current any = claims
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	return current
}

func claimStrings(value any) ([]string, bool) {
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return nil, false
		}
		return []string{typed}, true
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := claimString(item)
			if !ok || text == "" {
				return nil, false
			}
			result = append(result, text)
		}
		return result, len(result) > 0
	case []string:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, false
			}
			result = append(result, item)
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}

func claimString(value any) (string, bool) {
	text, ok := value.(string)
	return strings.TrimSpace(text), ok
}

func authError(reason string, err error) error {
	return &AuthenticationError{Reason: reason, err: err}
}

func validateOIDCURL(name, rawURL string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid OIDC %s URL", name)
	}
	if parsed.Scheme != "https" && !(allowInsecureHTTP && parsed.Scheme == "http") {
		return fmt.Errorf("OIDC %s URL must use HTTPS outside local mode", name)
	}
	return nil
}

func allowedSigningAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	default:
		return false
	}
}

func validRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

var permissionsByRole = map[Role]map[Permission]bool{
	RoleViewer: {
		PermissionView: true,
	},
	RoleOperator: {
		PermissionView:               true,
		PermissionIngestSignal:       true,
		PermissionManageIncident:     true,
		PermissionGenerateRCA:        true,
		PermissionProposeRemediation: true,
		PermissionApproveRemediation: true,
		PermissionExecuteRemediation: true,
		PermissionReindexRunbook:     true,
	},
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}
