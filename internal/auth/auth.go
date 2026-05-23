package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
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
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  Role   `json:"role"`
}

type tokenRecord struct {
	token     string
	principal Principal
}

type Authenticator struct {
	tokens []tokenRecord
}

func NewAuthenticator(raw string) (*Authenticator, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("ARGUS_AUTH_TOKENS is required")
	}

	var records []tokenRecord
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid token entry %q; want token:role:email", part)
		}
		token := strings.TrimSpace(fields[0])
		role := Role(strings.TrimSpace(fields[1]))
		email := strings.TrimSpace(fields[2])
		if token == "" || email == "" || !validRole(role) {
			return nil, fmt.Errorf("invalid token entry %q", part)
		}
		records = append(records, tokenRecord{token: token, principal: Principal{ID: email, Email: email, Role: role}})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no auth tokens configured")
	}
	return &Authenticator{tokens: records}, nil
}

func (a *Authenticator) AuthenticateHeader(header string) (Principal, bool) {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return Principal{}, false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if presented == "" {
		return Principal{}, false
	}
	for _, record := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(record.token)) == 1 {
			return record.principal, true
		}
	}
	return Principal{}, false
}

func (p Principal) Can(permission Permission) bool {
	if p.Role == RoleAdmin {
		return true
	}
	allowed := permissionsByRole[p.Role]
	return allowed[permission]
}

func BearerToken(r *http.Request) string {
	return r.Header.Get("Authorization")
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
