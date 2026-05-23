package auth

import "testing"

func TestAuthenticatorValidatesBearerToken(t *testing.T) {
	authn, err := NewAuthenticator("admin-token:admin:admin@local,viewer-token:viewer:viewer@local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	principal, ok := authn.AuthenticateHeader("Bearer viewer-token")
	if !ok {
		t.Fatalf("expected token to authenticate")
	}
	if principal.Role != RoleViewer || principal.Email != "viewer@local" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestViewerIsReadOnly(t *testing.T) {
	viewer := Principal{Email: "viewer@local", Role: RoleViewer}
	if !viewer.Can(PermissionView) {
		t.Fatalf("viewer should be allowed to read")
	}
	if viewer.Can(PermissionExecuteRemediation) {
		t.Fatalf("viewer must not execute remediation")
	}
}

func TestOperatorCannotManageServices(t *testing.T) {
	operator := Principal{Email: "operator@local", Role: RoleOperator}
	if !operator.Can(PermissionApproveRemediation) {
		t.Fatalf("operator should approve remediation")
	}
	if operator.Can(PermissionManageService) {
		t.Fatalf("operator must not manage service catalog")
	}
}
