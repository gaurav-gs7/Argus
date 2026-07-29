# OIDC Authentication Failures

## Signals

- `argus_authentication_failures_total` increases by reason.
- `argus_authorization_denials_total` increases by role and permission.
- The configured identity provider or JWKS endpoint is unavailable.

## Triage

1. Check identity-provider availability and TLS validity.
2. Compare the token `iss` and `aud` claims with Argus configuration without logging the raw token.
3. Confirm the token is unexpired and signed with an allowed algorithm.
4. Confirm the configured role-claim path contains exactly one mapped Argus role.
5. Check for a provider key rotation and verify the advertised JWKS contains the token's `kid`.

## Safety

- Do not disable issuer, audience, expiry, or signature checks.
- Do not add a static-token bypass during an identity-provider outage.
- Do not log or attach raw access tokens to incidents.
- Use provider break-glass controls with time-bound access and an external audit trail.

## Recovery

Restore provider or network health, correct the client audience or role mapping, and obtain a new short-lived token. Confirm authentication and authorization metrics return to baseline.
