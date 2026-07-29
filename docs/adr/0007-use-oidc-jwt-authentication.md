# ADR 0007: Use OIDC JWT Authentication

## Status

Accepted.

## Context

Static opaque tokens do not provide issuer binding, audience restriction, expiration, asymmetric signature verification, key rotation, or trustworthy identity claims. They are insufficient for incident and remediation APIs where an approval must be attributable to a durable identity.

## Decision

Argus accepts JWT access tokens from one configured OpenID Connect issuer. The API verifies the signature against the provider's rotating JWKS, exact issuer, configured audience, expiration, and an explicit signing-algorithm allow-list. Provider role claims are mapped to Argus roles by configuration. Missing, unmapped, or conflicting roles are rejected.

Authorization uses the mapped `admin`, `operator`, or `viewer` role. Audit entries and four-eyes checks use `issuer#sub`, not email or a request-body identity. Email and display name remain optional presentation attributes.

The local `users` table is catalog metadata and is not consulted to authenticate or elevate a request. OIDC verification and trusted provider role claims are the authorization source of truth.

OIDC discovery is the production default. An explicit JWKS URL is supported for split-horizon networking, while issuer validation remains mandatory. The local Compose environment uses a resource-capped Keycloak realm with short-lived service-account tokens for automated demos; it is not a production identity deployment.

## Consequences

- Access-token compromise is bounded by short expiration and provider revocation/rotation controls.
- Key rotation does not require an Argus restart.
- Production startup fails closed when issuer, audience, discovery, or role mapping is invalid.
- Human login stays with the organization's identity provider and can inherit MFA and conditional-access policy.
- Slack approver mappings must use the same immutable OIDC identity format.
