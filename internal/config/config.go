package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	Env                        string
	HTTPAddr                   string
	PostgresDSN                string
	RedisAddr                  string
	NATSURL                    string
	AIServiceURL               string
	AIServiceToken             string
	LogLevel                   string
	OIDCIssuerURL              string
	OIDCAudience               string
	OIDCJWKSURL                string
	OIDCRoleClaim              string
	OIDCRoleMappings           string
	OIDCEmailClaim             string
	OIDCDisplayNameClaim       string
	OIDCSigningAlgs            []string
	OIDCDiscoveryTimeout       time.Duration
	OIDCProviderTimeout        time.Duration
	IncidentGrouping           time.Duration
	RemediationExecutor        string
	HeliosBaseURL              string
	HeliosAdminToken           string
	HeliosPollTimeout          time.Duration
	WorkerID                   string
	WorkerHeartbeatEvery       time.Duration
	ApprovalWebhookURL         string
	ApprovalWebhookMode        string
	ApprovalWebhookSecret      string
	ApprovalCallbackBaseURL    string
	ApprovalTimeout            time.Duration
	ApprovalEscalateAfter      time.Duration
	ApprovalSweepInterval      time.Duration
	ApprovalNotifyTimeout      time.Duration
	ApprovalAllowSelf          bool
	ApprovalSlackSigningSecret string
	ApprovalSlackBotToken      string
	ApprovalSlackApprovers     string
}

func Load() Config {
	return Config{
		Env:                        getenv("ARGUS_ENV", "local"),
		HTTPAddr:                   getenv("ARGUS_HTTP_ADDR", ":8080"),
		PostgresDSN:                getenv("ARGUS_POSTGRES_DSN", "postgres://argus:argus@localhost:5432/argus?sslmode=disable"),
		RedisAddr:                  getenv("ARGUS_REDIS_ADDR", "localhost:6379"),
		NATSURL:                    getenv("ARGUS_NATS_URL", "nats://localhost:4222"),
		AIServiceURL:               strings.TrimRight(getenv("ARGUS_AI_SERVICE_URL", "http://localhost:8090"), "/"),
		AIServiceToken:             getenv("ARGUS_AI_SERVICE_TOKEN", "argus-ai-local"),
		LogLevel:                   strings.ToUpper(getenv("ARGUS_LOG_LEVEL", "INFO")),
		OIDCIssuerURL:              strings.TrimRight(getenv("ARGUS_OIDC_ISSUER_URL", ""), "/"),
		OIDCAudience:               getenv("ARGUS_OIDC_AUDIENCE", "argus-api"),
		OIDCJWKSURL:                getenv("ARGUS_OIDC_JWKS_URL", ""),
		OIDCRoleClaim:              getenv("ARGUS_OIDC_ROLE_CLAIM", "realm_access.roles"),
		OIDCRoleMappings:           getenv("ARGUS_OIDC_ROLE_MAPPINGS", "argus-admin=admin,argus-operator=operator,argus-viewer=viewer"),
		OIDCEmailClaim:             getenv("ARGUS_OIDC_EMAIL_CLAIM", "email"),
		OIDCDisplayNameClaim:       getenv("ARGUS_OIDC_DISPLAY_NAME_CLAIM", "preferred_username"),
		OIDCSigningAlgs:            getcsv("ARGUS_OIDC_SIGNING_ALGS", []string{"RS256"}),
		OIDCDiscoveryTimeout:       getduration("ARGUS_OIDC_DISCOVERY_TIMEOUT", 5*time.Second),
		OIDCProviderTimeout:        getduration("ARGUS_OIDC_PROVIDER_TIMEOUT", 3*time.Second),
		IncidentGrouping:           getduration("ARGUS_INCIDENT_GROUPING_WINDOW", 5*time.Minute),
		RemediationExecutor:        strings.ToLower(getenv("ARGUS_REMEDIATION_EXECUTOR", "local")),
		HeliosBaseURL:              strings.TrimRight(getenv("ARGUS_HELIOS_BASE_URL", ""), "/"),
		HeliosAdminToken:           getenv("ARGUS_HELIOS_ADMIN_TOKEN", ""),
		HeliosPollTimeout:          getduration("ARGUS_HELIOS_POLL_TIMEOUT", 8*time.Second),
		WorkerID:                   getenv("ARGUS_WORKER_ID", "argus-worker-1"),
		WorkerHeartbeatEvery:       getduration("ARGUS_WORKER_HEARTBEAT_EVERY", 10*time.Second),
		ApprovalWebhookURL:         getenv("ARGUS_APPROVAL_WEBHOOK_URL", ""),
		ApprovalWebhookMode:        strings.ToLower(getenv("ARGUS_APPROVAL_WEBHOOK_MODE", "generic")),
		ApprovalWebhookSecret:      getenv("ARGUS_APPROVAL_WEBHOOK_SECRET", ""),
		ApprovalCallbackBaseURL:    strings.TrimRight(getenv("ARGUS_APPROVAL_CALLBACK_BASE_URL", "http://localhost:8080"), "/"),
		ApprovalTimeout:            getduration("ARGUS_APPROVAL_TIMEOUT", 15*time.Minute),
		ApprovalEscalateAfter:      getduration("ARGUS_APPROVAL_ESCALATE_AFTER", 5*time.Minute),
		ApprovalSweepInterval:      getduration("ARGUS_APPROVAL_SWEEP_INTERVAL", 15*time.Second),
		ApprovalNotifyTimeout:      getduration("ARGUS_APPROVAL_NOTIFY_TIMEOUT", 3*time.Second),
		ApprovalAllowSelf:          getbool("ARGUS_APPROVAL_ALLOW_SELF_APPROVAL", false),
		ApprovalSlackSigningSecret: getenv("ARGUS_SLACK_SIGNING_SECRET", ""),
		ApprovalSlackBotToken:      getenv("ARGUS_SLACK_BOT_TOKEN", ""),
		ApprovalSlackApprovers:     getenv("ARGUS_SLACK_APPROVERS", ""),
	}
}

func getcsv(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func getbool(key string, fallback bool) bool {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		switch strings.ToLower(raw) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return fallback
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getduration(key string, fallback time.Duration) time.Duration {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed
		}
	}
	return fallback
}
