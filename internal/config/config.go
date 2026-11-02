package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env                        string
	HTTPAddr                   string
	HTTPReadHeaderTimeout      time.Duration
	HTTPReadTimeout            time.Duration
	HTTPWriteTimeout           time.Duration
	HTTPIdleTimeout            time.Duration
	PostgresDSN                string
	RedisAddr                  string
	NATSURL                    string
	AIServiceURL               string
	AIServiceToken             string
	PrometheusURL              string
	PrometheusBearerToken      string
	LokiURL                    string
	LokiBearerToken            string
	RCAProbeTimeout            time.Duration
	AlertStaleAfter            time.Duration
	RemediationEnvironments    []string
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
	WorkerConcurrency          int
	WorkerJobTimeout           time.Duration
	WorkerMaxDeliver           int
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
		Env:                   getenv("ARGUS_ENV", "local"),
		HTTPAddr:              getenv("ARGUS_HTTP_ADDR", ":8080"),
		HTTPReadHeaderTimeout: getduration("ARGUS_HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		HTTPReadTimeout:       getduration("ARGUS_HTTP_READ_TIMEOUT", 15*time.Second),
		HTTPWriteTimeout:      getduration("ARGUS_HTTP_WRITE_TIMEOUT", 30*time.Second),
		HTTPIdleTimeout:       getduration("ARGUS_HTTP_IDLE_TIMEOUT", 120*time.Second),
		PostgresDSN:           getenv("ARGUS_POSTGRES_DSN", "postgres://argus:argus@localhost:5432/argus?sslmode=disable"),
		RedisAddr:             getenv("ARGUS_REDIS_ADDR", "localhost:6379"),
		NATSURL:               getenv("ARGUS_NATS_URL", "nats://localhost:4222"),
		// The AI service is opt-in, and its token has no default: a
		// well-known fallback token is the same as no authentication.
		AIServiceURL:               strings.TrimRight(getenv("ARGUS_AI_SERVICE_URL", ""), "/"),
		AIServiceToken:             getenv("ARGUS_AI_SERVICE_TOKEN", ""),
		PrometheusURL:              strings.TrimRight(getenv("ARGUS_PROMETHEUS_URL", ""), "/"),
		PrometheusBearerToken:      getenv("ARGUS_PROMETHEUS_BEARER_TOKEN", ""),
		LokiURL:                    strings.TrimRight(getenv("ARGUS_LOKI_URL", ""), "/"),
		LokiBearerToken:            getenv("ARGUS_LOKI_BEARER_TOKEN", ""),
		RCAProbeTimeout:            getduration("ARGUS_RCA_PROBE_TIMEOUT", 3*time.Second),
		AlertStaleAfter:            getduration("ARGUS_ALERT_STALE_AFTER", 6*time.Hour),
		RemediationEnvironments:    strings.Split(getenv("ARGUS_REMEDIATION_ENVIRONMENTS", "local"), ","),
		LogLevel:                   strings.ToUpper(getenv("ARGUS_LOG_LEVEL", "INFO")),
		OIDCIssuerURL:              strings.TrimRight(getenv("ARGUS_OIDC_ISSUER_URL", ""), "/"),
		OIDCAudience:               getenv("ARGUS_OIDC_AUDIENCE", "argus-api"),
		OIDCJWKSURL:                getenv("ARGUS_OIDC_JWKS_URL", ""),
		OIDCRoleClaim:              getenv("ARGUS_OIDC_ROLE_CLAIM", "realm_access.roles"),
		OIDCRoleMappings:           getenv("ARGUS_OIDC_ROLE_MAPPINGS", "argus-admin=admin,argus-operator=operator,argus-viewer=viewer,argus-ingester=ingester"),
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
		WorkerConcurrency:          getint("ARGUS_WORKER_CONCURRENCY", 4),
		WorkerJobTimeout:           getduration("ARGUS_WORKER_JOB_TIMEOUT", 2*time.Minute),
		WorkerMaxDeliver:           getint("ARGUS_WORKER_MAX_DELIVER", 5),
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

// Validate rejects configurations that would run insecurely.
func (c Config) Validate() error {
	if c.AIServiceURL != "" && c.AIServiceToken == "" {
		return fmt.Errorf("ARGUS_AI_SERVICE_TOKEN must be set when ARGUS_AI_SERVICE_URL is configured")
	}
	return nil
}

func getint(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
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
