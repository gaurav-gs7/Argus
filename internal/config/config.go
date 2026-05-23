package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	Env                  string
	HTTPAddr             string
	PostgresDSN          string
	RedisAddr            string
	NATSURL              string
	AIServiceURL         string
	LogLevel             string
	AuthTokens           string
	IncidentGrouping     time.Duration
	RemediationExecutor  string
	HeliosBaseURL        string
	HeliosAdminToken     string
	HeliosPollTimeout    time.Duration
	WorkerID             string
	WorkerHeartbeatEvery time.Duration
}

func Load() Config {
	return Config{
		Env:                  getenv("ARGUS_ENV", "local"),
		HTTPAddr:             getenv("ARGUS_HTTP_ADDR", ":8080"),
		PostgresDSN:          getenv("ARGUS_POSTGRES_DSN", "postgres://argus:argus@localhost:5432/argus?sslmode=disable"),
		RedisAddr:            getenv("ARGUS_REDIS_ADDR", "localhost:6379"),
		NATSURL:              getenv("ARGUS_NATS_URL", "nats://localhost:4222"),
		AIServiceURL:         strings.TrimRight(getenv("ARGUS_AI_SERVICE_URL", "http://localhost:8090"), "/"),
		LogLevel:             strings.ToUpper(getenv("ARGUS_LOG_LEVEL", "INFO")),
		AuthTokens:           getenv("ARGUS_AUTH_TOKENS", "local-admin-token:admin:admin@local,local-operator-token:operator:operator@local,local-viewer-token:viewer:viewer@local"),
		IncidentGrouping:     getduration("ARGUS_INCIDENT_GROUPING_WINDOW", 5*time.Minute),
		RemediationExecutor:  strings.ToLower(getenv("ARGUS_REMEDIATION_EXECUTOR", "local")),
		HeliosBaseURL:        strings.TrimRight(getenv("ARGUS_HELIOS_BASE_URL", ""), "/"),
		HeliosAdminToken:     getenv("ARGUS_HELIOS_ADMIN_TOKEN", ""),
		HeliosPollTimeout:    getduration("ARGUS_HELIOS_POLL_TIMEOUT", 8*time.Second),
		WorkerID:             getenv("ARGUS_WORKER_ID", "argus-worker-1"),
		WorkerHeartbeatEvery: getduration("ARGUS_WORKER_HEARTBEAT_EVERY", 10*time.Second),
	}
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
