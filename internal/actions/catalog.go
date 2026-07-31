package actions

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

const (
	CollectDiagnostics       = "collect_diagnostics"
	RestartService           = "restart_service"
	RollbackConfig           = "rollback_config"
	ReloadNginx              = "reload_nginx"
	ClearRedisKeyspace       = "clear_redis_keyspace"
	DrainPostgresConnections = "drain_postgres_connections"
	ScaleWorkerSimulation    = "scale_worker_simulation"
	RevertFeatureFlag        = "revert_feature_flag"
	DisableBadRoute          = "disable_bad_route"
	RestartPod               = "restart_pod"
	ResizeConnectionPool     = "resize_connection_pool"
	ToggleFeatureFlag        = "toggle_feature_flag"
	PurgeCache               = "purge_cache"
)

var (
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	registered      = map[string]struct{}{
		CollectDiagnostics: {}, RestartService: {}, RollbackConfig: {}, ReloadNginx: {},
		ClearRedisKeyspace: {}, DrainPostgresConnections: {}, ScaleWorkerSimulation: {},
		RevertFeatureFlag: {}, DisableBadRoute: {}, RestartPod: {}, ResizeConnectionPool: {},
		ToggleFeatureFlag: {}, PurgeCache: {},
	}
	allowedFlags = map[string]struct{}{
		"payments-api/optional-notifications": {},
		"payments-api/checkout-v2":            {},
		"checkout-api/async-confirmation":     {},
	}
)

func IsRegistered(action string) bool {
	_, ok := registered[action]
	return ok
}

func Validate(action, target string, parameters map[string]any) error {
	switch action {
	case RestartPod:
		if err := validateKeys(parameters); err != nil {
			return err
		}
		parts := strings.Split(target, "/")
		if len(parts) != 2 || (parts[0] != "local" && parts[0] != "demo") ||
			!validDNSLabel(parts[1]) {
			return fmt.Errorf("pod target must be local/<pod> or demo/<pod>")
		}
	case ResizeConnectionPool:
		if !validDNSLabel(target) {
			return fmt.Errorf("connection-pool target must be a service name")
		}
		if err := validateKeys(parameters, "size"); err != nil {
			return err
		}
		size, ok := Integer(parameters["size"])
		if !ok || size < 2 || size > 50 {
			return fmt.Errorf("connection-pool size must be an integer between 2 and 50")
		}
	case ToggleFeatureFlag:
		if _, ok := allowedFlags[target]; !ok {
			return fmt.Errorf("feature flag target is not allow-listed")
		}
		if err := validateKeys(parameters, "enabled"); err != nil {
			return err
		}
		if _, ok := parameters["enabled"].(bool); !ok {
			return fmt.Errorf("feature flag enabled must be a boolean")
		}
	case PurgeCache:
		if err := validateCachePrefix(target); err != nil {
			return err
		}
		if err := validateKeys(parameters, "max_keys"); err != nil {
			return err
		}
		maxKeys, ok := Integer(parameters["max_keys"])
		if !ok || maxKeys < 1 || maxKeys > 1000 {
			return fmt.Errorf("cache purge max_keys must be an integer between 1 and 1000")
		}
	case ClearRedisKeyspace:
		if !strings.HasPrefix(target, "demo:pressure:") {
			return fmt.Errorf("redis remediation is restricted to demo:pressure:* keys")
		}
	}
	return nil
}

func Integer(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		if math.Trunc(typed) == typed && typed >= math.MinInt && typed <= math.MaxInt {
			return int(typed), true
		}
	case json.Number:
		value, err := typed.Int64()
		if err == nil {
			return int(value), true
		}
	}
	return 0, false
}

func validateKeys(parameters map[string]any, required ...string) error {
	if len(parameters) != len(required) {
		return fmt.Errorf("expected parameters: %s", strings.Join(required, ", "))
	}
	for _, key := range required {
		if _, ok := parameters[key]; !ok {
			return fmt.Errorf("missing parameter %q", key)
		}
	}
	return nil
}

func validateCachePrefix(target string) error {
	if !strings.HasPrefix(target, "demo:") || !strings.HasSuffix(target, ":*") ||
		strings.Count(target, "*") != 1 || len(strings.TrimSuffix(target, "*")) < len("demo:x:") {
		return fmt.Errorf("cache purge target must be a scoped demo:<segment>:* prefix")
	}
	return nil
}

func validDNSLabel(value string) bool {
	return len(value) <= 63 && dnsLabelPattern.MatchString(value)
}
