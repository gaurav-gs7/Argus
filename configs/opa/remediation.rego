package argus.remediation

default allow := false
default requires_approval := true

allow if {
  input.incident.environment == "local"
  input.remediation.type == "restart_service"
  input.history.same_action_last_10m < 2
}

allow if {
  input.incident.environment == "local"
  input.remediation.type == "clear_redis_keyspace"
  input.history.same_action_last_10m < 2
}

allow if {
  input.incident.environment == "local"
  input.remediation.type == "restart_pod"
  regex.match("^(local|demo)/[a-z0-9]([-a-z0-9]*[a-z0-9])?$", input.remediation.target)
  input.history.same_action_last_10m < 2
}

allow if {
  input.incident.environment == "local"
  input.remediation.type == "resize_connection_pool"
  regex.match("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", input.remediation.target)
  input.remediation.parameters.size >= 2
  input.remediation.parameters.size <= 50
  input.history.same_action_last_10m < 2
}

allow if {
  input.incident.environment == "local"
  input.remediation.type == "toggle_feature_flag"
  input.remediation.target in {
    "payments-api/optional-notifications",
    "payments-api/checkout-v2",
    "checkout-api/async-confirmation",
  }
  is_boolean(input.remediation.parameters.enabled)
  input.history.same_action_last_10m < 2
}

allow if {
  input.incident.environment == "local"
  input.remediation.type == "purge_cache"
  regex.match("^demo:[^:*]+:\\*$", input.remediation.target)
  input.remediation.parameters.max_keys >= 1
  input.remediation.parameters.max_keys <= 1000
  input.history.same_action_last_10m < 2
}

requires_approval if {
  input.remediation.risk == "medium"
}

deny_reason := "Too many repeated remediation attempts" if {
  input.history.same_action_last_10m >= 2
}
