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

requires_approval if {
  input.remediation.risk == "medium"
}

deny_reason := "Too many repeated remediation attempts" if {
  input.history.same_action_last_10m >= 2
}
