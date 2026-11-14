-- Ingestion looks up the open incidents on the handful of services topology
-- relates to an alert, instead of reading every open incident. This partial
-- index keeps that lookup proportional to those services' open incidents.
CREATE INDEX IF NOT EXISTS idx_incidents_open_service
    ON incidents(service_id) WHERE status NOT IN ('resolved', 'cancelled');

-- Timeline and RCA reads are always by incident.
CREATE INDEX IF NOT EXISTS idx_timeline_incident_time
    ON incident_timeline_events(incident_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_rca_reports_incident
    ON rca_reports(incident_id, created_at DESC);
