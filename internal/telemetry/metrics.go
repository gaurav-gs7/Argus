package telemetry

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	IncidentsTotal            *prometheus.CounterVec
	IncidentsOpen             prometheus.Gauge
	RCAJobsTotal              *prometheus.CounterVec
	RCADuration               *prometheus.HistogramVec
	RemediationsTotal         *prometheus.CounterVec
	RemediationDuration       *prometheus.HistogramVec
	RemediationFailuresTotal  *prometheus.CounterVec
	PolicyDenialsTotal        *prometheus.CounterVec
	LLMRequestsTotal          *prometheus.CounterVec
	LLMRequestDuration        *prometheus.HistogramVec
	WorkerHeartbeatAgeSeconds *prometheus.GaugeVec
	RCAConfidence             *prometheus.HistogramVec
}

func MustRegister() *Metrics {
	m := &Metrics{
		IncidentsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_incidents_total",
			Help: "Total incidents created or updated",
		}, []string{"result", "severity"}),
		IncidentsOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "argus_incidents_open",
			Help: "Current number of open incidents",
		}),
		RCAJobsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_rca_jobs_total",
			Help: "Total RCA jobs by result",
		}, []string{"result"}),
		RCADuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "argus_rca_job_duration_seconds",
			Help:    "RCA generation duration",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"}),
		RemediationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_remediations_total",
			Help: "Total remediation proposals and executions",
		}, []string{"action_type", "status"}),
		RemediationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "argus_remediation_duration_seconds",
			Help:    "Remediation execution duration",
			Buckets: prometheus.DefBuckets,
		}, []string{"action_type"}),
		RemediationFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_remediation_failures_total",
			Help: "Total remediation failures",
		}, []string{"action_type"}),
		PolicyDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_policy_denials_total",
			Help: "Total policy denials",
		}, []string{"action_type", "reason"}),
		LLMRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "argus_llm_requests_total",
			Help: "Total LLM requests",
		}, []string{"backend", "result"}),
		LLMRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "argus_llm_request_duration_seconds",
			Help:    "LLM request duration",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"}),
		WorkerHeartbeatAgeSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "argus_worker_heartbeat_age_seconds",
			Help: "Age of latest worker heartbeat",
		}, []string{"worker_id"}),
		RCAConfidence: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "argus_rca_confidence_score",
			Help:    "Deterministic RCA confidence score by primary hypothesis",
			Buckets: []float64{0.25, 0.5, 0.7, 0.8, 0.9, 0.95, 1.0},
		}, []string{"hypothesis"}),
	}

	prometheus.MustRegister(
		m.IncidentsTotal,
		m.IncidentsOpen,
		m.RCAJobsTotal,
		m.RCADuration,
		m.RemediationsTotal,
		m.RemediationDuration,
		m.RemediationFailuresTotal,
		m.PolicyDenialsTotal,
		m.LLMRequestsTotal,
		m.LLMRequestDuration,
		m.WorkerHeartbeatAgeSeconds,
		m.RCAConfidence,
	)

	return m
}
