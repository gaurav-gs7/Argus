# 150-Second Terminal Demo

## Why Terminal-First

Runtime behavior is shown as runtime behavior. API input, backend processing, PostgreSQL state, JetStream delivery, worker output, policy decisions, audit verification, and metrics appear as actual terminal commands and responses. ASCII flowcharts are used only to explain transitions between those operations. There are no rendered dashboard screenshots or fabricated command outputs in the capture.

The committed capture is an Asciinema v2 terminal stream generated from the real local Compose stack. Argus includes a Python standard-library replay path, so viewing it does not require Asciinema, a browser, a paid recorder, or a running Argus environment.

## Experience The Recorded Demo

From a clone:

```bash
make demo-terminal-replay
```

That command plays [`docs/demo-evidence/argus-terminal-demo.cast`](demo-evidence/argus-terminal-demo.cast) at its original 150-second pace. For review or CI-speed playback:

```bash
python3 demo/terminal/presenter.py replay \
  --cast docs/demo-evidence/argus-terminal-demo.cast \
  --speed 10
```

## Run It Against A Live Stack

Setup is intentionally outside the 150-second recording window:

```bash
make up
make seed
make demo-terminal
```

`make demo-terminal` executes the same real workflow and writes a fresh cast plus machine-local JSON evidence under `artifacts/terminal-demo/`. It uses the lightweight default profile: mock LLM generation, real OIDC/JWKS validation, real Verdikt governance, PostgreSQL, NATS JetStream, and typed workers. It does not require Ollama, Gemini, Kubernetes, or a paid service.

For a real backend run without presentation waits:

```bash
make demo-terminal-fast
```

## Exact 150-Second Timeline

| Time | Terminal scene | Live proof |
| --- | --- | --- |
| `0-6s` | Incident to safe remediation | Scope and laptop profile |
| `6-17s` | Control-plane flowchart | Deterministic and advisory boundaries |
| `17-29s` | Backend and identity | Compose state plus verified OIDC actor |
| `29-43s` | Actual input | Generate and POST twenty Alertmanager alerts |
| `43-56s` | Correlation processing | One root incident and eighteen suppressed pages |
| `56-69s` | Durable backend | Direct PostgreSQL and topology API reads |
| `69-85s` | Deterministic RCA | Hypothesis, confidence formula, factors, and blast radius |
| `85-99s` | Governed AI | Bounded candidates, `PROPOSE_ONLY`, `executed: false`, usage metrics |
| `99-111s` | Policy | Typed connection-pool proposal and policy decision |
| `111-123s` | Human approval | Self-approval rejection and separate admin identity/reason |
| `123-137s` | Execution | JetStream queue, typed worker, PostgreSQL receipt, replay reuse |
| `137-147s` | Audit and observability | Complete SHA-256 chain verification and Prometheus metrics |
| `147-150s` | Recap | Six runtime properties proven by the session |

## Runtime Flow

```text
20 real alerts
      |
      v
OIDC-protected Alertmanager ingress
      |
      v
topology graph walk -----> preserve 20 signals
      |                   suppress 18 downstream pages
      v
one PostgreSQL-root incident
      |
      v
fixed RCA evidence arithmetic
      |--------------------> AI summary -> Verdikt PROPOSE_ONLY
      v
typed candidate -> Go policy -> four-eyes approval
      |
      v
JetStream -> typed worker -> target state + idempotency receipt
      |
      v
hash-chain verification + Prometheus evidence
```

## Capture Integrity

`make terminal-demo-check` validates the committed recording as a release artifact. The check requires:

- an Asciinema v2 header and monotonic output events
- a duration between `149.5` and `155` seconds
- all thirteen terminal scenes
- runtime-generated incident and remediation IDs
- correlation, RCA, AI governance, approval, execution, replay, JetStream, audit, and metric proof markers
- no bearer JWT, local absolute path, demo client secret, or failed-run marker

The cast is evidence of one successful local run, not a substitute for tests. CI independently runs race detection, coverage gates, disposable PostgreSQL/JetStream integration, OIDC E2E, adversarial AI tests, deterministic RCA evaluation, and artifact validation.
