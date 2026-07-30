APP_NAME := argus

export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1

.PHONY: bootstrap up down full-up logs seed test integration-test oidc-test ai-test ai-test-local lint fmt fmt-check vet py-compile compose-check docs-check ci reset demo-alert-storm demo-postgres-exhaustion demo-redis-pressure demo-nginx-5xx demo-dependency-latency demo-bad-config

bootstrap:
	./scripts/bootstrap.sh

up: bootstrap
	docker compose up --build -d

full-up: bootstrap
	docker compose -f docker-compose.yml -f docker-compose.full.yml up --build -d

down:
	docker compose down -v --remove-orphans

logs:
	docker compose logs -f --tail=200

seed:
	./scripts/seed-data.sh

fmt:
	gofmt -w ./cmd ./internal ./demo/services

fmt-check:
	test -z "$$(gofmt -l ./cmd ./internal ./demo/services)"

test:
	go test ./...

integration-test:
	@set -eu; \
		docker compose -f deploy/compose.test.yaml up -d --wait; \
		trap 'docker compose -f deploy/compose.test.yaml down -v' EXIT; \
		ARGUS_TEST_POSTGRES_DSN='postgres://argus:argus@127.0.0.1:55432/argus?sslmode=disable' \
		go test -race -count=1 ./internal/audit; \
		ARGUS_TEST_POSTGRES_DSN='postgres://argus:argus@127.0.0.1:55432/argus?sslmode=disable' \
		ARGUS_TEST_NATS_URL='nats://127.0.0.1:54222' \
		go test -race -count=1 ./internal/incidents ./internal/queue

oidc-test:
	./scripts/test-oidc-e2e.sh

ai-test:
	docker compose run --rm --no-deps --build argus-ai python -m unittest discover -s tests -v

ai-test-local:
	PYTHONPATH=ai-service python3 -m unittest discover -s ai-service/tests -v

vet:
	go vet ./...

py-compile:
	PYTHONPYCACHEPREFIX=/tmp/argus-pycache python3 -m compileall -q ai-service/app

compose-check:
	docker compose config >/dev/null
	docker compose -f docker-compose.yml -f docker-compose.full.yml config >/dev/null

docs-check:
	python3 scripts/check-portable-docs.py

lint: fmt-check vet docs-check

ci: lint test ai-test py-compile compose-check

reset:
	./scripts/reset-local.sh

demo-alert-storm:
	./scripts/run-alert-storm-demo.sh

demo-postgres-exhaustion:
	./scripts/run-demo.sh postgres_connection_exhaustion

demo-redis-pressure:
	./scripts/run-demo.sh redis_memory_pressure

demo-nginx-5xx:
	./scripts/run-demo.sh nginx_5xx_spike

demo-dependency-latency:
	./scripts/run-demo.sh dependency_latency

demo-bad-config:
	./scripts/run-demo.sh bad_config_rollout
