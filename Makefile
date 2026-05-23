APP_NAME := argus

export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1

.PHONY: up down full-up logs seed test lint fmt fmt-check vet py-compile compose-check docs-check ci reset demo-postgres-exhaustion demo-redis-pressure demo-nginx-5xx demo-dependency-latency demo-bad-config

up:
	docker compose up --build -d

full-up:
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

ci: lint test py-compile compose-check

reset:
	./scripts/reset-local.sh

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
