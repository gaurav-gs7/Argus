package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/config"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/workers"
)

func main() {
	cfg := config.Load()
	logger := common.NewLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		log.Fatal(err)
	}

	queueClient, err := queue.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatal(err)
	}
	defer queueClient.Close()

	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	metrics := telemetry.MustRegister()
	controlState := workers.NewPostgresControlStateStore(database)
	runner := workers.NewRunner(store, auditor, queueClient, metrics, workers.DefaultHandlers(controlState)...)

	logger.Info("starting argus-worker", "worker_id", cfg.WorkerID)
	if err := runner.Start(ctx, cfg.WorkerID); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
}
