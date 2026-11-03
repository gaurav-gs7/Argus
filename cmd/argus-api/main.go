package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gauravgs7/argus/internal/api"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/config"
	"github.com/gauravgs7/argus/internal/db"
)

// migrate applies pending schema migrations and exits. It is the separate
// migration step for deployments whose API and worker run with
// ARGUS_MIGRATIONS=verify; ARGUS_MIGRATION_POSTGRES_DSN lets it use a role
// with DDL privileges the long-running processes do not have.
func migrate(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	dsn := cfg.MigrationPostgresDSN
	if dsn == "" {
		dsn = cfg.PostgresDSN
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := db.Prepare(ctx, database, db.ModeApply, logger); err != nil {
		return err
	}
	logger.Info("schema is up to date")
	return nil
}

func main() {
	cfg := config.Load()
	logger := common.NewLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(os.Args) > 1 {
		if os.Args[1] != "migrate" {
			log.Fatalf("unknown command %q (the only command is \"migrate\")", os.Args[1])
		}
		if err := migrate(ctx, cfg, logger); err != nil {
			log.Fatal(err)
		}
		return
	}

	server, err := api.New(ctx, cfg, logger)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	httpServer := api.NewHTTPServer(cfg.HTTPAddr, server.Handler(), api.HTTPTimeouts{
		ReadHeader: cfg.HTTPReadHeaderTimeout,
		Read:       cfg.HTTPReadTimeout,
		Write:      cfg.HTTPWriteTimeout,
		Idle:       cfg.HTTPIdleTimeout,
	})

	go func() {
		logger.Info("starting argus-api", "addr", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
