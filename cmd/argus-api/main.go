package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gauravgs7/argus/internal/api"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/config"
)

func main() {
	cfg := config.Load()
	logger := common.NewLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
