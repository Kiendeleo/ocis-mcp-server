package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owncloud/ocis-mcp-server/internal/client"
	"github.com/owncloud/ocis-mcp-server/internal/config"
	"github.com/owncloud/ocis-mcp-server/internal/httpapi"
	"github.com/owncloud/ocis-mcp-server/internal/tools"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	initLogger(cfg.LogLevel)

	if cfg.TLSSkipVerify {
		slog.Warn("TLS certificate verification is disabled (OCIS_MCP_TLS_SKIP_VERIFY=true)")
	}
	if cfg.Insecure {
		slog.Warn("insecure mode enabled — plaintext HTTP allowed (OCIS_MCP_INSECURE=true)")
	}

	ocisClient := client.New(cfg)

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "ocis-mcp-server",
			Version: version,
		},
		nil,
	)

	tools.RegisterAll(server, ocisClient, cfg)

	slog.Info("starting ocis-mcp-server",
		"version", version,
		"transport", cfg.Transport,
		"ocis_url", cfg.OcisBaseURL(),
		"auth_mode", cfg.AuthMode,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch cfg.Transport {
	case "stdio":
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			slog.Error("stdio server error", "error", err)
			os.Exit(1)
		}
	case "http":
		if err := httpapi.ListenAndServe(ctx, httpapi.Deps{
			Cfg:    cfg,
			Client: ocisClient,
			MCP:    server,
		}); err != nil {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}
}

func initLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)
}
