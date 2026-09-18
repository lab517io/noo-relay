// Command relay runs the Noo sync relay: a zero-knowledge store-and-forward
// mailbox for encrypted sync packets.
//
// It began as a port of a Python/FastAPI service that lived in the repository
// root, and speaks the wire protocol it established, unchanged.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lab517/noo-relay/internal/api"
	"github.com/lab517/noo-relay/internal/config"
	"github.com/lab517/noo-relay/internal/store"
)

// version is the release, and the one place it is written down: deploy.sh
// reads it from here to name release artefacts. Bump it in the commit that
// makes a release.
const version = "1.0.0"

// commit is stamped at build time by deploy.sh (-ldflags "-X main.commit=..."),
// so journalctl records exactly what is serving. Empty for a plain `go build`.
var commit = ""

func versionString() string {
	if commit == "" {
		return version
	}
	return version + " (" + commit + ")"
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("noo-relay", versionString())
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("noo-relay starting", "version", version, "commit", commit)
	api.Version = version

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	warnDefaultSecrets(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: api.New(cfg, st),
		// No WriteTimeout: a slow large-packet upload should not be cut off
		// mid-body. ReadHeaderTimeout still bounds a stalled client.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		tls := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
		slog.Info("listening", "addr", cfg.ListenAddr, "tls", tls, "database", cfg.DatabaseURL)
		if tls {
			errs <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		errs <- srv.ListenAndServe()
	}()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// warnDefaultSecrets shouts when the server is running with the built-in
// defaults. A known JWT secret lets anyone forge tokens for any user; a known
// admin token hands over the admin API. Config refuses them outright unless
// NOO_INSECURE_DEV is set, so this only ever fires in that mode.
func warnDefaultSecrets(cfg *config.Config) {
	jwtDefault, adminDefault := cfg.UsesDefaultSecrets()
	if jwtDefault {
		slog.Warn("NOO_JWT_SECRET is unset; using the built-in default. " +
			"Anyone who knows it can forge tokens for any user. " +
			"Set NOO_JWT_SECRET before exposing this server.")
	}
	if adminDefault {
		slog.Warn("NOO_ADMIN_TOKEN is unset; using the built-in default. " +
			"Set NOO_ADMIN_TOKEN before exposing this server.")
	}
}
