package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/discordapi"
	"nl-auth/internal/httpserver"
	"nl-auth/internal/security"
	"nl-auth/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string, logger *slog.Logger) error {
	if len(arguments) == 0 {
		return usageError()
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	database, err := store.Open(cfg.DatabasePath, cfg.Pepper, cfg.SessionTTL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	artifactManager, err := artifacts.New(cfg.ArtifactDirectory, cfg.ArtifactKey, cfg.SigningKey, cfg.MaxArtifactBytes)
	if err != nil {
		return err
	}

	switch arguments[0] {
	case "serve":
		return serve(cfg, database, artifactManager, logger)
	case "bootstrap-admin":
		return bootstrapAdmin(arguments[1:], database)
	case "license-issue":
		return issueLicense(arguments[1:], database)
	case "artifact-import":
		return importArtifact(arguments[1:], database, artifactManager)
	case "discord-register":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return discordapi.RegisterCommands(ctx, cfg)
	case "watermark-extract":
		return extractWatermark(arguments[1:], artifactManager)
	case "public-key":
		fmt.Println(base64.RawStdEncoding.EncodeToString(artifactManager.PublicKeySEC1()))
		return nil
	default:
		return usageError()
	}
}

func extractWatermark(arguments []string, artifactManager *artifacts.Manager) error {
	flags := flag.NewFlagSet("watermark-extract", flag.ContinueOnError)
	file := flags.String("file", "", "path to the leaked artifact copy")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("file is required")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	loaderID, err := artifactManager.ExtractWatermark(data)
	if err != nil {
		return err
	}
	fmt.Println(loaderID)
	return nil
}

func serve(cfg config.Config, database *store.Store, artifactManager *artifacts.Manager, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := httpserver.New(cfg, database, artifactManager, logger)
	go server.Background(ctx)

	serverError := make(chan error, 1)
	go func() {
		logger.Info("auth server listening", "address", cfg.ListenAddress)
		serverError <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func bootstrapAdmin(arguments []string, database *store.Store) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	username := flags.String("username", "admin", "administrator username")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	password := os.Getenv("NL_AUTH_BOOTSTRAP_PASSWORD")
	_ = os.Unsetenv("NL_AUTH_BOOTSTRAP_PASSWORD")
	if password == "" {
		return errors.New("NL_AUTH_BOOTSTRAP_PASSWORD is required")
	}
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	if err := database.BootstrapAdmin(context.Background(), *username, passwordHash); err != nil {
		return err
	}
	fmt.Println("administrator is ready")
	return nil
}

func issueLicense(arguments []string, database *store.Store) error {
	flags := flag.NewFlagSet("license-issue", flag.ContinueOnError)
	days := flags.Int("days", 30, "validity in days; zero means lifetime")
	devices := flags.Int("devices", 1, "maximum devices")
	note := flags.String("note", "", "internal note")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *days < 0 || *days > 3650 {
		return errors.New("days must be between zero and 3650")
	}
	key, err := database.IssueLicense(context.Background(), time.Duration(*days)*24*time.Hour, *devices, *note, "cli")
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}

func importArtifact(arguments []string, database *store.Store, artifactManager *artifacts.Manager) error {
	flags := flag.NewFlagSet("artifact-import", flag.ContinueOnError)
	file := flags.String("file", "", "source artifact path")
	version := flags.String("version", "", "artifact version")
	platform := flags.String("platform", "windows-x86", "artifact platform")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *file == "" || *version == "" {
		return errors.New("file and version are required")
	}
	artifact, err := artifactManager.Import(*file, *version, *platform)
	if err != nil {
		return err
	}
	if err := database.RegisterArtifact(context.Background(), artifact); err != nil {
		_ = artifactManager.Remove(artifact)
		return err
	}
	fmt.Printf("artifact %s registered: sha256=%s size=%s\n", artifact.Version, artifact.SHA256, strconv.FormatInt(artifact.Size, 10))
	return nil
}

func usageError() error {
	return errors.New("usage: nl-auth <serve|bootstrap-admin|license-issue|artifact-import|discord-register|watermark-extract|public-key>")
}
