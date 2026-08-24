package config

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress            string
	DatabasePath             string
	ArtifactDirectory        string
	ArtifactKey              []byte
	Pepper                   []byte
	SigningKey               *ecdsa.PrivateKey
	SigningKeyPath           string
	PublicURL                string
	CookieSecure             bool
	SessionTTL               time.Duration
	DownloadTicketTTL        time.Duration
	LoaderDownloadTTL        time.Duration
	HeartbeatTTL             time.Duration
	MaxArtifactBytes         int64
	LoaderTemplatePath       string
	DiscordPublicKeyHex      string
	DiscordAdminRoleID       string
	DiscordApplication       string
	DiscordGuildID           string
	DiscordBotToken          string
	DiscordBotTokenFile      string
	DiscordSecurityChannelID string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddress:            envOr("NL_AUTH_LISTEN", "127.0.0.1:8080"),
		DatabasePath:             envOr("NL_AUTH_DB", "/var/lib/nl-auth/auth.db"),
		ArtifactDirectory:        envOr("NL_AUTH_ARTIFACT_DIR", "/var/lib/nl-auth/artifacts"),
		SigningKeyPath:           envOr("NL_AUTH_SIGNING_KEY", "/etc/nl-auth/signing-key.pem"),
		PublicURL:                strings.TrimRight(envOr("NL_AUTH_PUBLIC_URL", "http://127.0.0.1:8080"), "/"),
		SessionTTL:               durationOr("NL_AUTH_SESSION_TTL", 15*time.Minute),
		DownloadTicketTTL:        durationOr("NL_AUTH_DOWNLOAD_TTL", 60*time.Second),
		LoaderDownloadTTL:        durationOr("NL_AUTH_LOADER_DOWNLOAD_TTL", 5*time.Minute),
		HeartbeatTTL:             durationOr("NL_AUTH_HEARTBEAT_TTL", 30*24*time.Hour),
		MaxArtifactBytes:         int64Or("NL_AUTH_MAX_ARTIFACT_BYTES", 256<<20),
		LoaderTemplatePath:       envOr("NL_AUTH_LOADER_TEMPLATE", "/opt/nl-auth/loader-template/nl-loader.exe"),
		DiscordPublicKeyHex:      strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_PUBLIC_KEY")),
		DiscordAdminRoleID:       strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_ADMIN_ROLE_ID")),
		DiscordApplication:       strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_APPLICATION_ID")),
		DiscordGuildID:           strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_GUILD_ID")),
		DiscordBotToken:          strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_BOT_TOKEN")),
		DiscordBotTokenFile:      envOr("NL_AUTH_DISCORD_BOT_TOKEN_FILE", "/etc/nl-auth/discord-bot-token"),
		DiscordSecurityChannelID: strings.TrimSpace(os.Getenv("NL_AUTH_DISCORD_SECURITY_CHANNEL_ID")),
	}

	var err error
	cfg.PublicURL, cfg.CookieSecure, err = validatePublicURL(cfg.PublicURL)
	if err != nil {
		return Config{}, err
	}

	cfg.Pepper, err = decodeSecret("NL_AUTH_PEPPER", 32)
	if err != nil {
		return Config{}, err
	}
	cfg.ArtifactKey, err = decodeSecret("NL_AUTH_ARTIFACT_KEY", 32)
	if err != nil {
		return Config{}, err
	}
	cfg.SigningKey, err = loadSigningKey(cfg.SigningKeyPath)
	if err != nil {
		return Config{}, err
	}
	if cfg.DiscordBotToken == "" && cfg.DiscordSecurityChannelID != "" {
		cfg.DiscordBotToken, err = loadDiscordBotToken(cfg.DiscordBotTokenFile)
		if err != nil {
			return Config{}, err
		}
	}
	if err := validateDiscordConfig(cfg); err != nil {
		return Config{}, err
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o750); err != nil {
		return Config{}, fmt.Errorf("create database directory: %w", err)
	}
	if err := os.MkdirAll(cfg.ArtifactDirectory, 0o750); err != nil {
		return Config{}, fmt.Errorf("create artifact directory: %w", err)
	}

	return cfg, nil
}

func loadDiscordBotToken(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read Discord bot token file: %w", err)
	}
	if len(data) > 512 {
		return "", errors.New("Discord bot token file is too large")
	}
	token := strings.TrimSpace(string(data))
	if !validDiscordBotToken(token) {
		return "", errors.New("Discord bot token file has an invalid format")
	}
	return token, nil
}

func validateDiscordConfig(cfg Config) error {
	values := []string{
		cfg.DiscordPublicKeyHex,
		cfg.DiscordAdminRoleID,
		cfg.DiscordApplication,
		cfg.DiscordGuildID,
	}
	configured := 0
	for _, value := range values {
		if value != "" {
			configured++
		}
	}
	if configured != 0 && configured != len(values) {
		return errors.New("Discord integration requires public key, application ID, guild ID, and admin role ID")
	}
	if configured == len(values) {
		publicKey, err := hex.DecodeString(cfg.DiscordPublicKeyHex)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return errors.New("NL_AUTH_DISCORD_PUBLIC_KEY must be a 32-byte hexadecimal Ed25519 key")
		}
		for name, value := range map[string]string{
			"NL_AUTH_DISCORD_APPLICATION_ID": cfg.DiscordApplication,
			"NL_AUTH_DISCORD_GUILD_ID":       cfg.DiscordGuildID,
			"NL_AUTH_DISCORD_ADMIN_ROLE_ID":  cfg.DiscordAdminRoleID,
		} {
			if !validDiscordSnowflake(value) {
				return fmt.Errorf("%s must be a valid Discord snowflake", name)
			}
		}
	}
	if cfg.DiscordSecurityChannelID != "" {
		if !validDiscordSnowflake(cfg.DiscordSecurityChannelID) {
			return errors.New("NL_AUTH_DISCORD_SECURITY_CHANNEL_ID must be a valid Discord snowflake")
		}
		if !validDiscordBotToken(cfg.DiscordBotToken) {
			return errors.New("NL_AUTH_DISCORD_BOT_TOKEN is required and must have a valid format for security alerts")
		}
	}
	return nil
}

func validDiscordBotToken(value string) bool {
	return len(value) >= 20 && len(value) <= 256 && !strings.ContainsAny(value, " \t\r\n\x00")
}

func validDiscordSnowflake(value string) bool {
	if len(value) < 17 || len(value) > 20 || value[0] == '0' {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func validatePublicURL(value string) (string, bool, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", false, errors.New("NL_AUTH_PUBLIC_URL must be an HTTPS origin")
	}
	parsed.Path = ""
	hostname := parsed.Hostname()
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return strings.TrimRight(parsed.String(), "/"), true, nil
	case "http":
		address := net.ParseIP(hostname)
		if !strings.EqualFold(hostname, "localhost") && (address == nil || !address.IsLoopback()) {
			return "", false, errors.New("NL_AUTH_PUBLIC_URL only permits HTTP on loopback")
		}
		return strings.TrimRight(parsed.String(), "/"), false, nil
	default:
		return "", false, errors.New("NL_AUTH_PUBLIC_URL must use HTTPS")
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func int64Or(name string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func decodeSecret(name string, expectedBytes int) ([]byte, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) != expectedBytes {
		return nil, fmt.Errorf("%s must be base64-encoded %d bytes", name, expectedBytes)
	}
	return decoded, nil
}

func loadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key must be ECDSA")
	}
	return key, nil
}
