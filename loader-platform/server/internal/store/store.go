package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"nl-auth/internal/security"

	_ "modernc.org/sqlite"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrLicenseUnavailable  = errors.New("license is unavailable")
	ErrLicenseBound        = errors.New("license is already activated")
	ErrDeviceLimit         = errors.New("device limit reached")
	ErrDeviceRevoked       = errors.New("device is revoked")
	ErrSessionExpired      = errors.New("session expired")
	ErrTicketUnavailable   = errors.New("download ticket is unavailable")
	ErrDiscordBound        = errors.New("Discord account already has an active license")
	ErrLoaderUnavailable   = errors.New("loader is unavailable")
	ErrPairingRequired     = errors.New("device pairing is required")
	ErrPairingInvalid      = errors.New("device pairing code is invalid")
	ErrSecurityEventReplay = errors.New("security event was already processed")
)

type Store struct {
	db         *sql.DB
	pepper     []byte
	dummy      string
	sessionTTL time.Duration
}

type ClientContext struct {
	IP          string
	UserAgent   string
	ClientNonce string
	Version     string
}

type SessionResult struct {
	Token     string
	ExpiresAt time.Time
	Username  string
	Role      string
}

type AuthenticatedSession struct {
	ID               int64
	AccountID        int64
	DeviceID         int64
	LicenseID        int64
	LoaderInstanceID int64
	LoaderID         string
	Username         string
	Role             string
	DevicePublicKey  []byte
	ExpiresAt        time.Time
}

type Artifact struct {
	ID        int64
	Version   string
	Platform  string
	Path      string
	SHA256    string
	Size      int64
	Signature []byte
	CreatedAt time.Time
	Active    bool
}

type LicenseView struct {
	ID          int64
	Prefix      string
	Username    string
	Status      string
	ExpiresAt   *time.Time
	MaxDevices  int
	DeviceCount int
	Note        string
	CreatedAt   time.Time
}

type DashboardCounts struct {
	Users          int
	ActiveLicenses int
	Devices        int
	ActiveSessions int
}

type LoaderIssue struct {
	LoaderID      string
	DownloadToken string
	ExpiresAt     time.Time
}

type LoaderPackage struct {
	LoaderID             string
	CertificatePayload   []byte
	CertificateSignature []byte
	EnrollmentSecret     string
	HeartbeatToken       string
}

type LoaderDownloadInfo struct {
	LoaderID  string
	ExpiresAt time.Time
}

type TicketWatermark struct {
	SHA256 string
	Size   int64
}

type SecurityEventInput struct {
	EventID        string
	EventType      string
	Component      string
	ExpectedSHA256 string
	ObservedSHA256 string
	ClientVersion  string
	IP             string
}

type SecurityIncident struct {
	ID              int64
	EventID         string
	EventType       string
	Component       string
	ExpectedSHA256  string
	ObservedSHA256  string
	ClientVersion   string
	IP              string
	LoaderID        string
	DiscordID       string
	CreatedAt       time.Time
	Disposition     string
}

type SecurityAlert struct {
	ID        int64
	Kind      string
	Subject   string
	Message   string
	CreatedAt time.Time
}

type LoaderSigner func(loaderID string, licenseID int64, issuedAt time.Time) (payload []byte, signature []byte, err error)

func Open(path string, pepper []byte, sessionTTL time.Duration) (*Store, error) {
	if sessionTTL < time.Minute || sessionTTL > 24*time.Hour {
		return nil, errors.New("session TTL must be between one minute and 24 hours")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	dummy, err := security.HashPassword("dummy-password-that-is-never-valid")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{db: db, pepper: append([]byte(nil), pepper...), dummy: dummy, sessionTTL: sessionTTL}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username_display TEXT NOT NULL,
    username_canonical TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'banned')),
    discord_id TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash BLOB NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
    assigned_discord_id TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at INTEGER,
    max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices BETWEEN 1 AND 8),
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    activated_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_licenses_account ON licenses(account_id);
CREATE INDEX IF NOT EXISTS idx_licenses_prefix ON licenses(key_prefix);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    hwid_hash BLOB NOT NULL,
    loader_instance_id INTEGER REFERENCES loader_instances(id) ON DELETE SET NULL,
    public_key_sec1 BLOB,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER,
    UNIQUE(account_id, hwid_hash)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    loader_instance_id INTEGER REFERENCES loader_instances(id) ON DELETE CASCADE,
    client_nonce TEXT NOT NULL,
    client_version TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS auth_challenges (
    token_hash BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry ON auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE,
    csrf_hash BLOB NOT NULL,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip_address TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    storage_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    plaintext_size INTEGER NOT NULL,
    signature BLOB NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    UNIQUE(version, platform)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_latest ON artifacts(platform, active, created_at DESC);

CREATE TABLE IF NOT EXISTS download_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    client_public_key BLOB,
    watermark_sha256 TEXT NOT NULL DEFAULT '',
    watermark_size INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_download_tickets_expiry ON download_tickets(expires_at);

CREATE TABLE IF NOT EXISTS loader_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    loader_id TEXT NOT NULL UNIQUE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    license_id INTEGER NOT NULL UNIQUE REFERENCES licenses(id) ON DELETE CASCADE,
    certificate_payload BLOB NOT NULL,
    certificate_signature BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    download_token_hash BLOB UNIQUE,
    download_expires_at INTEGER,
	enrollment_secret_hash BLOB,
	enrollment_expires_at INTEGER,
	enrolled_at INTEGER,
    heartbeat_token_hash BLOB,
    heartbeat_expires_at INTEGER,
    downloaded_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loader_instances_account ON loader_instances(account_id);
CREATE INDEX IF NOT EXISTS idx_loader_instances_download ON loader_instances(download_token_hash);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    loader_instance_id INTEGER REFERENCES loader_instances(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    component TEXT NOT NULL,
    expected_sha256 TEXT NOT NULL,
    observed_sha256 TEXT NOT NULL,
    client_version TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT 'security_hold' CHECK (disposition IN ('security_hold', 'confirmed', 'dismissed')),
    discord_notified_at INTEGER,
    discord_attempts INTEGER NOT NULL DEFAULT 0,
    discord_last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_events_account ON security_events(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS device_bind_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    hwid_hash BLOB NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_bind_events_license ON device_bind_events(license_id, created_at);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    sent_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_security_alerts_pending ON security_alerts(sent_at, created_at);
CREATE INDEX IF NOT EXISTS idx_security_alerts_subject ON security_alerts(kind, subject, created_at);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "licenses", "assigned_discord_id", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "devices", "loader_instance_id", "INTEGER REFERENCES loader_instances(id) ON DELETE SET NULL"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "devices", "public_key_sec1", "BLOB"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "download_tickets", "client_public_key", "BLOB"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "sessions", "loader_instance_id", "INTEGER REFERENCES loader_instances(id) ON DELETE CASCADE"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "loader_instances", "enrollment_secret_hash", "BLOB"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "loader_instances", "enrollment_expires_at", "INTEGER"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "loader_instances", "enrolled_at", "INTEGER"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "download_tickets", "watermark_sha256", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "download_tickets", "watermark_size", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "loader_instances", "heartbeat_token_hash", "BLOB"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "loader_instances", "heartbeat_expires_at", "INTEGER"); err != nil {
		return err
	}
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_licenses_assigned_discord ON licenses(assigned_discord_id)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_loader ON devices(loader_instance_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_loader_public_key ON devices(loader_instance_id, public_key_sec1) WHERE loader_instance_id IS NOT NULL AND public_key_sec1 IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_loader ON sessions(loader_instance_id)`,
	}
	for _, statement := range indexes {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition)
	return err
}

func (s *Store) BootstrapAdmin(ctx context.Context, username, passwordHash string) error {
	display, canonical, err := security.NormalizeUsername(username)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO accounts(username_display, username_canonical, password_hash, role, status, created_at)
VALUES(?, ?, ?, 'admin', 'active', ?)
ON CONFLICT(username_canonical) DO UPDATE SET
    password_hash = excluded.password_hash,
    role = 'admin',
    status = 'active'`, display, canonical, passwordHash, now)
	if err == nil {
		s.audit(ctx, "system", "bootstrap", "admin.bootstrap", "account", canonical, "", nil)
	}
	return err
}

func (s *Store) RegisterChallenge(ctx context.Context, token string, expiresAt time.Time) error {
	if len(token) < 32 || expiresAt.Before(time.Now().UTC()) {
		return errors.New("invalid challenge")
	}
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO auth_challenges(token_hash, created_at, expires_at)
VALUES(?, ?, ?)`, security.Digest(s.pepper, token), now, expiresAt.Unix())
	return err
}

func (s *Store) ConsumeChallenge(ctx context.Context, token string) error {
	if len(token) < 32 || len(token) > 128 {
		return ErrInvalidCredentials
	}
	now := time.Now().UTC().Unix()
	result, err := s.db.ExecContext(ctx, `
UPDATE auth_challenges SET used_at = ?
WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, now, security.Digest(s.pepper, token), now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *Store) IssueLicense(ctx context.Context, validFor time.Duration, maxDevices int, note, actor string) (string, error) {
	return s.issueLicense(ctx, validFor, maxDevices, note, actor, "")
}

func (s *Store) IssueLicenseForDiscord(ctx context.Context, validFor time.Duration, maxDevices int, note, actor, discordID string) (string, error) {
	if !validDiscordID(discordID) {
		return "", errors.New("invalid Discord user ID")
	}
	return s.issueLicense(ctx, validFor, maxDevices, note, actor, discordID)
}

func (s *Store) issueLicense(ctx context.Context, validFor time.Duration, maxDevices int, note, actor, assignedDiscordID string) (string, error) {
	if maxDevices < 1 || maxDevices > 8 {
		return "", errors.New("max devices must be between 1 and 8")
	}
	if len(note) > 256 {
		return "", errors.New("note is too long")
	}
	key, err := security.LicenseKey()
	if err != nil {
		return "", err
	}
	normalized, _ := security.NormalizeLicense(key)
	digest := security.Digest(s.pepper, normalized)
	now := time.Now().UTC()
	var expiry any
	if validFor > 0 {
		expiry = now.Add(validFor).Unix()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO licenses(key_hash, key_prefix, assigned_discord_id, status, expires_at, max_devices, note, created_at)
VALUES(?, ?, NULLIF(?, ''), 'active', ?, ?, ?, ?)`, digest, normalized[:12], assignedDiscordID, expiry, maxDevices, strings.TrimSpace(note), now.Unix())
	if err != nil {
		return "", err
	}
	s.audit(ctx, "admin", actor, "license.issue", "license", normalized[:12], "", map[string]any{"max_devices": maxDevices, "valid_for_seconds": int64(validFor.Seconds()), "assigned_discord_id": assignedDiscordID})
	return key, nil
}

func (s *Store) ReissueLicenseForDiscord(ctx context.Context, discordID string, validFor time.Duration, maxDevices int, note, actor, ip string) (string, error) {
	if !validDiscordID(discordID) {
		return "", errors.New("invalid Discord user ID")
	}
	if maxDevices < 1 || maxDevices > 8 || len(note) > 256 {
		return "", errors.New("invalid license options")
	}
	key, err := security.LicenseKey()
	if err != nil {
		return "", err
	}
	normalized, _ := security.NormalizeLicense(key)
	now := time.Now().UTC()
	var expiry any
	if validFor > 0 {
		expiry = now.Add(validFor).Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var accountID sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE discord_id = ?`, discordID).Scan(&accountID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if accountID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`, now.Unix(), accountID.Int64); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE loader_instances SET status = 'revoked', download_token_hash = NULL, download_expires_at = NULL, enrollment_secret_hash = NULL, enrollment_expires_at = NULL, heartbeat_token_hash = NULL, heartbeat_expires_at = NULL WHERE account_id = ? AND status = 'active'`, accountID.Int64); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE licenses SET status = 'revoked' WHERE account_id = ? AND status = 'active'`, accountID.Int64); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE account_id = ?`, accountID.Int64); err != nil {
			return "", err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE licenses SET status = 'revoked' WHERE assigned_discord_id = ? AND account_id IS NULL AND status = 'active'`, discordID); err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO licenses(key_hash, key_prefix, assigned_discord_id, status, expires_at, max_devices, note, created_at)
VALUES(?, ?, ?, 'active', ?, ?, ?, ?)`, security.Digest(s.pepper, normalized), normalized[:12], discordID, expiry, maxDevices, strings.TrimSpace(note), now.Unix())
	if err != nil {
		return "", err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "license.reissue", "discord_user", discordID, ip, map[string]any{"max_devices": maxDevices, "valid_for_seconds": int64(validFor.Seconds())}); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return key, nil
}

func (s *Store) RedeemLicense(ctx context.Context, licenseKey, discordID string, ttl time.Duration, signer LoaderSigner, ip string) (LoaderIssue, error) {
	if !validDiscordID(discordID) || ttl < time.Minute || ttl > 24*time.Hour || signer == nil {
		return LoaderIssue{}, ErrLicenseUnavailable
	}
	normalized, err := security.NormalizeLicense(licenseKey)
	if err != nil {
		return LoaderIssue{}, ErrLicenseUnavailable
	}
	loaderID, err := security.RandomToken(18)
	if err != nil {
		return LoaderIssue{}, err
	}
	downloadToken, err := security.RandomToken(32)
	if err != nil {
		return LoaderIssue{}, err
	}
	randomPassword, err := security.RandomToken(48)
	if err != nil {
		return LoaderIssue{}, err
	}
	passwordHash, err := security.HashPassword(randomPassword)
	if err != nil {
		return LoaderIssue{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoaderIssue{}, err
	}
	defer tx.Rollback()

	var licenseID int64
	var accountID sql.NullInt64
	var assignedDiscordID string
	var status string
	var licenseExpiresAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
SELECT id, account_id, COALESCE(assigned_discord_id, ''), status, expires_at
FROM licenses WHERE key_hash = ?`, security.Digest(s.pepper, normalized)).
		Scan(&licenseID, &accountID, &assignedDiscordID, &status, &licenseExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoaderIssue{}, ErrLicenseUnavailable
	}
	if err != nil {
		return LoaderIssue{}, err
	}
	if status != "active" || (licenseExpiresAt.Valid && licenseExpiresAt.Int64 <= now.Unix()) ||
		(assignedDiscordID != "" && assignedDiscordID != discordID) {
		return LoaderIssue{}, ErrLicenseUnavailable
	}

	var resolvedAccountID int64
	if accountID.Valid {
		var linkedDiscordID, accountStatus string
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(discord_id, ''), status FROM accounts WHERE id = ?`, accountID.Int64).
			Scan(&linkedDiscordID, &accountStatus); err != nil {
			return LoaderIssue{}, err
		}
		if linkedDiscordID != discordID || accountStatus != "active" {
			return LoaderIssue{}, ErrLicenseBound
		}
		resolvedAccountID = accountID.Int64

		var existingLoaderID string
		err = tx.QueryRowContext(ctx, `
SELECT loader_id FROM loader_instances
WHERE license_id = ? AND account_id = ? AND status = 'active'`, licenseID, resolvedAccountID).
			Scan(&existingLoaderID)
		if err == nil {
			if _, err := tx.ExecContext(ctx, `
			UPDATE loader_instances
			SET download_token_hash = ?, download_expires_at = ?,
			    enrollment_secret_hash = NULL, enrollment_expires_at = NULL
			WHERE loader_id = ? AND status = 'active'`,
				security.Digest(s.pepper, downloadToken), expiresAt.Unix(), existingLoaderID); err != nil {
				return LoaderIssue{}, err
			}
			if err := s.auditTx(ctx, tx, "discord", discordID, "loader.download.issue", "loader", existingLoaderID, ip, map[string]any{"reason": "redeem_repeat"}); err != nil {
				return LoaderIssue{}, err
			}
			if err := tx.Commit(); err != nil {
				return LoaderIssue{}, err
			}
			return LoaderIssue{LoaderID: existingLoaderID, DownloadToken: downloadToken, ExpiresAt: expiresAt}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return LoaderIssue{}, err
		}
	} else {
		var accountStatus string
		err = tx.QueryRowContext(ctx, `SELECT id, status FROM accounts WHERE discord_id = ?`, discordID).
			Scan(&resolvedAccountID, &accountStatus)
		if errors.Is(err, sql.ErrNoRows) {
			username := "discord_" + discordID
			result, err := tx.ExecContext(ctx, `
INSERT INTO accounts(username_display, username_canonical, password_hash, role, status, discord_id, created_at)
VALUES(?, ?, ?, 'user', 'active', ?, ?)`, username, username, passwordHash, discordID, now.Unix())
			if err != nil {
				return LoaderIssue{}, err
			}
			resolvedAccountID, err = result.LastInsertId()
			if err != nil {
				return LoaderIssue{}, err
			}
		} else if err != nil {
			return LoaderIssue{}, err
		} else if accountStatus != "active" {
			return LoaderIssue{}, ErrLicenseUnavailable
		}

		var activeLicenses int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(1) FROM licenses
WHERE account_id = ? AND id != ? AND status = 'active'
  AND (expires_at IS NULL OR expires_at > ?)`, resolvedAccountID, licenseID, now.Unix()).Scan(&activeLicenses); err != nil {
			return LoaderIssue{}, err
		}
		if activeLicenses != 0 {
			return LoaderIssue{}, ErrDiscordBound
		}

		result, err := tx.ExecContext(ctx, `
UPDATE licenses
SET account_id = ?, assigned_discord_id = ?, activated_at = ?
WHERE id = ? AND account_id IS NULL`, resolvedAccountID, discordID, now.Unix(), licenseID)
		if err != nil {
			return LoaderIssue{}, err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return LoaderIssue{}, ErrLicenseBound
		}
	}

	payload, signature, err := signer(loaderID, licenseID, now)
	if err != nil {
		return LoaderIssue{}, err
	}
	if len(payload) == 0 || len(payload) > 4096 || len(signature) != 64 {
		return LoaderIssue{}, errors.New("invalid loader certificate")
	}
	_, err = tx.ExecContext(ctx, `
	INSERT INTO loader_instances(
	    loader_id, account_id, license_id, certificate_payload, certificate_signature,
	    status, download_token_hash, download_expires_at, created_at
	)
	VALUES(?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		loaderID, resolvedAccountID, licenseID, payload, signature,
		security.Digest(s.pepper, downloadToken), expiresAt.Unix(), now.Unix())
	if err != nil {
		return LoaderIssue{}, err
	}
	if err := s.auditTx(ctx, tx, "discord", discordID, "license.redeem", "license", fmt.Sprint(licenseID), ip, map[string]any{"loader_id": loaderID}); err != nil {
		return LoaderIssue{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoaderIssue{}, err
	}
	return LoaderIssue{LoaderID: loaderID, DownloadToken: downloadToken, ExpiresAt: expiresAt}, nil
}

func (s *Store) RenewLoaderDownloadByDiscordID(ctx context.Context, discordID string, ttl time.Duration, ip string) (LoaderIssue, error) {
	if !validDiscordID(discordID) || ttl < time.Minute || ttl > 24*time.Hour {
		return LoaderIssue{}, ErrLoaderUnavailable
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return LoaderIssue{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoaderIssue{}, err
	}
	defer tx.Rollback()

	var loaderID string
	err = tx.QueryRowContext(ctx, `
SELECT li.loader_id
FROM loader_instances li
JOIN accounts a ON a.id = li.account_id
JOIN licenses l ON l.id = li.license_id
WHERE a.discord_id = ? AND a.status = 'active'
  AND li.status = 'active'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)
ORDER BY li.created_at DESC LIMIT 1`, discordID, now.Unix()).Scan(&loaderID)
	if errors.Is(err, sql.ErrNoRows) {
		return LoaderIssue{}, ErrLoaderUnavailable
	}
	if err != nil {
		return LoaderIssue{}, err
	}
	result, err := tx.ExecContext(ctx, `
	UPDATE loader_instances
	SET download_token_hash = ?, download_expires_at = ?,
	    enrollment_secret_hash = NULL, enrollment_expires_at = NULL
	WHERE loader_id = ? AND status = 'active'`,
		security.Digest(s.pepper, token), expiresAt.Unix(), loaderID)
	if err != nil {
		return LoaderIssue{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return LoaderIssue{}, ErrLoaderUnavailable
	}
	if err := s.auditTx(ctx, tx, "discord", discordID, "loader.download.issue", "loader", loaderID, ip, map[string]any{"reason": "self_service"}); err != nil {
		return LoaderIssue{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoaderIssue{}, err
	}
	return LoaderIssue{LoaderID: loaderID, DownloadToken: token, ExpiresAt: expiresAt}, nil
}

func (s *Store) PeekLoaderDownload(ctx context.Context, token string) (LoaderDownloadInfo, error) {
	if len(token) < 32 || len(token) > 128 {
		return LoaderDownloadInfo{}, ErrLoaderUnavailable
	}
	now := time.Now().UTC()
	var info LoaderDownloadInfo
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `
SELECT li.loader_id, li.download_expires_at
FROM loader_instances li
JOIN accounts a ON a.id = li.account_id
JOIN licenses l ON l.id = li.license_id
WHERE li.download_token_hash = ?
  AND li.download_expires_at > ?
  AND li.status = 'active'
  AND a.status = 'active'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)`, security.Digest(s.pepper, token), now.Unix(), now.Unix()).
		Scan(&info.LoaderID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoaderDownloadInfo{}, ErrLoaderUnavailable
	}
	if err != nil {
		return LoaderDownloadInfo{}, err
	}
	info.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return info, nil
}

func (s *Store) ConsumeLoaderDownload(ctx context.Context, token string, heartbeatTTL time.Duration) (LoaderPackage, error) {
	if len(token) < 32 || len(token) > 128 {
		return LoaderPackage{}, ErrLoaderUnavailable
	}
	enrollmentSecret, err := security.RandomToken(18)
	if err != nil {
		return LoaderPackage{}, err
	}
	heartbeatToken, err := security.RandomToken(32)
	if err != nil {
		return LoaderPackage{}, err
	}
	now := time.Now().UTC()
	enrollmentExpiresAt := now.Add(15 * time.Minute)
	heartbeatExpiresAt := now.Add(heartbeatTTL)
	digest := security.Digest(s.pepper, token)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LoaderPackage{}, err
	}
	defer tx.Rollback()

	var result LoaderPackage
	err = tx.QueryRowContext(ctx, `
SELECT li.loader_id, li.certificate_payload, li.certificate_signature
FROM loader_instances li
JOIN accounts a ON a.id = li.account_id
JOIN licenses l ON l.id = li.license_id
WHERE li.download_token_hash = ?
  AND li.download_expires_at > ?
  AND li.status = 'active'
  AND a.status = 'active'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)`, digest, now.Unix(), now.Unix()).
		Scan(&result.LoaderID, &result.CertificatePayload, &result.CertificateSignature)
	if errors.Is(err, sql.ErrNoRows) {
		return LoaderPackage{}, ErrLoaderUnavailable
	}
	if err != nil {
		return LoaderPackage{}, err
	}
	if len(result.CertificatePayload) == 0 || len(result.CertificatePayload) > 4096 || len(result.CertificateSignature) != 64 {
		return LoaderPackage{}, ErrLoaderUnavailable
	}
	result.EnrollmentSecret = enrollmentSecret
	result.HeartbeatToken = heartbeatToken
	update, err := tx.ExecContext(ctx, `
UPDATE loader_instances
SET download_token_hash = NULL, download_expires_at = NULL, downloaded_at = ?,
    enrollment_secret_hash = ?, enrollment_expires_at = ?,
    heartbeat_token_hash = ?, heartbeat_expires_at = ?
WHERE download_token_hash = ? AND status = 'active'`,
		now.Unix(), security.Digest(s.pepper, enrollmentSecret), enrollmentExpiresAt.Unix(),
		security.Digest(s.pepper, heartbeatToken), heartbeatExpiresAt.Unix(), digest)
	if err != nil {
		return LoaderPackage{}, err
	}
	rows, err := update.RowsAffected()
	if err != nil || rows != 1 {
		return LoaderPackage{}, ErrLoaderUnavailable
	}
	if err := tx.Commit(); err != nil {
		return LoaderPackage{}, err
	}
	return result, nil
}

// ValidateHeartbeat checks a runtime heartbeat token presented by a personal
// loader. On success it slides the token expiry forward and returns nil.
func (s *Store) ValidateHeartbeat(ctx context.Context, loaderID, heartbeatToken string, renewFor time.Duration) error {
	if !validLoaderID(loaderID) || len(heartbeatToken) < 32 || len(heartbeatToken) > 128 || renewFor < time.Hour {
		return ErrLoaderUnavailable
	}
	now := time.Now().UTC()
	digest := security.Digest(s.pepper, heartbeatToken)
	result, err := s.db.ExecContext(ctx, `
UPDATE loader_instances
SET heartbeat_expires_at = ?
WHERE loader_id = ?
  AND heartbeat_token_hash = ?
  AND heartbeat_expires_at > ?
  AND status = 'active'
  AND EXISTS(
      SELECT 1 FROM accounts a
      WHERE a.id = loader_instances.account_id AND a.status = 'active'
  )
  AND EXISTS(
      SELECT 1 FROM licenses l
      WHERE l.id = loader_instances.license_id AND l.status = 'active'
        AND (l.expires_at IS NULL OR l.expires_at > ?)
  )`, now.Add(renewFor).Unix(), loaderID, digest, now.Unix(), now.Unix())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrLoaderUnavailable
	}
	return nil
}

// ReportViolation processes a runtime tamper report presented by the personal
// loader watchdog. The report is authenticated with the heartbeat token, so
// only the legitimate loader of this instance can file it. On success the
// account is banned, every session is revoked, and a Discord alert is queued.
func (s *Store) ReportViolation(ctx context.Context, loaderID, heartbeatToken, reason, ip string) error {
	if !validLoaderID(loaderID) || len(heartbeatToken) < 32 || len(heartbeatToken) > 128 {
		return ErrLoaderUnavailable
	}
	reason = truncate(strings.TrimSpace(reason), 256)
	if reason == "" {
		reason = "unspecified"
	}
	now := time.Now().UTC()
	digest := security.Digest(s.pepper, heartbeatToken)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var accountID int64
	var discordID string
	err = tx.QueryRowContext(ctx, `
SELECT li.account_id, COALESCE(a.discord_id, '')
FROM loader_instances li
JOIN accounts a ON a.id = li.account_id
WHERE li.loader_id = ?
  AND li.heartbeat_token_hash = ?
  AND li.status = 'active'`, loaderID, digest).Scan(&accountID, &discordID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLoaderUnavailable
	}
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET status = 'banned' WHERE id = ? AND role != 'admin'`, accountID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`, now.Unix(), accountID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE loader_instances
SET status = 'revoked', download_token_hash = NULL, download_expires_at = NULL,
    enrollment_secret_hash = NULL, enrollment_expires_at = NULL,
    heartbeat_token_hash = NULL, heartbeat_expires_at = NULL
WHERE account_id = ? AND status = 'active'`, accountID); err != nil {
		return err
	}

	user := "not linked"
	if discordID != "" {
		user = "<@" + discordID + ">"
	}
	message := fmt.Sprintf(
		"RUNTIME TAMPER DETECTED\nUser: %s\nLoader: `%s`\nReason: `%s`\nIP: `%s`\nThe account was banned automatically. Review before restoring.",
		user, loaderID, reason, maskIPText(ip))
	if _, err := tx.ExecContext(ctx, `
INSERT INTO security_alerts(kind, subject, message, created_at)
VALUES('tamper', ?, ?, ?)`, loaderID, truncate(message, 1900), now.Unix()); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "loader", loaderID, "security.tamper", "account", fmt.Sprint(accountID), ip, map[string]any{"reason": reason}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LoginLoader(ctx context.Context, loaderID string, certificatePayload, certificateSignature []byte, hwidHash string, publicKeySEC1 []byte, pairingCode string, client ClientContext) (SessionResult, error) {
	if !validLoaderID(loaderID) || len(certificatePayload) == 0 || len(certificatePayload) > 4096 ||
		len(certificateSignature) != 64 || len(publicKeySEC1) != 65 {
		return SessionResult{}, ErrInvalidCredentials
	}
	pairingCode = strings.TrimSpace(pairingCode)
	if pairingCode != "" && !validPairingCode(pairingCode) {
		return SessionResult{}, ErrPairingInvalid
	}
	normalizedHWID, err := security.NormalizeHWID(hwidHash)
	if err != nil {
		return SessionResult{}, ErrInvalidCredentials
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionResult{}, err
	}
	defer tx.Rollback()

	var loaderInstanceID, accountID, licenseID int64
	var username, role string
	var maxDevices int
	var enrollmentSecretHash []byte
	var enrollmentExpiresAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
SELECT li.id, li.account_id, li.license_id, a.username_display, a.role, l.max_devices,
       li.enrollment_secret_hash, li.enrollment_expires_at
FROM loader_instances li
JOIN accounts a ON a.id = li.account_id
JOIN licenses l ON l.id = li.license_id
WHERE li.loader_id = ?
  AND li.certificate_payload = ?
  AND li.certificate_signature = ?
  AND li.status = 'active'
  AND a.status = 'active'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)`,
		loaderID, certificatePayload, certificateSignature, now.Unix()).
		Scan(&loaderInstanceID, &accountID, &licenseID, &username, &role, &maxDevices,
			&enrollmentSecretHash, &enrollmentExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return SessionResult{}, err
	}

	deviceID, err := s.bindLoaderDeviceTx(ctx, tx, accountID, loaderInstanceID, normalizedHWID,
		publicKeySEC1, pairingCode, enrollmentSecretHash, enrollmentExpiresAt, maxDevices, now)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, ErrDeviceLimit) || errors.Is(err, ErrDeviceRevoked) || errors.Is(err, ErrPairingInvalid) {
			background := context.Background()
			hwidDigest := security.Digest(s.pepper, normalizedHWID)
			_ = s.RecordDeviceBindEvent(background, licenseID, hwidDigest, client.IP, false)
			if errors.Is(err, ErrDeviceLimit) || errors.Is(err, ErrDeviceRevoked) {
				_, _ = s.RegisterMultiHWIDAlert(background, licenseID, loaderID, 24*time.Hour)
			}
		}
		return SessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE sessions SET revoked_at = ?
WHERE loader_instance_id = ? AND revoked_at IS NULL`, now.Unix(), loaderInstanceID); err != nil {
		return SessionResult{}, err
	}
	session, err := s.createSessionTx(ctx, tx, accountID, deviceID, licenseID,
		sql.NullInt64{Int64: loaderInstanceID, Valid: true}, username, role, client, now)
	if err != nil {
		return SessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET last_login_at = ? WHERE id = ?`, now.Unix(), accountID); err != nil {
		return SessionResult{}, err
	}
	if err := s.auditTx(ctx, tx, "loader", loaderID, "session.login", "account", fmt.Sprint(accountID), client.IP, map[string]any{"client_version": client.Version}); err != nil {
		return SessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionResult{}, err
	}
	_ = s.RecordDeviceBindEvent(context.Background(), licenseID, security.Digest(s.pepper, normalizedHWID), client.IP, true)
	return session, nil
}

func (s *Store) bindLoaderDeviceTx(ctx context.Context, tx *sql.Tx, accountID, loaderInstanceID int64, normalizedHWID string,
	publicKeySEC1 []byte, pairingCode string, enrollmentSecretHash []byte, enrollmentExpiresAt sql.NullInt64,
	maxDevices int, now time.Time) (int64, error) {
	hwidDigest := security.Digest(s.pepper, normalizedHWID)
	var deviceID int64
	var linkedLoaderID sql.NullInt64
	var storedPublicKey []byte
	var revokedAt sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT id, loader_instance_id, public_key_sec1, revoked_at
FROM devices WHERE account_id = ? AND hwid_hash = ?`, accountID, hwidDigest).
		Scan(&deviceID, &linkedLoaderID, &storedPublicKey, &revokedAt)
	if err == nil {
		if revokedAt.Valid {
			return 0, ErrDeviceRevoked
		}
		if linkedLoaderID.Valid || len(storedPublicKey) != 0 {
			if !linkedLoaderID.Valid || linkedLoaderID.Int64 != loaderInstanceID || !hmacEqual(storedPublicKey, publicKeySEC1) {
				return 0, ErrInvalidCredentials
			}
		} else {
			if err := s.validatePairingCode(pairingCode, enrollmentSecretHash, enrollmentExpiresAt, now); err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET loader_instance_id = ?, public_key_sec1 = ? WHERE id = ?`, loaderInstanceID, publicKeySEC1, deviceID); err != nil {
				return 0, err
			}
			if err := consumePairingCodeTx(ctx, tx, loaderInstanceID, enrollmentSecretHash, now); err != nil {
				return 0, err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, now.Unix(), deviceID)
		return deviceID, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err := s.validatePairingCode(pairingCode, enrollmentSecretHash, enrollmentExpiresAt, now); err != nil {
		return 0, err
	}

	var activeDevices int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM devices WHERE account_id = ? AND revoked_at IS NULL`, accountID).Scan(&activeDevices); err != nil {
		return 0, err
	}
	if activeDevices >= maxDevices {
		return 0, ErrDeviceLimit
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO devices(account_id, hwid_hash, loader_instance_id, public_key_sec1, first_seen_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?)`, accountID, hwidDigest, loaderInstanceID, publicKeySEC1, now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	deviceID, err = result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := consumePairingCodeTx(ctx, tx, loaderInstanceID, enrollmentSecretHash, now); err != nil {
		return 0, err
	}
	return deviceID, nil
}

func (s *Store) validatePairingCode(code string, expectedHash []byte, expiresAt sql.NullInt64, now time.Time) error {
	if code == "" {
		return ErrPairingRequired
	}
	if !validPairingCode(code) || len(expectedHash) == 0 || !expiresAt.Valid || expiresAt.Int64 <= now.Unix() ||
		!hmacEqual(expectedHash, security.Digest(s.pepper, code)) {
		return ErrPairingInvalid
	}
	return nil
}

func consumePairingCodeTx(ctx context.Context, tx *sql.Tx, loaderInstanceID int64, expectedHash []byte, now time.Time) error {
	result, err := tx.ExecContext(ctx, `
UPDATE loader_instances
SET enrollment_secret_hash = NULL, enrollment_expires_at = NULL,
    enrolled_at = COALESCE(enrolled_at, ?)
WHERE id = ? AND enrollment_secret_hash = ? AND enrollment_expires_at > ?`,
		now.Unix(), loaderInstanceID, expectedHash, now.Unix())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrPairingInvalid
	}
	return nil
}

func (s *Store) Activate(ctx context.Context, username, password, licenseKey, hwidHash string, client ClientContext) (SessionResult, error) {
	display, canonical, err := security.NormalizeUsername(username)
	if err != nil {
		return SessionResult{}, ErrInvalidCredentials
	}
	normalizedLicense, err := security.NormalizeLicense(licenseKey)
	if err != nil {
		return SessionResult{}, ErrInvalidCredentials
	}
	normalizedHWID, err := security.NormalizeHWID(hwidHash)
	if err != nil {
		return SessionResult{}, err
	}
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return SessionResult{}, err
	}

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionResult{}, err
	}
	defer tx.Rollback()

	licenseDigest := security.Digest(s.pepper, normalizedLicense)
	var licenseID int64
	var accountID sql.NullInt64
	var assignedDiscordID sql.NullString
	var status string
	var expiresAt sql.NullInt64
	var maxDevices int
	err = tx.QueryRowContext(ctx, `SELECT id, account_id, assigned_discord_id, status, expires_at, max_devices FROM licenses WHERE key_hash = ?`, licenseDigest).
		Scan(&licenseID, &accountID, &assignedDiscordID, &status, &expiresAt, &maxDevices)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionResult{}, ErrLicenseUnavailable
	}
	if err != nil {
		return SessionResult{}, err
	}
	if status != "active" || (expiresAt.Valid && expiresAt.Int64 <= now.Unix()) {
		return SessionResult{}, ErrLicenseUnavailable
	}
	if assignedDiscordID.Valid && assignedDiscordID.String != "" {
		return SessionResult{}, ErrLicenseUnavailable
	}
	if accountID.Valid {
		return SessionResult{}, ErrLicenseBound
	}

	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM accounts WHERE username_canonical = ?`, canonical).Scan(&existing); err != nil {
		return SessionResult{}, err
	}
	if existing != 0 {
		return SessionResult{}, ErrInvalidCredentials
	}

	result, err := tx.ExecContext(ctx, `
INSERT INTO accounts(username_display, username_canonical, password_hash, role, status, created_at)
VALUES(?, ?, ?, 'user', 'active', ?)`, display, canonical, passwordHash, now.Unix())
	if err != nil {
		return SessionResult{}, err
	}
	newAccountID, err := result.LastInsertId()
	if err != nil {
		return SessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE licenses SET account_id = ?, activated_at = ? WHERE id = ? AND account_id IS NULL`, newAccountID, now.Unix(), licenseID); err != nil {
		return SessionResult{}, err
	}
	deviceID, err := s.bindDeviceTx(ctx, tx, newAccountID, normalizedHWID, maxDevices, now)
	if err != nil {
		return SessionResult{}, err
	}
	session, err := s.createSessionTx(ctx, tx, newAccountID, deviceID, licenseID, sql.NullInt64{}, display, "user", client, now)
	if err != nil {
		return SessionResult{}, err
	}
	if err := s.auditTx(ctx, tx, "user", fmt.Sprint(newAccountID), "account.activate", "license", fmt.Sprint(licenseID), client.IP, map[string]any{"client_version": client.Version}); err != nil {
		return SessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionResult{}, err
	}
	return session, nil
}

func (s *Store) Login(ctx context.Context, username, password, licenseKey, hwidHash string, client ClientContext) (SessionResult, error) {
	_, canonical, err := security.NormalizeUsername(username)
	if err != nil {
		security.VerifyPassword(s.dummy, password)
		return SessionResult{}, ErrInvalidCredentials
	}
	normalizedLicense, err := security.NormalizeLicense(licenseKey)
	if err != nil {
		security.VerifyPassword(s.dummy, password)
		return SessionResult{}, ErrInvalidCredentials
	}
	normalizedHWID, err := security.NormalizeHWID(hwidHash)
	if err != nil {
		return SessionResult{}, err
	}

	var accountID int64
	var display, passwordHash, role, accountStatus string
	err = s.db.QueryRowContext(ctx, `
SELECT id, username_display, password_hash, role, status
FROM accounts WHERE username_canonical = ?`, canonical).
		Scan(&accountID, &display, &passwordHash, &role, &accountStatus)
	if errors.Is(err, sql.ErrNoRows) {
		security.VerifyPassword(s.dummy, password)
		return SessionResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return SessionResult{}, err
	}
	if !security.VerifyPassword(passwordHash, password) || accountStatus != "active" {
		return SessionResult{}, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionResult{}, err
	}
	defer tx.Rollback()

	licenseDigest := security.Digest(s.pepper, normalizedLicense)
	var licenseID int64
	var licenseStatus string
	var expiresAt sql.NullInt64
	var maxDevices int
	err = tx.QueryRowContext(ctx, `
SELECT id, status, expires_at, max_devices
FROM licenses WHERE key_hash = ? AND account_id = ?`, licenseDigest, accountID).
		Scan(&licenseID, &licenseStatus, &expiresAt, &maxDevices)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return SessionResult{}, err
	}
	if licenseStatus != "active" || (expiresAt.Valid && expiresAt.Int64 <= now.Unix()) {
		return SessionResult{}, ErrLicenseUnavailable
	}
	deviceID, err := s.bindDeviceTx(ctx, tx, accountID, normalizedHWID, maxDevices, now)
	if err != nil {
		return SessionResult{}, err
	}
	session, err := s.createSessionTx(ctx, tx, accountID, deviceID, licenseID, sql.NullInt64{}, display, role, client, now)
	if err != nil {
		return SessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET last_login_at = ? WHERE id = ?`, now.Unix(), accountID); err != nil {
		return SessionResult{}, err
	}
	if err := s.auditTx(ctx, tx, "user", fmt.Sprint(accountID), "session.login", "session", "", client.IP, map[string]any{"client_version": client.Version}); err != nil {
		return SessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionResult{}, err
	}
	return session, nil
}

func (s *Store) bindDeviceTx(ctx context.Context, tx *sql.Tx, accountID int64, normalizedHWID string, maxDevices int, now time.Time) (int64, error) {
	hwidDigest := security.Digest(s.pepper, normalizedHWID)
	var deviceID int64
	var revokedAt sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id, revoked_at FROM devices WHERE account_id = ? AND hwid_hash = ?`, accountID, hwidDigest).
		Scan(&deviceID, &revokedAt)
	if err == nil {
		if revokedAt.Valid {
			return 0, ErrDeviceRevoked
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, now.Unix(), deviceID)
		return deviceID, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	var activeDevices int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM devices WHERE account_id = ? AND revoked_at IS NULL`, accountID).Scan(&activeDevices); err != nil {
		return 0, err
	}
	if activeDevices >= maxDevices {
		return 0, ErrDeviceLimit
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO devices(account_id, hwid_hash, first_seen_at, last_seen_at)
VALUES(?, ?, ?, ?)`, accountID, hwidDigest, now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) createSessionTx(ctx context.Context, tx *sql.Tx, accountID, deviceID, licenseID int64, loaderInstanceID sql.NullInt64, username, role string, client ClientContext, now time.Time) (SessionResult, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return SessionResult{}, err
	}
	expiresAt := now.Add(s.sessionTTL)
	_, err = tx.ExecContext(ctx, `
INSERT INTO sessions(token_hash, account_id, device_id, license_id, loader_instance_id, client_nonce, client_version, ip_address, user_agent, created_at, last_seen_at, expires_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		security.Digest(s.pepper, token), accountID, deviceID, licenseID,
		loaderInstanceID, client.ClientNonce, client.Version, client.IP, truncate(client.UserAgent, 256),
		now.Unix(), now.Unix(), expiresAt.Unix())
	if err != nil {
		return SessionResult{}, err
	}
	return SessionResult{Token: token, ExpiresAt: expiresAt, Username: username, Role: role}, nil
}

func (s *Store) AuthenticateSession(ctx context.Context, token string) (AuthenticatedSession, error) {
	if len(token) < 32 || len(token) > 128 {
		return AuthenticatedSession{}, ErrSessionExpired
	}
	now := time.Now().UTC()
	var result AuthenticatedSession
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `
SELECT s.id, s.account_id, s.device_id, s.license_id, COALESCE(s.loader_instance_id, 0),
       COALESCE(li.loader_id, ''),
       a.username_display, a.role, d.public_key_sec1, s.expires_at
FROM sessions s
JOIN accounts a ON a.id = s.account_id
JOIN licenses l ON l.id = s.license_id
JOIN devices d ON d.id = s.device_id
LEFT JOIN loader_instances li ON li.id = s.loader_instance_id
WHERE s.token_hash = ?
  AND s.revoked_at IS NULL
  AND s.expires_at > ?
  AND a.status = 'active'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)
  AND d.revoked_at IS NULL
  AND (s.loader_instance_id IS NULL OR (
      li.status = 'active'
      AND li.account_id = s.account_id
      AND li.license_id = s.license_id
      AND d.loader_instance_id = s.loader_instance_id
  ))`, security.Digest(s.pepper, token), now.Unix(), now.Unix()).
	Scan(&result.ID, &result.AccountID, &result.DeviceID, &result.LicenseID, &result.LoaderInstanceID,
		&result.LoaderID, &result.Username, &result.Role, &result.DevicePublicKey, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedSession{}, ErrSessionExpired
	}
	if err != nil {
		return AuthenticatedSession{}, err
	}
	result.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?`, now.Unix(), result.ID, now.Add(-time.Minute).Unix())
	return result, nil
}

func (s *Store) Logout(ctx context.Context, sessionID int64, ip string) error {
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, sessionID)
	if err == nil {
		s.audit(ctx, "user", "", "session.logout", "session", fmt.Sprint(sessionID), ip, nil)
	}
	return err
}

// ApplySecurityEvent atomically records a device-signed integrity incident,
// disables the affected non-admin account, and revokes every active session.
func (s *Store) ApplySecurityEvent(ctx context.Context, sessionID int64, input SecurityEventInput) (SecurityIncident, error) {
	if sessionID <= 0 || !validSecurityEventInput(input) {
		return SecurityIncident{}, ErrInvalidCredentials
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SecurityIncident{}, err
	}
	defer tx.Rollback()

	var accountID, deviceID, loaderInstanceID int64
	var loaderID, discordID string
	err = tx.QueryRowContext(ctx, `
SELECT s.account_id, s.device_id, s.loader_instance_id, li.loader_id, COALESCE(a.discord_id, '')
FROM sessions s
JOIN accounts a ON a.id = s.account_id
JOIN licenses l ON l.id = s.license_id AND l.account_id = s.account_id
JOIN devices d ON d.id = s.device_id AND d.account_id = s.account_id
JOIN loader_instances li ON li.id = s.loader_instance_id
WHERE s.id = ?
  AND s.revoked_at IS NULL
  AND s.expires_at > ?
  AND a.status = 'active'
  AND a.role != 'admin'
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)
  AND d.revoked_at IS NULL
  AND d.loader_instance_id = s.loader_instance_id
  AND length(d.public_key_sec1) = 65
  AND li.status = 'active'
  AND li.account_id = s.account_id
  AND li.license_id = s.license_id`, sessionID, now.Unix(), now.Unix()).
		Scan(&accountID, &deviceID, &loaderInstanceID, &loaderID, &discordID)
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityIncident{}, ErrSessionExpired
	}
	if err != nil {
		return SecurityIncident{}, err
	}

	result, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO security_events(
    event_id, account_id, device_id, session_id, loader_instance_id,
    event_type, component, expected_sha256, observed_sha256,
    client_version, ip_address, disposition, created_at
)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'security_hold', ?)`,
		input.EventID, accountID, deviceID, sessionID, loaderInstanceID,
		input.EventType, input.Component, input.ExpectedSHA256, input.ObservedSHA256,
		truncate(input.ClientVersion, 64), truncate(input.IP, 64), now.Unix())
	if err != nil {
		return SecurityIncident{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return SecurityIncident{}, err
	}
	if rows != 1 {
		return SecurityIncident{}, ErrSecurityEventReplay
	}
	incidentID, err := result.LastInsertId()
	if err != nil {
		return SecurityIncident{}, err
	}

	update, err := tx.ExecContext(ctx, `UPDATE accounts SET status = 'disabled' WHERE id = ? AND status = 'active' AND role != 'admin'`, accountID)
	if err != nil {
		return SecurityIncident{}, err
	}
	rows, err = update.RowsAffected()
	if err != nil || rows != 1 {
		return SecurityIncident{}, ErrSessionExpired
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`, now.Unix(), accountID); err != nil {
		return SecurityIncident{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE loader_instances
SET download_token_hash = NULL, download_expires_at = NULL,
    enrollment_secret_hash = NULL, enrollment_expires_at = NULL,
    heartbeat_token_hash = NULL, heartbeat_expires_at = NULL
WHERE account_id = ? AND status = 'active'`, accountID); err != nil {
		return SecurityIncident{}, err
	}
	if err := s.auditTx(ctx, tx, "loader", loaderID, "security.hold", "account", fmt.Sprint(accountID), input.IP, map[string]any{
		"incident_id": incidentID,
		"event_type":  input.EventType,
		"component":   input.Component,
	}); err != nil {
		return SecurityIncident{}, err
	}
	if err := tx.Commit(); err != nil {
		return SecurityIncident{}, err
	}
	return SecurityIncident{
		ID:             incidentID,
		EventID:        input.EventID,
		EventType:      input.EventType,
		Component:      input.Component,
		ExpectedSHA256: input.ExpectedSHA256,
		ObservedSHA256: input.ObservedSHA256,
		ClientVersion:  truncate(input.ClientVersion, 64),
		IP:             truncate(input.IP, 64),
		LoaderID:       loaderID,
		DiscordID:      discordID,
		CreatedAt:      now,
		Disposition:    "security_hold",
	}, nil
}

func (s *Store) PendingSecurityNotifications(ctx context.Context, limit int) ([]SecurityIncident, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, e.event_id, e.event_type, e.component, e.expected_sha256, e.observed_sha256,
       e.client_version, e.ip_address, COALESCE(li.loader_id, ''), COALESCE(a.discord_id, ''), e.created_at, e.disposition
FROM security_events e
JOIN accounts a ON a.id = e.account_id
LEFT JOIN loader_instances li ON li.id = e.loader_instance_id
WHERE e.discord_notified_at IS NULL
ORDER BY e.created_at ASC, e.id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	incidents := make([]SecurityIncident, 0, limit)
	for rows.Next() {
		var incident SecurityIncident
		var createdAt int64
		if err := rows.Scan(
			&incident.ID, &incident.EventID, &incident.EventType, &incident.Component,
			&incident.ExpectedSHA256, &incident.ObservedSHA256, &incident.ClientVersion,
			&incident.IP, &incident.LoaderID, &incident.DiscordID, &createdAt, &incident.Disposition,
		); err != nil {
			return nil, err
		}
		incident.CreatedAt = time.Unix(createdAt, 0).UTC()
		incidents = append(incidents, incident)
	}
	return incidents, rows.Err()
}

func (s *Store) RecordSecurityNotification(ctx context.Context, incidentID int64, notificationErr error) error {
	if incidentID <= 0 {
		return errors.New("invalid security incident ID")
	}
	if notificationErr == nil {
		_, err := s.db.ExecContext(ctx, `
UPDATE security_events
SET discord_notified_at = ?, discord_attempts = discord_attempts + 1, discord_last_error = ''
WHERE id = ? AND discord_notified_at IS NULL`, time.Now().UTC().Unix(), incidentID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE security_events
SET discord_attempts = discord_attempts + 1, discord_last_error = ?
WHERE id = ? AND discord_notified_at IS NULL`, truncate(notificationErr.Error(), 256), incidentID)
	return err
}

const multiHWIDAlertThreshold = 3

// RecordDeviceBindEvent stores a device binding outcome for license abuse
// monitoring. Failures (device limit, revoked device) are the sharing signal.
func (s *Store) RecordDeviceBindEvent(ctx context.Context, licenseID int64, hwidDigest []byte, ip string, success bool) error {
	if licenseID <= 0 || len(hwidDigest) == 0 {
		return errors.New("invalid device bind event")
	}
	successValue := 0
	if success {
		successValue = 1
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO device_bind_events(license_id, hwid_hash, ip_address, success, created_at)
VALUES(?, ?, ?, ?, ?)`, licenseID, hwidDigest, truncate(ip, 64), successValue, time.Now().UTC().Unix())
	return err
}

// RegisterMultiHWIDAlert checks whether a license accumulated too many distinct
// blocked HWIDs inside the window and queues a Discord alert once per window.
// Returns true when a new alert was queued.
func (s *Store) RegisterMultiHWIDAlert(ctx context.Context, licenseID int64, loaderID string, window time.Duration) (bool, error) {
	if licenseID <= 0 || window < time.Minute {
		return false, errors.New("invalid multi HWID alert parameters")
	}
	now := time.Now().UTC()
	windowStart := now.Add(-window).Unix()

	var distinctHWIDs int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM (
    SELECT DISTINCT hwid_hash FROM device_bind_events
    WHERE license_id = ? AND success = 0 AND created_at > ?
)`, licenseID, windowStart).Scan(&distinctHWIDs); err != nil {
		return false, err
	}
	if distinctHWIDs < multiHWIDAlertThreshold {
		return false, nil
	}

	subject := loaderID
	if subject == "" {
		subject = fmt.Sprintf("license-%d", licenseID)
	}
	var existing int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM security_alerts
WHERE kind = 'multi_hwid' AND subject = ? AND created_at > ?`, subject, windowStart).Scan(&existing); err != nil {
		return false, err
	}
	if existing != 0 {
		return false, nil
	}

	var licensePrefix string
	var accountID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
SELECT key_prefix, account_id FROM licenses WHERE id = ?`, licenseID).
		Scan(&licensePrefix, &accountID); err != nil {
		return false, err
	}
	user := "not linked"
	if accountID.Valid {
		var discordID sql.NullString
		var username string
		if err := s.db.QueryRowContext(ctx, `
SELECT username_display, discord_id FROM accounts WHERE id = ?`, accountID.Int64).
			Scan(&username, &discordID); err == nil {
			if discordID.Valid && discordID.String != "" {
				user = "<@" + discordID.String + ">"
			} else {
				user = username
			}
		}
	}

	ips := make([]string, 0, 4)
	rows, err := s.db.QueryContext(ctx, `
SELECT ip_address FROM device_bind_events
WHERE license_id = ? AND success = 0 AND created_at > ? AND ip_address != ''
ORDER BY created_at DESC LIMIT 8`, licenseID, windowStart)
	if err != nil {
		return false, err
	}
	seen := make(map[string]bool)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return false, err
		}
		masked := maskIPText(ip)
		if !seen[masked] {
			seen[masked] = true
			ips = append(ips, "`"+masked+"`")
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	message := fmt.Sprintf(
		"LICENSE SHARING SUSPECTED\nLicense: `%s...`\nUser: %s\nLoader: `%s`\nBlocked distinct HWIDs (%dh): %d\nRecent IPs: %s\nAll attempts were rejected. Review the license and revoke it if sharing is confirmed.",
		licensePrefix, user, subject, int(window.Hours()), distinctHWIDs, strings.Join(ips, ", "))
	result, err := s.db.ExecContext(ctx, `
INSERT INTO security_alerts(kind, subject, message, created_at)
VALUES('multi_hwid', ?, ?, ?)`, subject, truncate(message, 1900), now.Unix())
	if err != nil {
		return false, err
	}
	alertID, err := result.LastInsertId()
	if err != nil {
		return false, err
	}
	s.audit(ctx, "system", fmt.Sprint(alertID), "security.alert", "license", fmt.Sprint(licenseID), "", map[string]any{
		"kind":             "multi_hwid",
		"distinct_hwids":   distinctHWIDs,
		"window_seconds":   int64(window.Seconds()),
	})
	return true, nil
}

func (s *Store) PendingSecurityAlerts(ctx context.Context, limit int) ([]SecurityAlert, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, kind, subject, message, created_at
FROM security_alerts
WHERE sent_at IS NULL
ORDER BY created_at ASC, id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := make([]SecurityAlert, 0, limit)
	for rows.Next() {
		var alert SecurityAlert
		var createdAt int64
		if err := rows.Scan(&alert.ID, &alert.Kind, &alert.Subject, &alert.Message, &createdAt); err != nil {
			return nil, err
		}
		alert.CreatedAt = time.Unix(createdAt, 0).UTC()
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

func (s *Store) RecordSecurityAlertNotification(ctx context.Context, alertID int64, notificationErr error) error {
	if alertID <= 0 {
		return errors.New("invalid security alert ID")
	}
	if notificationErr == nil {
		_, err := s.db.ExecContext(ctx, `
UPDATE security_alerts
SET sent_at = ?, attempts = attempts + 1, last_error = ''
WHERE id = ? AND sent_at IS NULL`, time.Now().UTC().Unix(), alertID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE security_alerts
SET attempts = attempts + 1, last_error = ?
WHERE id = ? AND sent_at IS NULL`, truncate(notificationErr.Error(), 256), alertID)
	return err
}

func maskIPText(value string) string {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "unknown"
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return fmt.Sprintf("%d.%d.%d.x", ipv4[0], ipv4[1], ipv4[2])
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (s *Store) CreateDownloadTicket(ctx context.Context, sessionID int64, artifactID int64, clientPublicKey []byte, ttl time.Duration, watermarkSHA256 string, watermarkSize int64) (string, time.Time, error) {
	if sessionID <= 0 || artifactID <= 0 || len(clientPublicKey) != 65 || ttl <= 0 {
		return "", time.Time{}, errors.New("invalid download ticket parameters")
	}
	if (watermarkSHA256 == "") != (watermarkSize == 0) {
		return "", time.Time{}, errors.New("watermark metadata is inconsistent")
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	result, err := s.db.ExecContext(ctx, `
	INSERT INTO download_tickets(token_hash, session_id, artifact_id, client_public_key, watermark_sha256, watermark_size, created_at, expires_at)
	SELECT ?, s.id, a.id, ?, ?, ?, ?, ?
	FROM sessions s
	JOIN accounts u ON u.id = s.account_id
	JOIN licenses l ON l.id = s.license_id AND l.account_id = s.account_id
	JOIN devices d ON d.id = s.device_id AND d.account_id = s.account_id
	JOIN artifacts a ON a.id = ? AND a.active = 1
	LEFT JOIN loader_instances li ON li.id = s.loader_instance_id
	WHERE s.id = ?
	  AND s.revoked_at IS NULL
	  AND s.expires_at > ?
	  AND u.status = 'active'
	  AND l.status = 'active'
	  AND (l.expires_at IS NULL OR l.expires_at > ?)
	  AND d.revoked_at IS NULL
	  AND (s.loader_instance_id IS NULL OR (
	      li.status = 'active'
	      AND li.account_id = s.account_id
	      AND li.license_id = s.license_id
	      AND d.loader_instance_id = s.loader_instance_id
	  ))`, security.Digest(s.pepper, token), clientPublicKey, watermarkSHA256, watermarkSize, now.Unix(), expiresAt.Unix(),
		artifactID, sessionID, now.Unix(), now.Unix())
	if err != nil {
		return "", time.Time{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return "", time.Time{}, ErrSessionExpired
	}
	return token, expiresAt, nil
}

func (s *Store) ConsumeDownloadTicket(ctx context.Context, token string, sessionID int64, clientPublicKey []byte) (Artifact, TicketWatermark, error) {
	if len(token) < 32 || len(token) > 128 || sessionID <= 0 || len(clientPublicKey) != 65 {
		return Artifact{}, TicketWatermark{}, ErrTicketUnavailable
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Artifact{}, TicketWatermark{}, err
	}
	defer tx.Rollback()

	var artifact Artifact
	var watermark TicketWatermark
	var createdAt int64
	err = tx.QueryRowContext(ctx, `
SELECT a.id, a.version, a.platform, a.storage_path, a.sha256, a.plaintext_size, a.signature, a.created_at, a.active,
       t.watermark_sha256, t.watermark_size
FROM download_tickets t
JOIN sessions s ON s.id = t.session_id
JOIN licenses l ON l.id = s.license_id
	JOIN accounts u ON u.id = s.account_id
	JOIN devices d ON d.id = s.device_id
	JOIN artifacts a ON a.id = t.artifact_id
	LEFT JOIN loader_instances li ON li.id = s.loader_instance_id
WHERE t.token_hash = ?
  AND t.session_id = ?
  AND t.client_public_key = ?
  AND t.used_at IS NULL
  AND t.expires_at > ?
  AND s.revoked_at IS NULL
  AND s.expires_at > ?
  AND l.status = 'active'
  AND (l.expires_at IS NULL OR l.expires_at > ?)
  AND u.status = 'active'
 	  AND d.revoked_at IS NULL
 	  AND (s.loader_instance_id IS NULL OR (
 	      li.status = 'active'
 	      AND li.account_id = s.account_id
 	      AND li.license_id = s.license_id
 	      AND d.loader_instance_id = s.loader_instance_id
 	  ))
 	  AND a.active = 1`, security.Digest(s.pepper, token), sessionID, clientPublicKey, now.Unix(), now.Unix(), now.Unix()).
	Scan(&artifact.ID, &artifact.Version, &artifact.Platform, &artifact.Path, &artifact.SHA256, &artifact.Size, &artifact.Signature, &createdAt, &artifact.Active,
		&watermark.SHA256, &watermark.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, TicketWatermark{}, ErrTicketUnavailable
	}
	if err != nil {
		return Artifact{}, TicketWatermark{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE download_tickets SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`, now.Unix(), security.Digest(s.pepper, token))
	if err != nil {
		return Artifact{}, TicketWatermark{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Artifact{}, TicketWatermark{}, ErrTicketUnavailable
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, TicketWatermark{}, err
	}
	artifact.CreatedAt = time.Unix(createdAt, 0).UTC()
	return artifact, watermark, nil
}

func (s *Store) LatestArtifact(ctx context.Context, platform string) (Artifact, error) {
	var artifact Artifact
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `
SELECT id, version, platform, storage_path, sha256, plaintext_size, signature, created_at, active
FROM artifacts WHERE platform = ? AND active = 1
ORDER BY created_at DESC LIMIT 1`, platform).
		Scan(&artifact.ID, &artifact.Version, &artifact.Platform, &artifact.Path, &artifact.SHA256, &artifact.Size, &artifact.Signature, &createdAt, &artifact.Active)
	if err != nil {
		return Artifact{}, err
	}
	artifact.CreatedAt = time.Unix(createdAt, 0).UTC()
	return artifact, nil
}

func (s *Store) RegisterArtifact(ctx context.Context, artifact Artifact) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE artifacts SET active = 0 WHERE platform = ?`, artifact.Platform); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO artifacts(version, platform, storage_path, sha256, plaintext_size, signature, active, created_at)
VALUES(?, ?, ?, ?, ?, ?, 1, ?)`, artifact.Version, artifact.Platform, artifact.Path, artifact.SHA256, artifact.Size, artifact.Signature, time.Now().UTC().Unix())
	if err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "admin", "cli", "artifact.import", "artifact", artifact.Version, "", map[string]any{"sha256": artifact.SHA256, "size": artifact.Size}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Dashboard(ctx context.Context) (DashboardCounts, error) {
	var counts DashboardCounts
	queries := []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(1) FROM accounts WHERE role = 'user'`, &counts.Users},
		{`SELECT COUNT(1) FROM licenses WHERE status = 'active' AND (expires_at IS NULL OR expires_at > unixepoch())`, &counts.ActiveLicenses},
		{`SELECT COUNT(1) FROM devices WHERE revoked_at IS NULL`, &counts.Devices},
		{`SELECT COUNT(1) FROM sessions WHERE revoked_at IS NULL AND expires_at > unixepoch()`, &counts.ActiveSessions},
	}
	for _, item := range queries {
		if err := s.db.QueryRowContext(ctx, item.query).Scan(item.dest); err != nil {
			return DashboardCounts{}, err
		}
	}
	return counts, nil
}

func (s *Store) ListLicenses(ctx context.Context, limit int) ([]LicenseView, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT l.id, l.key_prefix, COALESCE(a.username_display, ''), l.status, l.expires_at,
       l.max_devices, COUNT(d.id), l.note, l.created_at
FROM licenses l
LEFT JOIN accounts a ON a.id = l.account_id
LEFT JOIN devices d ON d.account_id = a.id AND d.revoked_at IS NULL
GROUP BY l.id
ORDER BY l.created_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	licenses := make([]LicenseView, 0, limit)
	for rows.Next() {
		var item LicenseView
		var expiry sql.NullInt64
		var createdAt int64
		if err := rows.Scan(&item.ID, &item.Prefix, &item.Username, &item.Status, &expiry, &item.MaxDevices, &item.DeviceCount, &item.Note, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		if expiry.Valid {
			value := time.Unix(expiry.Int64, 0).UTC()
			item.ExpiresAt = &value
		}
		licenses = append(licenses, item)
	}
	return licenses, rows.Err()
}

func (s *Store) RevokeLicense(ctx context.Context, licenseID int64, actor, ip string) error {
	now := time.Now().UTC().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE licenses SET status = 'revoked' WHERE id = ? AND status = 'active'`, licenseID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE license_id = ? AND revoked_at IS NULL`, now, licenseID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE loader_instances SET status = 'revoked', download_token_hash = NULL, download_expires_at = NULL, enrollment_secret_hash = NULL, enrollment_expires_at = NULL, heartbeat_token_hash = NULL, heartbeat_expires_at = NULL WHERE license_id = ? AND status = 'active'`, licenseID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "license.revoke", "license", fmt.Sprint(licenseID), ip, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ResetDevices(ctx context.Context, username, actor, ip string) (int64, error) {
	_, canonical, err := security.NormalizeUsername(username)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var accountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE username_canonical = ?`, canonical).Scan(&accountID); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE account_id = ?`, accountID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "device.reset", "account", fmt.Sprint(accountID), ip, map[string]any{"devices": count}); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (s *Store) ResetDevicesByDiscordID(ctx context.Context, discordID, actor, ip string) (int64, error) {
	if !validDiscordID(discordID) {
		return 0, errors.New("invalid Discord user ID")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var accountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE discord_id = ?`, discordID).Scan(&accountID); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE account_id = ?`, accountID)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "device.reset", "discord_user", discordID, ip, map[string]any{"devices": count}); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (s *Store) SetUserStatus(ctx context.Context, username, status, actor, ip string) error {
	if status != "active" && status != "disabled" && status != "banned" {
		return errors.New("unsupported status")
	}
	_, canonical, err := security.NormalizeUsername(username)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var accountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE username_canonical = ?`, canonical).Scan(&accountID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET status = ? WHERE id = ? AND role != 'admin'`, status, accountID); err != nil {
		return err
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`, now, accountID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE loader_instances SET download_token_hash = NULL, download_expires_at = NULL, enrollment_secret_hash = NULL, enrollment_expires_at = NULL, heartbeat_token_hash = NULL, heartbeat_expires_at = NULL WHERE account_id = ? AND status = 'active'`, accountID); err != nil {
			return err
		}
	}
	if err := updateSecurityDispositionTx(ctx, tx, accountID, status); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "account.status", "account", fmt.Sprint(accountID), ip, map[string]any{"status": status}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetUserStatusByDiscordID(ctx context.Context, discordID, status, actor, ip string) error {
	if !validDiscordID(discordID) {
		return errors.New("invalid Discord user ID")
	}
	if status != "active" && status != "disabled" && status != "banned" {
		return errors.New("unsupported status")
	}
	now := time.Now().UTC().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var accountID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE discord_id = ? AND role != 'admin'`, discordID).Scan(&accountID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET status = ? WHERE id = ?`, status, accountID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return sql.ErrNoRows
	}
	if status != "active" {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`, now, accountID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE loader_instances SET download_token_hash = NULL, download_expires_at = NULL, enrollment_secret_hash = NULL, enrollment_expires_at = NULL, heartbeat_token_hash = NULL, heartbeat_expires_at = NULL WHERE account_id = ? AND status = 'active'`, accountID); err != nil {
			return err
		}
	}
	if err := updateSecurityDispositionTx(ctx, tx, accountID, status); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "admin", actor, "account.status", "discord_user", discordID, ip, map[string]any{"status": status}); err != nil {
		return err
	}
	return tx.Commit()
}

func updateSecurityDispositionTx(ctx context.Context, tx *sql.Tx, accountID int64, status string) error {
	disposition := ""
	switch status {
	case "active":
		disposition = "dismissed"
	case "banned":
		disposition = "confirmed"
	default:
		return nil
	}
	_, err := tx.ExecContext(ctx, `
UPDATE security_events SET disposition = ?
WHERE account_id = ? AND disposition = 'security_hold'`, disposition, accountID)
	return err
}

func (s *Store) AuthenticateAdmin(ctx context.Context, username, password, ip string, ttl time.Duration) (token, csrf string, expiresAt time.Time, err error) {
	_, canonical, normalizeErr := security.NormalizeUsername(username)
	if normalizeErr != nil {
		security.VerifyPassword(s.dummy, password)
		return "", "", time.Time{}, ErrInvalidCredentials
	}
	var accountID int64
	var passwordHash, role, status string
	err = s.db.QueryRowContext(ctx, `SELECT id, password_hash, role, status FROM accounts WHERE username_canonical = ?`, canonical).
		Scan(&accountID, &passwordHash, &role, &status)
	if errors.Is(err, sql.ErrNoRows) {
		security.VerifyPassword(s.dummy, password)
		return "", "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	if !security.VerifyPassword(passwordHash, password) || role != "admin" || status != "active" {
		return "", "", time.Time{}, ErrInvalidCredentials
	}
	token, err = security.RandomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrf, err = security.RandomToken(24)
	if err != nil {
		return "", "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(ttl)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO admin_sessions(token_hash, csrf_hash, account_id, created_at, expires_at, ip_address)
VALUES(?, ?, ?, ?, ?, ?)`, security.Digest(s.pepper, token), security.Digest(s.pepper, csrf), accountID, now.Unix(), expiresAt.Unix(), ip)
	if err == nil {
		s.audit(ctx, "admin", fmt.Sprint(accountID), "admin.login", "session", "", ip, nil)
	}
	return token, csrf, expiresAt, err
}

func (s *Store) ValidateAdminSession(ctx context.Context, token, csrf string, requireCSRF bool) (int64, string, error) {
	if len(token) < 32 {
		return 0, "", ErrSessionExpired
	}
	var accountID int64
	var username string
	var csrfHash []byte
	err := s.db.QueryRowContext(ctx, `
SELECT a.id, a.username_display, s.csrf_hash
FROM admin_sessions s
JOIN accounts a ON a.id = s.account_id
WHERE s.token_hash = ? AND s.expires_at > ? AND a.role = 'admin' AND a.status = 'active'`,
		security.Digest(s.pepper, token), time.Now().UTC().Unix()).Scan(&accountID, &username, &csrfHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrSessionExpired
	}
	if err != nil {
		return 0, "", err
	}
	if requireCSRF && !hmacEqual(csrfHash, security.Digest(s.pepper, csrf)) {
		return 0, "", ErrInvalidCredentials
	}
	return accountID, username, nil
}

func (s *Store) LogoutAdmin(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ?`, security.Digest(s.pepper, token))
	return err
}

func (s *Store) Prune(ctx context.Context) error {
	now := time.Now().UTC().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM auth_challenges WHERE expires_at < ? OR used_at IS NOT NULL`, []any{now}},
		{`DELETE FROM download_tickets WHERE expires_at < ? OR used_at IS NOT NULL`, []any{now}},
		{`DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`, []any{now, now - 86400}},
		{`DELETE FROM admin_sessions WHERE expires_at < ?`, []any{now}},
		{`UPDATE loader_instances SET download_token_hash = NULL, download_expires_at = NULL WHERE download_expires_at < ?`, []any{now}},
		{`UPDATE loader_instances SET enrollment_secret_hash = NULL, enrollment_expires_at = NULL WHERE enrollment_expires_at < ?`, []any{now}},
		{`UPDATE loader_instances SET heartbeat_token_hash = NULL, heartbeat_expires_at = NULL WHERE heartbeat_expires_at < ?`, []any{now}},
		{`DELETE FROM device_bind_events WHERE created_at < ?`, []any{now - 30*86400}},
		{`DELETE FROM security_alerts WHERE sent_at IS NOT NULL AND sent_at < ?`, []any{now - 30*86400}},
		{`DELETE FROM audit_log WHERE created_at < ?`, []any{now - 180*86400}},
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) audit(ctx context.Context, actorType, actorID, action, targetType, targetID, ip string, metadata map[string]any) {
	_, _ = s.db.ExecContext(ctx, auditSQL, actorType, actorID, action, targetType, targetID, ip, metadataJSON(metadata), time.Now().UTC().Unix())
}

func (s *Store) auditTx(ctx context.Context, tx *sql.Tx, actorType, actorID, action, targetType, targetID, ip string, metadata map[string]any) error {
	_, err := tx.ExecContext(ctx, auditSQL, actorType, actorID, action, targetType, targetID, ip, metadataJSON(metadata), time.Now().UTC().Unix())
	return err
}

const auditSQL = `
INSERT INTO audit_log(actor_type, actor_id, action, target_type, target_id, ip_address, metadata_json, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`

func metadataJSON(metadata map[string]any) string {
	if metadata == nil {
		return "{}"
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func hmacEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func validDiscordID(value string) bool {
	if len(value) < 5 || len(value) > 24 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validLoaderID(value string) bool {
	if len(value) < 20 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validPairingCode(value string) bool {
	if len(value) < 20 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validSecurityEventInput(input SecurityEventInput) bool {
	if !validSecurityEventID(input.EventID) || input.EventType != "post_run_hash_mismatch" ||
		(input.Component != "module" && input.Component != "injector") ||
		len(input.ExpectedSHA256) != 64 || len(input.ObservedSHA256) != 64 ||
		input.ExpectedSHA256 == input.ObservedSHA256 || len(input.ClientVersion) == 0 || len(input.ClientVersion) > 64 ||
		len(input.IP) > 64 {
		return false
	}
	for _, value := range []string{input.ExpectedSHA256, input.ObservedSHA256} {
		for _, char := range value {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				return false
			}
		}
	}
	return !strings.ContainsAny(input.ClientVersion, "\r\n\x00")
}

func validSecurityEventID(value string) bool {
	if len(value) < 22 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '+' || char == '/') {
			return false
		}
	}
	return true
}
