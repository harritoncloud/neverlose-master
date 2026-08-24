package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nl-auth/internal/security"
)

func TestLicenseLifecycle(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("test-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	key, err := database.IssueLicense(ctx, 24*time.Hour, 1, "integration test", "test")
	if err != nil {
		t.Fatal(err)
	}
	challenge := "test-challenge-token-with-enough-entropy"
	if err := database.RegisterChallenge(ctx, challenge, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeChallenge(ctx, challenge); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("challenge reuse returned %v", err)
	}
	firstHWID := sha256.Sum256([]byte("device-one"))
	nonce := base64.RawStdEncoding.EncodeToString(make([]byte, 24))
	client := ClientContext{IP: "127.0.0.1", ClientNonce: nonce, Version: "test"}
	activated, err := database.Activate(ctx, "test_user", "correct-horse-battery", key, hex.EncodeToString(firstHWID[:]), client)
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.AuthenticateSession(ctx, activated.Token)
	if err != nil {
		t.Fatal(err)
	}

	artifact := Artifact{Version: "1.0.0", Platform: "windows-x86", Path: filepath.Join(t.TempDir(), "artifact.nla"), SHA256: hex.EncodeToString(firstHWID[:]), Size: 123, Signature: []byte("signature")}
	if err := database.RegisterArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	latest, err := database.LatestArtifact(ctx, "windows-x86")
	if err != nil {
		t.Fatal(err)
	}
	clientPublicKey := append([]byte{0x04}, make([]byte, 64)...)
	ticket, _, err := database.CreateDownloadTicket(ctx, session.ID, latest.ID, clientPublicKey, time.Minute, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublicKey := append([]byte(nil), clientPublicKey...)
	wrongPublicKey[1] = 1
	if _, _, err := database.ConsumeDownloadTicket(ctx, ticket, session.ID, wrongPublicKey); !errors.Is(err, ErrTicketUnavailable) {
		t.Fatalf("ticket accepted another client key: %v", err)
	}
	if _, _, err := database.ConsumeDownloadTicket(ctx, ticket, session.ID+1, clientPublicKey); !errors.Is(err, ErrTicketUnavailable) {
		t.Fatalf("ticket accepted another session: %v", err)
	}
	if _, watermark, err := database.ConsumeDownloadTicket(ctx, ticket, session.ID, clientPublicKey); err != nil || watermark.SHA256 != "" || watermark.Size != 0 {
		t.Fatalf("unexpected consume result: watermark=%+v err=%v", watermark, err)
	}
	if _, _, err := database.ConsumeDownloadTicket(ctx, ticket, session.ID, clientPublicKey); !errors.Is(err, ErrTicketUnavailable) {
		t.Fatalf("ticket reuse returned %v", err)
	}

	secondHWID := sha256.Sum256([]byte("device-two"))
	if _, err := database.Login(ctx, "test_user", "correct-horse-battery", key, hex.EncodeToString(secondHWID[:]), client); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("device limit returned %v", err)
	}
	if count, err := database.ResetDevices(ctx, "test_user", "test", "127.0.0.1"); err != nil || count != 1 {
		t.Fatalf("device reset count=%d error=%v", count, err)
	}
	secondSession, err := database.Login(ctx, "test_user", "correct-horse-battery", key, hex.EncodeToString(secondHWID[:]), client)
	if err != nil {
		t.Fatal(err)
	}
	licenses, err := database.ListLicenses(ctx, 10)
	if err != nil || len(licenses) != 1 {
		t.Fatalf("license list count=%d error=%v", len(licenses), err)
	}
	if err := database.RevokeLicense(ctx, licenses[0].ID, "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateSession(ctx, secondSession.Token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("revoked license left a valid session: %v", err)
	}
}

func TestDiscordLoaderLifecycle(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("discord-test-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const discordID = "123456789012345678"
	key, err := database.IssueLicenseForDiscord(ctx, 24*time.Hour, 1, "discord test", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	hwid := sha256.Sum256([]byte("legacy-device"))
	nonce := base64.RawStdEncoding.EncodeToString(make([]byte, 24))
	if _, err := database.Activate(ctx, "legacy_user", "correct-horse-battery", key, hex.EncodeToString(hwid[:]), ClientContext{ClientNonce: nonce}); !errors.Is(err, ErrLicenseUnavailable) {
		t.Fatalf("Discord-assigned key bypassed redeem flow: %v", err)
	}

	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		payload := []byte(loaderID + ":" + issuedAt.UTC().Format(time.RFC3339))
		signature := make([]byte, 64)
		for index := range signature {
			signature[index] = byte(licenseID + int64(index))
		}
		return payload, signature, nil
	}
	if _, err := database.RedeemLicense(ctx, key, "999999999999999999", 5*time.Minute, signer, "127.0.0.1"); !errors.Is(err, ErrLicenseUnavailable) {
		t.Fatalf("assigned key accepted another Discord user: %v", err)
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if issue.LoaderID == "" || issue.DownloadToken == "" {
		t.Fatal("redeem returned an incomplete loader issue")
	}
	info, err := database.PeekLoaderDownload(ctx, issue.DownloadToken)
	if err != nil || info.LoaderID != issue.LoaderID {
		t.Fatalf("loader peek id=%q error=%v", info.LoaderID, err)
	}
	personalization, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if personalization.LoaderID != issue.LoaderID || len(personalization.CertificatePayload) == 0 ||
		len(personalization.CertificateSignature) != 64 || !validPairingCode(personalization.EnrollmentSecret) {
		t.Fatal("loader personalization is incomplete")
	}
	if _, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("loader link was reusable: %v", err)
	}

	renewed, err := database.RenewLoaderDownloadByDiscordID(ctx, discordID, 5*time.Minute, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if renewed.LoaderID != issue.LoaderID || renewed.DownloadToken == issue.DownloadToken {
		t.Fatal("loader renewal did not preserve identity with a fresh token")
	}
	repeated, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if repeated.LoaderID != issue.LoaderID || repeated.DownloadToken == renewed.DownloadToken {
		t.Fatal("repeat redeem did not issue a fresh link for the existing loader")
	}

	replacementKey, err := database.ReissueLicenseForDiscord(ctx, discordID, 48*time.Hour, 1, "replacement", "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.PeekLoaderDownload(ctx, repeated.DownloadToken); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("reissued license left the old loader link active: %v", err)
	}
	replacement, err := database.RedeemLicense(ctx, replacementKey, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.LoaderID == issue.LoaderID {
		t.Fatal("replacement license reused a revoked loader identity")
	}
	replacementPackage, err := database.ConsumeLoaderDownload(ctx, replacement.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := make([]byte, 65)
	publicKey[0] = 4
	loaderSession, err := database.LoginLoader(
		ctx,
		replacement.LoaderID,
		replacementPackage.CertificatePayload,
		replacementPackage.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		publicKey,
		"",
		ClientContext{IP: "127.0.0.1", ClientNonce: nonce, Version: "test-loader"},
	)
	if !errors.Is(err, ErrPairingRequired) {
		t.Fatalf("first loader login without pairing code returned %v", err)
	}
	loaderSession, err = database.LoginLoader(
		ctx,
		replacement.LoaderID,
		replacementPackage.CertificatePayload,
		replacementPackage.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		publicKey,
		replacementPackage.EnrollmentSecret,
		ClientContext{IP: "127.0.0.1", ClientNonce: nonce, Version: "test-loader"},
	)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedLoader, err := database.AuthenticateSession(ctx, loaderSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authenticatedLoader.DevicePublicKey, publicKey) {
		t.Fatal("loader session lost its bound device public key")
	}
	rotatedLoaderSession, err := database.LoginLoader(
		ctx,
		replacement.LoaderID,
		replacementPackage.CertificatePayload,
		replacementPackage.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		publicKey,
		"",
		ClientContext{IP: "127.0.0.1", ClientNonce: nonce, Version: "test-loader"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateSession(ctx, loaderSession.Token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("rotated loader session remained active: %v", err)
	}
	if _, err := database.AuthenticateSession(ctx, rotatedLoaderSession.Token); err != nil {
		t.Fatalf("replacement loader session is invalid: %v", err)
	}
	wrongPublicKey := append([]byte(nil), publicKey...)
	wrongPublicKey[1] = 1
	if _, err := database.LoginLoader(ctx, replacement.LoaderID, replacementPackage.CertificatePayload, replacementPackage.CertificateSignature, hex.EncodeToString(hwid[:]), wrongPublicKey, "", ClientContext{ClientNonce: nonce, Version: "test-loader"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("device public key replacement returned %v", err)
	}
	if _, err := database.AuthenticateSession(ctx, rotatedLoaderSession.Token); err != nil {
		t.Fatalf("failed key replacement revoked the valid session: %v", err)
	}
	pairing, err := database.RenewLoaderDownloadByDiscordID(ctx, discordID, 5*time.Minute, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pairingPackage, err := database.ConsumeLoaderDownload(ctx, pairing.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherHWID := sha256.Sum256([]byte("second-loader-device"))
	if _, err := database.LoginLoader(ctx, replacement.LoaderID, pairingPackage.CertificatePayload, pairingPackage.CertificateSignature, hex.EncodeToString(otherHWID[:]), publicKey, pairingPackage.EnrollmentSecret, ClientContext{ClientNonce: nonce, Version: "test-loader"}); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("loader device limit returned %v", err)
	}
	if count, err := database.ResetDevicesByDiscordID(ctx, discordID, "test", "127.0.0.1"); err != nil || count != 1 {
		t.Fatalf("Discord HWID reset count=%d error=%v", count, err)
	}
}

func TestOneTimeCredentialsRejectConcurrentReplay(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("concurrent-replay-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	challenge := "concurrent-challenge-token-with-enough-entropy"
	if err := database.RegisterChallenge(ctx, challenge, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertSingleConcurrentSuccess(t, 16, func() error {
		return database.ConsumeChallenge(ctx, challenge)
	}, ErrInvalidCredentials)

	const discordID = "123456789012345678"
	key, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "concurrent loader", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte(loaderID), make([]byte, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	assertSingleConcurrentSuccess(t, 8, func() error {
		_, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
		return err
	}, ErrLoaderUnavailable)
}

func TestLoaderRevocationClosesTicketRace(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("loader-revocation-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const discordID = "123456789012345678"
	key, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "revocation race", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte(loaderID), make([]byte, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hwid := sha256.Sum256([]byte("revocation-device"))
	devicePublicKey := append([]byte{0x04}, make([]byte, 64)...)
	login, err := database.LoginLoader(ctx, issue.LoaderID, pkg.CertificatePayload, pkg.CertificateSignature,
		hex.EncodeToString(hwid[:]), devicePublicKey, pkg.EnrollmentSecret,
		ClientContext{ClientNonce: base64.RawStdEncoding.EncodeToString(make([]byte, 24)), Version: "test-loader"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.AuthenticateSession(ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256([]byte("artifact"))
	artifact := Artifact{Version: "revocation-test", Platform: "windows-x86", Path: filepath.Join(t.TempDir(), "artifact.nla"), SHA256: hex.EncodeToString(artifactDigest[:]), Size: 123, Signature: make([]byte, 64)}
	if err := database.RegisterArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	artifact, err = database.LatestArtifact(ctx, "windows-x86")
	if err != nil {
		t.Fatal(err)
	}
	exchangePublicKey := append([]byte{0x04}, make([]byte, 64)...)
	ticket, _, err := database.CreateDownloadTicket(ctx, session.ID, artifact.ID, exchangePublicKey, time.Minute, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE loader_instances SET status = 'revoked' WHERE loader_id = ?`, issue.LoaderID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.CreateDownloadTicket(ctx, session.ID, artifact.ID, exchangePublicKey, time.Minute, "", 0); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("revoked loader created a fresh ticket: %v", err)
	}
	if _, _, err := database.ConsumeDownloadTicket(ctx, ticket, session.ID, exchangePublicKey); !errors.Is(err, ErrTicketUnavailable) {
		t.Fatalf("revoked loader consumed an existing ticket: %v", err)
	}
}

func TestSignedSecurityEventAppliesRecoverableHold(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("security-event-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const discordID = "123456789012345678"
	key, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "security event", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte(loaderID), make([]byte, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hwid := sha256.Sum256([]byte("security-event-device"))
	devicePublicKey := append([]byte{0x04}, make([]byte, 64)...)
	login, err := database.LoginLoader(
		ctx,
		issue.LoaderID,
		pkg.CertificatePayload,
		pkg.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		devicePublicKey,
		pkg.EnrollmentSecret,
		ClientContext{IP: "127.0.0.1", ClientNonce: base64.RawStdEncoding.EncodeToString(make([]byte, 24)), Version: "1.5.0"},
	)
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.AuthenticateSession(ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}

	invalid := SecurityEventInput{
		EventID:        base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 24)),
		EventType:      "post_run_hash_mismatch",
		Component:      "module",
		ExpectedSHA256: strings.Repeat("a", 64),
		ObservedSHA256: strings.Repeat("a", 64),
		ClientVersion:  "1.5.0",
		IP:             "127.0.0.1",
	}
	if _, err := database.ApplySecurityEvent(ctx, session.ID, invalid); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid event returned %v", err)
	}
	if _, err := database.AuthenticateSession(ctx, login.Token); err != nil {
		t.Fatalf("invalid event changed account state: %v", err)
	}

	valid := invalid
	valid.ObservedSHA256 = strings.Repeat("b", 64)
	incident, err := database.ApplySecurityEvent(ctx, session.ID, valid)
	if err != nil {
		t.Fatal(err)
	}
	if incident.ID <= 0 || incident.Disposition != "security_hold" || incident.DiscordID != discordID {
		t.Fatalf("unexpected incident: %+v", incident)
	}
	if _, err := database.AuthenticateSession(ctx, login.Token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("security hold left the session active: %v", err)
	}
	if _, err := database.RenewLoaderDownloadByDiscordID(ctx, discordID, 5*time.Minute, "127.0.0.1"); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("security hold left loader renewal active: %v", err)
	}
	pending, err := database.PendingSecurityNotifications(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].ID != incident.ID {
		t.Fatalf("pending notifications=%d error=%v", len(pending), err)
	}
	if err := database.RecordSecurityNotification(ctx, incident.ID, errors.New("temporary Discord failure")); err != nil {
		t.Fatal(err)
	}
	pending, err = database.PendingSecurityNotifications(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("failed notification was not retained: count=%d error=%v", len(pending), err)
	}
	if err := database.RecordSecurityNotification(ctx, incident.ID, nil); err != nil {
		t.Fatal(err)
	}
	pending, err = database.PendingSecurityNotifications(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("delivered notification remained pending: count=%d error=%v", len(pending), err)
	}
	if err := database.SetUserStatusByDiscordID(ctx, discordID, "active", "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var disposition string
	if err := database.db.QueryRowContext(ctx, `SELECT disposition FROM security_events WHERE id = ?`, incident.ID).Scan(&disposition); err != nil {
		t.Fatal(err)
	}
	if disposition != "dismissed" {
		t.Fatalf("released security incident disposition=%q", disposition)
	}
	if _, err := database.RenewLoaderDownloadByDiscordID(ctx, discordID, 5*time.Minute, "127.0.0.1"); err != nil {
		t.Fatalf("released security hold did not restore loader access: %v", err)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE security_events SET disposition = 'security_hold' WHERE id = ?`, incident.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.SetUserStatusByDiscordID(ctx, discordID, "banned", "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, `SELECT disposition FROM security_events WHERE id = ?`, incident.ID).Scan(&disposition); err != nil {
		t.Fatal(err)
	}
	if disposition != "confirmed" {
		t.Fatalf("confirmed security incident disposition=%q", disposition)
	}
	if _, err := database.RenewLoaderDownloadByDiscordID(ctx, discordID, 5*time.Minute, "127.0.0.1"); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("confirmed security incident restored loader access: %v", err)
	}
}

func assertSingleConcurrentSuccess(t *testing.T, workers int, operation func() error, expectedFailure error) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- operation()
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes := 0
	failures := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, expectedFailure):
			failures++
		default:
			t.Fatalf("concurrent operation returned an unexpected error: %v", err)
		}
	}
	if successes != 1 || failures != workers-1 {
		t.Fatalf("concurrent replay successes=%d failures=%d", successes, failures)
	}
}

func TestMultiHWIDAlertFlow(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("multi-hwid-test-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	key, err := database.IssueLicense(ctx, 24*time.Hour, 1, "multi hwid test", "test")
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := security.NormalizeLicense(key)
	if err != nil {
		t.Fatal(err)
	}
	var licenseID int64
	if err := database.db.QueryRowContext(ctx, `SELECT id FROM licenses WHERE key_hash = ?`,
		security.Digest(database.pepper, normalized)).Scan(&licenseID); err != nil {
		t.Fatal(err)
	}

	const loaderID = "loader-multi-hwid-test-01"
	for i := 0; i < multiHWIDAlertThreshold; i++ {
		hwid := sha256.Sum256([]byte("shared-hwid-" + string(rune('a'+i))))
		if err := database.RecordDeviceBindEvent(ctx, licenseID, hwid[:], "10.0.0."+string(rune('1'+i)), false); err != nil {
			t.Fatal(err)
		}
	}

	queued, err := database.RegisterMultiHWIDAlert(ctx, licenseID, loaderID, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !queued {
		t.Fatal("expected a multi HWID alert to be queued")
	}
	queuedAgain, err := database.RegisterMultiHWIDAlert(ctx, licenseID, loaderID, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if queuedAgain {
		t.Fatal("duplicate multi HWID alert was queued inside the window")
	}

	alerts, err := database.PendingSecurityAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 pending alert, got %d", len(alerts))
	}
	if alerts[0].Kind != "multi_hwid" || alerts[0].Subject != loaderID {
		t.Fatalf("unexpected alert: kind=%s subject=%s", alerts[0].Kind, alerts[0].Subject)
	}
	if !strings.Contains(alerts[0].Message, "LICENSE SHARING SUSPECTED") {
		t.Fatalf("alert message is missing the header: %s", alerts[0].Message)
	}

	if err := database.RecordSecurityAlertNotification(ctx, alerts[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	remaining, err := database.PendingSecurityAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no pending alerts after notification, got %d", len(remaining))
	}
}

func TestLoaderHeartbeatFlow(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("heartbeat-test-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const discordID = "123456789012345678"
	key, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "heartbeat test", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte("heartbeat-cert-" + loaderID), bytes.Repeat([]byte{0x4b}, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.HeartbeatToken == "" || pkg.HeartbeatToken == pkg.EnrollmentSecret {
		t.Fatalf("heartbeat token missing or duplicates enrollment secret: %+v", pkg)
	}

	if err := database.ValidateHeartbeat(ctx, issue.LoaderID, pkg.HeartbeatToken, 24*time.Hour); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	if err := database.ValidateHeartbeat(ctx, issue.LoaderID, pkg.HeartbeatToken+"x", 24*time.Hour); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("wrong heartbeat token returned %v", err)
	}
	if err := database.ValidateHeartbeat(ctx, issue.LoaderID+"zz", pkg.HeartbeatToken, 24*time.Hour); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("wrong loader id returned %v", err)
	}

	var licenseID int64
	if err := database.db.QueryRowContext(ctx, `SELECT license_id FROM loader_instances WHERE loader_id = ?`, issue.LoaderID).Scan(&licenseID); err != nil {
		t.Fatal(err)
	}
	if err := database.RevokeLicense(ctx, licenseID, "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := database.ValidateHeartbeat(ctx, issue.LoaderID, pkg.HeartbeatToken, 24*time.Hour); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("heartbeat survived license revocation: %v", err)
	}
}

func TestReportViolationBansAccount(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("violation-test-pepper"))
	database, err := Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	const discordID = "987654321098765432"
	key, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "violation test", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte("violation-cert-" + loaderID), bytes.Repeat([]byte{0x3c}, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, key, discordID, 5*time.Minute, signer, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := database.ReportViolation(ctx, issue.LoaderID, pkg.HeartbeatToken+"x", "debugger_attached", "127.0.0.1"); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("wrong heartbeat token accepted: %v", err)
	}
	if err := database.ValidateHeartbeat(ctx, issue.LoaderID, pkg.HeartbeatToken, 24*time.Hour); err != nil {
		t.Fatalf("heartbeat must be valid before violation: %v", err)
	}
	if err := database.ReportViolation(ctx, issue.LoaderID, pkg.HeartbeatToken, "debugger_attached", "127.0.0.1"); err != nil {
		t.Fatalf("valid violation report rejected: %v", err)
	}
	if err := database.ValidateHeartbeat(ctx, issue.LoaderID, pkg.HeartbeatToken, 24*time.Hour); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("heartbeat survived violation: %v", err)
	}
	if err := database.ReportViolation(ctx, issue.LoaderID, pkg.HeartbeatToken, "module_unloaded", "127.0.0.1"); !errors.Is(err, ErrLoaderUnavailable) {
		t.Fatalf("second violation report accepted after ban: %v", err)
	}

	alerts, err := database.PendingSecurityAlerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != "tamper" {
		t.Fatalf("expected one tamper alert, got %+v", alerts)
	}
	if !strings.Contains(alerts[0].Message, "RUNTIME TAMPER DETECTED") {
		t.Fatalf("alert message missing header: %s", alerts[0].Message)
	}
}
