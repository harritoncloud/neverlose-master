package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/store"
)

func TestSecurityEventRequiresBoundDeviceProofBeforeHold(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("security-handler-pepper"))
	database, err := store.Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	serverSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey := sha256.Sum256([]byte("security-handler-artifact-key"))
	manager, err := artifacts.New(t.TempDir(), artifactKey[:], serverSigningKey, 2<<20)
	if err != nil {
		t.Fatal(err)
	}

	const discordID = "123456789012345678"
	licenseKey, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "security handler", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	certificateSigner := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		return []byte(loaderID), bytes.Repeat([]byte{0x52}, 64), nil
	}
	issue, err := database.RedeemLicense(ctx, licenseKey, discordID, 5*time.Minute, certificateSigner, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := database.ConsumeLoaderDownload(ctx, issue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	devicePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublicKey := elliptic.Marshal(elliptic.P256(), devicePrivateKey.X, devicePrivateKey.Y)
	hwid := sha256.Sum256([]byte("security-handler-device"))
	login, err := database.LoginLoader(
		ctx,
		issue.LoaderID,
		pkg.CertificatePayload,
		pkg.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		devicePublicKey,
		pkg.EnrollmentSecret,
		store.ClientContext{IP: "127.0.0.1", ClientNonce: base64.RawStdEncoding.EncodeToString(make([]byte, 24)), Version: "1.6.0"},
	)
	if err != nil {
		t.Fatal(err)
	}

	const audience = "https://auth.example.test"
	server := New(
		config.Config{PublicURL: audience},
		database,
		manager,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	postEvent := func(marker byte, validSignature bool) *httptest.ResponseRecorder {
		challenge := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 32))
		if err := database.RegisterChallenge(ctx, challenge, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		eventID := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{marker + 1}, 24))
		clientNonce := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{marker + 2}, 24))
		expected := strings.Repeat("a", 64)
		observed := strings.Repeat("b", 64)
		message := securityEventMessage(
			audience,
			challenge,
			eventID,
			"post_run_hash_mismatch",
			"module",
			expected,
			observed,
			clientNonce,
			"1.6.0",
		)
		digest := sha256.Sum256(message)
		r, s, err := ecdsa.Sign(rand.Reader, devicePrivateKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		if !validSignature {
			signature[0] ^= 1
		}
		body, err := json.Marshal(map[string]string{
			"event_id":         eventID,
			"event_type":       "post_run_hash_mismatch",
			"component":        "module",
			"expected_sha256":  expected,
			"observed_sha256":  observed,
			"client_version":   "1.6.0",
			"client_nonce":     clientNonce,
			"server_challenge": challenge,
			"device_signature": base64.RawStdEncoding.EncodeToString(signature),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/security/events", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+login.Token)
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		return response
	}

	if response := postEvent(0x21, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid proof status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := database.AuthenticateSession(ctx, login.Token); err != nil {
		t.Fatalf("invalid proof applied a hold: %v", err)
	}
	if response := postEvent(0x31, true); response.Code != http.StatusAccepted {
		t.Fatalf("valid event status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := database.AuthenticateSession(ctx, login.Token); !errors.Is(err, store.ErrSessionExpired) {
		t.Fatalf("valid security event left the session active: %v", err)
	}
}

func TestSecurityNotificationRedactsSensitiveValues(t *testing.T) {
	text := securityNotificationText(store.SecurityIncident{
		ID:             7,
		EventType:      "post_run_hash_mismatch",
		Component:      "module",
		ExpectedSHA256: strings.Repeat("a", 64),
		ObservedSHA256: strings.Repeat("b", 64),
		ClientVersion:  "1.6.0",
		IP:             "203.0.113.42",
		LoaderID:       "abcdefghijklmnopqrstuv",
		DiscordID:      "123456789012345678",
		CreatedAt:      time.Unix(1_800_000_000, 0).UTC(),
	})
	if strings.Contains(text, strings.Repeat("a", 64)) || strings.Contains(text, "203.0.113.42") ||
		strings.Contains(text, "abcdefghijklmnopqrstuv") {
		t.Fatal("security notification exposed full sensitive values")
	}
	if !strings.Contains(text, "203.0.113.x") || !strings.Contains(text, "security_hold") && !strings.Contains(text, "SECURITY HOLD") {
		t.Fatal("security notification omitted required incident metadata")
	}
}
