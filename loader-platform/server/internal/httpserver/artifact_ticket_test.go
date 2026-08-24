package httpserver

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/store"
)

func TestArtifactTicketRequiresDeviceProofAndBindsExchangeKey(t *testing.T) {
	ctx := context.Background()
	pepper := sha256.Sum256([]byte("artifact-ticket-test-pepper"))
	database, err := store.Open(filepath.Join(t.TempDir(), "auth.db"), pepper[:], 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey := sha256.Sum256([]byte("artifact-ticket-storage-key"))
	artifactDirectory := filepath.Join(t.TempDir(), "artifacts")
	if err := os.MkdirAll(artifactDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := artifacts.New(artifactDirectory, artifactKey[:], signingKey, 2<<20)
	if err != nil {
		t.Fatal(err)
	}

	const discordID = "123456789012345678"
	licenseKey, err := database.IssueLicenseForDiscord(ctx, time.Hour, 1, "ticket test", "test", discordID)
	if err != nil {
		t.Fatal(err)
	}
	certificateSigner := func(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
		payload := []byte(loaderID + issuedAt.UTC().Format(time.RFC3339))
		return payload, bytes.Repeat([]byte{0x5a}, 64), nil
	}
	loaderIssue, err := database.RedeemLicense(ctx, licenseKey, discordID, 5*time.Minute, certificateSigner, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	loaderPackage, err := database.ConsumeLoaderDownload(ctx, loaderIssue.DownloadToken, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	devicePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublicKey := elliptic.Marshal(elliptic.P256(), devicePrivateKey.X, devicePrivateKey.Y)
	hwid := sha256.Sum256([]byte("artifact-ticket-device"))
	login, err := database.LoginLoader(
		ctx,
		loaderIssue.LoaderID,
		loaderPackage.CertificatePayload,
		loaderPackage.CertificateSignature,
		hex.EncodeToString(hwid[:]),
		devicePublicKey,
		loaderPackage.EnrollmentSecret,
		store.ClientContext{IP: "127.0.0.1", ClientNonce: base64.RawStdEncoding.EncodeToString(make([]byte, 24)), Version: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}

	artifactSource := filepath.Join(t.TempDir(), "neverlose.dll")
	if err := os.WriteFile(artifactSource, bytes.Repeat([]byte{0x41}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := manager.Import(artifactSource, "test-1", "windows-x86")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RegisterArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}

	const audience = "https://auth.example.test"
	server := New(
		config.Config{PublicURL: audience, DownloadTicketTTL: time.Minute},
		database,
		manager,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	challenge := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	if err := database.RegisterChallenge(ctx, challenge, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	exchangePrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exchangePublicKey := exchangePrivateKey.PublicKey().Bytes()
	clientNonce := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 24))
	proofMessage := artifactTicketMessage(audience, challenge, "windows-x86", exchangePublicKey, clientNonce)
	proofDigest := sha256.Sum256(proofMessage)
	r, s, err := ecdsa.Sign(rand.Reader, devicePrivateKey, proofDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	proof := make([]byte, 64)
	r.FillBytes(proof[:32])
	s.FillBytes(proof[32:])
	ticketBody, err := json.Marshal(map[string]string{
		"platform":          "windows-x86",
		"client_public_key": base64.RawStdEncoding.EncodeToString(exchangePublicKey),
		"device_signature":  base64.RawStdEncoding.EncodeToString(proof),
		"client_nonce":      clientNonce,
		"server_challenge":  challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketRequest := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/ticket", bytes.NewReader(ticketBody))
	ticketRequest.Header.Set("Authorization", "Bearer "+login.Token)
	ticketResponse := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(ticketResponse, ticketRequest)
	if ticketResponse.Code != http.StatusCreated {
		t.Fatalf("ticket status=%d body=%s", ticketResponse.Code, ticketResponse.Body.String())
	}
	var ticket struct {
		Token  string `json:"ticket"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := json.Unmarshal(ticketResponse.Body.Bytes(), &ticket); err != nil || ticket.Token == "" {
		t.Fatalf("invalid ticket response: %v", err)
	}

	wrongExchange, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	postDownload := func(publicKey []byte) *httptest.ResponseRecorder {
		body, marshalErr := json.Marshal(map[string]string{
			"ticket":            ticket.Token,
			"client_public_key": base64.RawStdEncoding.EncodeToString(publicKey),
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/download", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+login.Token)
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		return response
	}
	if response := postDownload(wrongExchange.PublicKey().Bytes()); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong exchange key status=%d", response.Code)
	}
	validResponse := postDownload(exchangePublicKey)
	if validResponse.Code != http.StatusOK || validResponse.Body.Len() == 0 {
		t.Fatalf("valid download status=%d size=%d", validResponse.Code, validResponse.Body.Len())
	}
	if response := postDownload(exchangePublicKey); response.Code != http.StatusUnauthorized {
		t.Fatalf("reused ticket status=%d", response.Code)
	}

	headerSHA := validResponse.Header().Get("X-NL-SHA256")
	headerSize, parseErr := strconv.ParseInt(validResponse.Header().Get("X-NL-Plaintext-Size"), 10, 64)
	if parseErr != nil {
		t.Fatalf("invalid plaintext size header: %v", parseErr)
	}
	if headerSHA != ticket.SHA256 || headerSize != ticket.Size {
		t.Fatalf("ticket metadata diverged from download: ticket=%s/%d download=%s/%d", ticket.SHA256, ticket.Size, headerSHA, headerSize)
	}
	serverKeyBytes, err := base64.RawStdEncoding.DecodeString(validResponse.Header().Get("X-NL-Server-Key"))
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := ecdh.P256().NewPublicKey(serverKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := exchangePrivateKey.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	saltInput := append([]byte(ticket.Token), exchangePublicKey...)
	salt := sha256.Sum256(saltInput)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt[:], []byte("nl-auth-artifact-envelope-v1")), derived); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(validResponse.Header().Get("X-NL-Nonce"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf("nl-artifact-v1\nversion=%s\nplatform=windows-x86\nsha256=%s\nsize=%d\n",
		validResponse.Header().Get("X-NL-Version"), headerSHA, headerSize)
	plaintext, err := gcm.Open(nil, nonce, validResponse.Body.Bytes(), []byte(manifest))
	if err != nil {
		t.Fatalf("watermarked envelope failed to decrypt: %v", err)
	}
	plaintextDigest := sha256.Sum256(plaintext)
	if hex.EncodeToString(plaintextDigest[:]) != headerSHA || int64(len(plaintext)) != headerSize {
		t.Fatal("watermarked plaintext does not match its ticket metadata")
	}
	if int64(len(plaintext)) <= artifact.Size {
		t.Fatal("watermarked plaintext is not larger than the source artifact")
	}
	extractedLoaderID, err := manager.ExtractWatermark(plaintext)
	if err != nil || extractedLoaderID != loaderIssue.LoaderID {
		t.Fatalf("downloaded artifact watermark mismatch: got %q want %q err=%v", extractedLoaderID, loaderIssue.LoaderID, err)
	}
}
