package httpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"nl-auth/internal/config"
)

func TestDiscordInteractionSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{cfg: config.Config{DiscordPublicKeyHex: hex.EncodeToString(publicKey)}}
	body := []byte(`{"id":"123456789012345678","type":1}`)

	request := signedDiscordRequest(t, privateKey, strconv.FormatInt(time.Now().Unix(), 10), body)
	response := httptest.NewRecorder()
	server.discordInteraction(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"type":1`) {
		t.Fatalf("valid interaction status=%d body=%s", response.Code, response.Body.String())
	}

	tampered := signedDiscordRequest(t, privateKey, strconv.FormatInt(time.Now().Unix(), 10), body)
	tampered.Body = ioNopCloser{bytes.NewReader([]byte(`{"id":"123456789012345678","type":2}`))}
	response = httptest.NewRecorder()
	server.discordInteraction(response, tampered)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("tampered interaction status=%d", response.Code)
	}

	staleTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	stale := signedDiscordRequest(t, privateKey, staleTimestamp, body)
	response = httptest.NewRecorder()
	server.discordInteraction(response, stale)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("stale interaction status=%d", response.Code)
	}
}

func TestDiscordInteractionIsBoundToApplicationAndGuild(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{cfg: config.Config{
		DiscordPublicKeyHex: hex.EncodeToString(publicKey),
		DiscordApplication:  "100000000000000004",
		DiscordGuildID:      "100000000000000005",
	}}
	body := []byte(`{"type":2,"application_id":"100000000000000004","guild_id":"100000000000000001","member":{"user":{"id":"100000000000000002"}},"data":{"name":"loader"}}`)
	request := signedDiscordRequest(t, privateKey, strconv.FormatInt(time.Now().Unix(), 10), body)
	response := httptest.NewRecorder()
	server.discordInteraction(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Access denied") {
		t.Fatalf("foreign guild status=%d body=%s", response.Code, response.Body.String())
	}
}

type ioNopCloser struct {
	*bytes.Reader
}

func (ioNopCloser) Close() error { return nil }

func signedDiscordRequest(t *testing.T, privateKey ed25519.PrivateKey, timestamp string, body []byte) *http.Request {
	t.Helper()
	signed := append([]byte(timestamp), body...)
	signature := ed25519.Sign(privateKey, signed)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/discord/interactions", bytes.NewReader(body))
	request.Header.Set("X-Signature-Timestamp", timestamp)
	request.Header.Set("X-Signature-Ed25519", hex.EncodeToString(signature))
	return request
}
