package httpserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/security"
	"nl-auth/internal/store"
)

const serverVersion = "0.10.0"

type Server struct {
	cfg                   config.Config
	store                 *store.Store
	artifacts             *artifacts.Manager
	logger                *slog.Logger
	limiter               *rateLimiter
	http                  *http.Server
	securityNotifications chan struct{}
}

type credentialsRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	LicenseKey    string `json:"license_key"`
	HWIDHash      string `json:"hwid_hash"`
	ClientNonce   string `json:"client_nonce"`
	ClientVersion string `json:"client_version"`
	Challenge     string `json:"server_challenge"`
}

type ticketRequest struct {
	Platform        string `json:"platform"`
	ClientPublicKey string `json:"client_public_key"`
	DeviceSignature string `json:"device_signature"`
	ClientNonce     string `json:"client_nonce"`
	Challenge       string `json:"server_challenge"`
}

type downloadRequest struct {
	Ticket          string `json:"ticket"`
	ClientPublicKey string `json:"client_public_key"`
}

func New(cfg config.Config, database *store.Store, artifactManager *artifacts.Manager, logger *slog.Logger) *Server {
	server := &Server{
		cfg:                   cfg,
		store:                 database,
		artifacts:             artifactManager,
		logger:                logger,
		limiter:               newRateLimiter(),
		securityNotifications: make(chan struct{}, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /api/v1/public-key", server.publicKey)
	mux.HandleFunc("GET /api/v1/challenge", server.challenge)
	mux.HandleFunc("POST /api/v1/activate", server.activate)
	mux.HandleFunc("POST /api/v1/sessions", server.login)
	mux.HandleFunc("GET /api/v1/session", server.sessionInfo)
	mux.HandleFunc("DELETE /api/v1/session", server.logout)
	mux.HandleFunc("POST /api/v1/artifacts/ticket", server.artifactTicket)
	mux.HandleFunc("POST /api/v1/artifacts/download", server.artifactDownload)
	mux.HandleFunc("POST /api/v1/loader/sessions", server.loaderSession)
	mux.HandleFunc("POST /api/v1/security/events", server.securityEvent)
	server.registerAdminRoutes(mux)
	server.registerDiscordRoutes(mux)
	server.registerLoaderRoutes(mux)
	server.http = &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           server.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return server
}

func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) Background(ctx context.Context) {
	if s.cfg.DiscordSecurityChannelID != "" && s.cfg.DiscordBotToken != "" {
		go s.securityNotificationLoop(ctx)
	}
	pruneTicker := time.NewTicker(10 * time.Minute)
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pruneTicker.C:
			pruneContext, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := s.store.Prune(pruneContext); err != nil {
				s.logger.Error("database prune failed", "error", err)
			}
			cancel()
			s.limiter.prune(time.Hour)
		}
	}
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := request.Header.Get("X-Request-ID")
		if requestID == "" || len(requestID) > 96 {
			digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", time.Now().UnixNano(), request.RemoteAddr, request.URL.Path)))
			requestID = base64.RawURLEncoding.EncodeToString(digest[:12])
		}
		writer.Header().Set("X-Request-ID", requestID)
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("request panic", "request_id", requestID, "error", recovered)
				writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) health(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Health(ctx); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "unavailable", "Service unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok", "version": serverVersion})
}

func (s *Server) publicKey(writer http.ResponseWriter, _ *http.Request) {
	der, err := s.artifacts.PublicKeyDER()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"algorithm":       "ECDSA_P256_SHA256_RAW",
		"public_key_der":  base64.RawStdEncoding.EncodeToString(der),
		"public_key_sec1": base64.RawStdEncoding.EncodeToString(s.artifacts.PublicKeySEC1()),
	})
}

func (s *Server) challenge(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "challenge", 30, time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	nonce, err := security.RandomToken(32)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	expiresAt := time.Now().UTC().Add(60 * time.Second)
	message := challengeMessage(s.cfg.PublicURL, nonce, expiresAt.Unix())
	signature, err := s.artifacts.Sign(message)
	if err != nil || s.store.RegisterChallenge(request.Context(), nonce, expiresAt) != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"audience":   s.cfg.PublicURL,
		"nonce":      nonce,
		"expires_at": expiresAt.Unix(),
		"signature":  base64.RawStdEncoding.EncodeToString(signature),
	})
}

func (s *Server) activate(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "activate", 5, 10*time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	var input credentialsRequest
	if err := decodeJSON(writer, request, &input, 16<<10); err != nil {
		return
	}
	if !validNonce(input.ClientNonce) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if err := s.store.ConsumeChallenge(request.Context(), input.Challenge); err != nil {
		writeError(writer, http.StatusUnauthorized, "challenge_invalid", "Authentication challenge is invalid")
		return
	}
	result, err := s.store.Activate(request.Context(), input.Username, input.Password, input.LicenseKey, input.HWIDHash, s.clientContext(request, input))
	if err != nil {
		s.authError(writer, err, true)
		return
	}
	writeJSON(writer, http.StatusCreated, sessionResponse(result))
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "login", 8, 10*time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	var input credentialsRequest
	if err := decodeJSON(writer, request, &input, 16<<10); err != nil {
		return
	}
	if !validNonce(input.ClientNonce) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if err := s.store.ConsumeChallenge(request.Context(), input.Challenge); err != nil {
		writeError(writer, http.StatusUnauthorized, "challenge_invalid", "Authentication challenge is invalid")
		return
	}
	result, err := s.store.Login(request.Context(), input.Username, input.Password, input.LicenseKey, input.HWIDHash, s.clientContext(request, input))
	if err != nil {
		s.authError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusCreated, sessionResponse(result))
}

func (s *Server) sessionInfo(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.requireSession(writer, request)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"username":   session.Username,
		"expires_at": session.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) logout(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.requireSession(writer, request)
	if !ok {
		return
	}
	if err := s.store.Logout(request.Context(), session.ID, clientIP(request)); err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) artifactTicket(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.requireSession(writer, request)
	if !ok {
		return
	}
	if !s.allowRequest(request, "ticket:"+strconv.FormatInt(session.AccountID, 10), 10, time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	var input ticketRequest
	if err := decodeJSON(writer, request, &input, 4<<10); err != nil {
		return
	}
	platform := strings.ToLower(strings.TrimSpace(input.Platform))
	if platform == "" {
		platform = "windows-x86"
	}
	if !validClientVersion(platform) || !validNonce(input.ClientNonce) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Artifact request is invalid")
		return
	}
	clientPublicKey, _, err := decodeP256PublicKey(input.ClientPublicKey)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Artifact request is invalid")
		return
	}
	devicePublicKey, err := parseP256PublicKey(session.DevicePublicKey)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "device_proof_required", "Device proof is required")
		return
	}
	deviceSignature, err := decodeBase64(input.DeviceSignature, 64, 64)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "device_proof_invalid", "Device proof is invalid")
		return
	}
	if err := s.store.ConsumeChallenge(request.Context(), input.Challenge); err != nil {
		writeError(writer, http.StatusUnauthorized, "challenge_invalid", "Authentication challenge is invalid")
		return
	}
	proof := artifactTicketMessage(s.cfg.PublicURL, input.Challenge, platform, clientPublicKey, input.ClientNonce)
	if !verifyRawP256(devicePublicKey, proof, deviceSignature) {
		writeError(writer, http.StatusUnauthorized, "device_proof_invalid", "Device proof is invalid")
		return
	}
	artifact, err := s.store.LatestArtifact(request.Context(), platform)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(writer, http.StatusNotFound, "artifact_unavailable", "No artifact is available")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	watermarkSHA256 := ""
	var watermarkSize int64
	responseSHA256 := artifact.SHA256
	responseSize := artifact.Size
	if session.LoaderID != "" {
		trailer, trailerErr := s.artifacts.WatermarkTrailer(session.LoaderID)
		if trailerErr != nil {
			s.logger.Error("artifact watermark failed", "error", trailerErr)
			writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
			return
		}
		watermarkSHA256, watermarkSize, err = s.artifacts.WatermarkedMeta(artifact, trailer)
		if err != nil {
			s.logger.Error("artifact watermark metadata failed", "artifact_id", artifact.ID, "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
			return
		}
		responseSHA256 = watermarkSHA256
		responseSize = watermarkSize
	}
	token, expiresAt, err := s.store.CreateDownloadTicket(request.Context(), session.ID, artifact.ID, clientPublicKey, s.cfg.DownloadTicketTTL, watermarkSHA256, watermarkSize)
	if errors.Is(err, store.ErrSessionExpired) {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"ticket":     token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"version":    artifact.Version,
		"sha256":     responseSHA256,
		"size":       responseSize,
	})
}

func (s *Server) artifactDownload(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "download", 20, time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	session, ok := s.requireSession(writer, request)
	if !ok {
		return
	}
	var input downloadRequest
	if err := decodeJSON(writer, request, &input, 16<<10); err != nil {
		return
	}
	clientPublicKey, _, err := decodeP256PublicKey(input.ClientPublicKey)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Artifact request is invalid")
		return
	}
	artifact, watermark, err := s.store.ConsumeDownloadTicket(request.Context(), strings.TrimSpace(input.Ticket), session.ID, clientPublicKey)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "invalid_ticket", "Download ticket is invalid")
		return
	}
	var trailer []byte
	if watermark.SHA256 != "" {
		if session.LoaderID == "" {
			writeError(writer, http.StatusUnauthorized, "invalid_ticket", "Download ticket is invalid")
			return
		}
		trailer, err = s.artifacts.WatermarkTrailer(session.LoaderID)
		if err != nil {
			s.logger.Error("artifact watermark failed", "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
			return
		}
	}
	envelope, err := s.artifacts.Seal(artifact, input.Ticket, input.ClientPublicKey, trailer)
	if err != nil {
		s.logger.Warn("artifact sealing failed", "artifact_id", artifact.ID, "error", err)
		writeError(writer, http.StatusBadRequest, "invalid_request", "Artifact request is invalid")
		return
	}
	if watermark.SHA256 != "" && (envelope.SHA256 != watermark.SHA256 || envelope.PlaintextSize != watermark.Size) {
		s.logger.Error("artifact watermark mismatch", "artifact_id", artifact.ID)
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.Itoa(len(envelope.Ciphertext)))
	writer.Header().Set("X-NL-Server-Key", envelope.ServerPublicKey)
	writer.Header().Set("X-NL-Nonce", envelope.Nonce)
	writer.Header().Set("X-NL-Version", envelope.Version)
	writer.Header().Set("X-NL-Platform", envelope.Platform)
	writer.Header().Set("X-NL-SHA256", envelope.SHA256)
	writer.Header().Set("X-NL-Plaintext-Size", strconv.FormatInt(envelope.PlaintextSize, 10))
	writer.Header().Set("X-NL-Signature", envelope.Signature)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(envelope.Ciphertext)
}

func (s *Server) requireSession(writer http.ResponseWriter, request *http.Request) (store.AuthenticatedSession, bool) {
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return store.AuthenticatedSession{}, false
	}
	session, err := s.store.AuthenticateSession(request.Context(), strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return store.AuthenticatedSession{}, false
	}
	return session, true
}

func (s *Server) authError(writer http.ResponseWriter, err error, activation bool) {
	switch {
	case errors.Is(err, store.ErrDeviceLimit):
		writeError(writer, http.StatusForbidden, "device_limit", "Device limit reached")
	case errors.Is(err, store.ErrDeviceRevoked):
		writeError(writer, http.StatusForbidden, "device_revoked", "Device access was revoked")
	case errors.Is(err, store.ErrPairingRequired):
		writeError(writer, http.StatusPreconditionRequired, "device_pairing_required", "Download a fresh personal loader through Discord")
	case errors.Is(err, store.ErrPairingInvalid):
		writeError(writer, http.StatusForbidden, "device_pairing_invalid", "Automatic device enrollment is invalid or expired")
	case activation && errors.Is(err, store.ErrLicenseBound):
		writeError(writer, http.StatusConflict, "license_activated", "License is already activated")
	case errors.Is(err, store.ErrLicenseUnavailable):
		writeError(writer, http.StatusForbidden, "license_unavailable", "License is unavailable")
	case errors.Is(err, store.ErrInvalidCredentials):
		writeError(writer, http.StatusUnauthorized, "invalid_credentials", "Credentials are invalid")
	default:
		s.logger.Error("authentication failed", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
	}
}

func (s *Server) clientContext(request *http.Request, input credentialsRequest) store.ClientContext {
	return store.ClientContext{
		IP:          clientIP(request),
		UserAgent:   request.UserAgent(),
		ClientNonce: input.ClientNonce,
		Version:     strings.TrimSpace(input.ClientVersion),
	}
}

func (s *Server) allowRequest(request *http.Request, scope string, limit int, window time.Duration) bool {
	return s.limiter.allow(scope+"|"+clientIP(request), limit, window)
}

func sessionResponse(result store.SessionResult) map[string]any {
	return map[string]any{
		"access_token": result.Token,
		"token_type":   "Bearer",
		"expires_at":   result.ExpiresAt.Format(time.RFC3339),
		"username":     result.Username,
	}
}

func validNonce(value string) bool {
	if len(value) < 22 || len(value) > 128 {
		return false
	}
	encodings := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return len(decoded) >= 16 && len(decoded) <= 64
		}
	}
	return false
}

func challengeMessage(audience, nonce string, expiresAt int64) []byte {
	return []byte(fmt.Sprintf(
		"nl-auth-challenge-v1\naudience=%s\nnonce=%s\nexpires_at=%d\n",
		audience,
		nonce,
		expiresAt,
	))
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any, maxBytes int64) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json", "Invalid JSON request")
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_json", "Request must contain one JSON object")
		return errors.New("multiple JSON objects")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	parsed := net.ParseIP(host)
	if parsed != nil && parsed.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	if parsed == nil {
		return "unknown"
	}
	return parsed.String()
}
