package httpserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"nl-auth/internal/discordapi"
	"nl-auth/internal/store"
)

type securityEventRequest struct {
	EventID         string `json:"event_id"`
	EventType       string `json:"event_type"`
	Component       string `json:"component"`
	ExpectedSHA256  string `json:"expected_sha256"`
	ObservedSHA256  string `json:"observed_sha256"`
	ClientVersion   string `json:"client_version"`
	ClientNonce     string `json:"client_nonce"`
	Challenge       string `json:"server_challenge"`
	DeviceSignature string `json:"device_signature"`
}

func (s *Server) securityEvent(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.requireSession(writer, request)
	if !ok {
		return
	}
	if session.LoaderInstanceID <= 0 || len(session.DevicePublicKey) != 65 {
		writeError(writer, http.StatusForbidden, "security_event_denied", "Security event was rejected")
		return
	}
	if !s.allowRequest(request, fmt.Sprintf("security-event:%d", session.AccountID), 4, time.Hour) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	var input securityEventRequest
	if err := decodeJSON(writer, request, &input, 8<<10); err != nil {
		return
	}
	normalizeSecurityEvent(&input)
	if !validSecurityEventRequest(input) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid security event")
		return
	}
	if !clientVersionAtLeast(input.ClientVersion, minimumLoaderClientVersion) {
		writeError(writer, http.StatusUpgradeRequired, "loader_update_required", "Download a fresh personal loader through Discord")
		return
	}
	publicKey, err := parseP256PublicKey(session.DevicePublicKey)
	if err != nil {
		writeError(writer, http.StatusForbidden, "security_event_denied", "Security event was rejected")
		return
	}
	signature, err := decodeBase64(input.DeviceSignature, 64, 64)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "invalid_signature", "Security event signature is invalid")
		return
	}
	if err := s.store.ConsumeChallenge(request.Context(), input.Challenge); err != nil {
		writeError(writer, http.StatusUnauthorized, "challenge_invalid", "Authentication challenge is invalid")
		return
	}
	message := securityEventMessage(
		s.cfg.PublicURL,
		input.Challenge,
		input.EventID,
		input.EventType,
		input.Component,
		input.ExpectedSHA256,
		input.ObservedSHA256,
		input.ClientNonce,
		input.ClientVersion,
	)
	if !verifyRawP256(publicKey, message, signature) {
		writeError(writer, http.StatusUnauthorized, "invalid_signature", "Security event signature is invalid")
		return
	}
	incident, err := s.store.ApplySecurityEvent(request.Context(), session.ID, store.SecurityEventInput{
		EventID:        input.EventID,
		EventType:      input.EventType,
		Component:      input.Component,
		ExpectedSHA256: input.ExpectedSHA256,
		ObservedSHA256: input.ObservedSHA256,
		ClientVersion:  input.ClientVersion,
		IP:             clientIP(request),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSessionExpired):
			writeError(writer, http.StatusUnauthorized, "unauthorized", "Authentication required")
		case errors.Is(err, store.ErrSecurityEventReplay):
			writeError(writer, http.StatusConflict, "security_event_replayed", "Security event was already processed")
		default:
			s.logger.Error("security hold failed", "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		}
		return
	}
	s.queueSecurityNotification()
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"incident_id": incident.ID,
		"status":      incident.Disposition,
	})
}

func normalizeSecurityEvent(input *securityEventRequest) {
	input.EventID = strings.TrimSpace(input.EventID)
	input.EventType = strings.ToLower(strings.TrimSpace(input.EventType))
	input.Component = strings.ToLower(strings.TrimSpace(input.Component))
	input.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(input.ExpectedSHA256))
	input.ObservedSHA256 = strings.ToLower(strings.TrimSpace(input.ObservedSHA256))
	input.ClientVersion = strings.TrimSpace(input.ClientVersion)
	input.ClientNonce = strings.TrimSpace(input.ClientNonce)
	input.Challenge = strings.TrimSpace(input.Challenge)
	input.DeviceSignature = strings.TrimSpace(input.DeviceSignature)
}

func validSecurityEventRequest(input securityEventRequest) bool {
	if !validNonce(input.EventID) || !validNonce(input.ClientNonce) || !validNonce(input.Challenge) ||
		input.EventType != "post_run_hash_mismatch" ||
		(input.Component != "module" && input.Component != "injector") ||
		!validClientVersion(input.ClientVersion) || input.ExpectedSHA256 == input.ObservedSHA256 {
		return false
	}
	for _, value := range []string{input.ExpectedSHA256, input.ObservedSHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return false
		}
	}
	return true
}

func securityEventMessage(audience, challenge, eventID, eventType, component, expectedSHA256, observedSHA256, clientNonce, clientVersion string) []byte {
	return []byte(fmt.Sprintf(
		"nl-security-event-v1\naudience=%s\nchallenge=%s\nevent_id=%s\nevent_type=%s\ncomponent=%s\nexpected_sha256=%s\nobserved_sha256=%s\nclient_nonce=%s\nclient_version=%s\n",
		audience,
		challenge,
		eventID,
		eventType,
		component,
		expectedSHA256,
		observedSHA256,
		clientNonce,
		clientVersion,
	))
}

func (s *Server) queueSecurityNotification() {
	if s.cfg.DiscordSecurityChannelID == "" || s.cfg.DiscordBotToken == "" {
		return
	}
	select {
	case s.securityNotifications <- struct{}{}:
	default:
		// A queued wake-up will flush every pending outbox row.
	}
}

func (s *Server) securityNotificationLoop(ctx context.Context) {
	retryTicker := time.NewTicker(5 * time.Minute)
	defer retryTicker.Stop()
	s.flushSecurityNotifications(ctx)
	s.flushSecurityAlerts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.securityNotifications:
			s.flushSecurityNotifications(ctx)
			s.flushSecurityAlerts(ctx)
		case <-retryTicker.C:
			s.flushSecurityNotifications(ctx)
			s.flushSecurityAlerts(ctx)
		}
	}
}

func (s *Server) flushSecurityNotifications(ctx context.Context) {
	queryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	incidents, err := s.store.PendingSecurityNotifications(queryContext, 20)
	cancel()
	if err != nil {
		s.logger.Warn("security notification outbox query failed", "error", err)
		return
	}
	for _, incident := range incidents {
		if ctx.Err() != nil {
			return
		}
		s.sendSecurityNotification(ctx, incident)
	}
}

func (s *Server) sendSecurityNotification(ctx context.Context, incident store.SecurityIncident) {
	message := securityNotificationText(incident)
	sendContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	err := discordapi.SendChannelMessage(
		sendContext,
		s.cfg.DiscordBotToken,
		s.cfg.DiscordSecurityChannelID,
		message,
	)
	cancel()
	recordContext, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	recordErr := s.store.RecordSecurityNotification(recordContext, incident.ID, err)
	recordCancel()
	if recordErr != nil {
		s.logger.Warn("security notification result was not recorded", "incident_id", incident.ID, "error", recordErr)
	}
	if err != nil {
		s.logger.Warn("Discord security notification failed", "incident_id", incident.ID, "error", err)
	}
}

func (s *Server) flushSecurityAlerts(ctx context.Context) {
	queryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	alerts, err := s.store.PendingSecurityAlerts(queryContext, 20)
	cancel()
	if err != nil {
		s.logger.Warn("security alert outbox query failed", "error", err)
		return
	}
	for _, alert := range alerts {
		if ctx.Err() != nil {
			return
		}
		s.sendSecurityAlert(ctx, alert)
	}
}

func (s *Server) sendSecurityAlert(ctx context.Context, alert store.SecurityAlert) {
	sendContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	err := discordapi.SendChannelMessage(
		sendContext,
		s.cfg.DiscordBotToken,
		s.cfg.DiscordSecurityChannelID,
		alert.Message,
	)
	cancel()
	recordContext, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	recordErr := s.store.RecordSecurityAlertNotification(recordContext, alert.ID, err)
	recordCancel()
	if recordErr != nil {
		s.logger.Warn("security alert result was not recorded", "alert_id", alert.ID, "error", recordErr)
	}
	if err != nil {
		s.logger.Warn("Discord security alert failed", "alert_id", alert.ID, "error", err)
	}
}

func securityNotificationText(incident store.SecurityIncident) string {
	loaderID := maskIdentifier(incident.LoaderID)
	discordUser := "not linked"
	if incident.DiscordID != "" {
		discordUser = "<@" + incident.DiscordID + ">"
	}
	return fmt.Sprintf(
		"SECURITY HOLD #%d\nUser: %s\nLoader: `%s`\nSignal: `%s/%s`\nExpected: `%s`\nObserved: `%s`\nClient: `%s`\nIP: `%s`\nTime: <t:%d:F>\nAll sessions were revoked. Permanent ban requires review.",
		incident.ID,
		discordUser,
		loaderID,
		incident.EventType,
		incident.Component,
		hashPrefix(incident.ExpectedSHA256),
		hashPrefix(incident.ObservedSHA256),
		incident.ClientVersion,
		maskIPAddress(incident.IP),
		incident.CreatedAt.Unix(),
	)
}

func hashPrefix(value string) string {
	if len(value) > 12 {
		return value[:12] + "..."
	}
	return value
}

func maskIdentifier(value string) string {
	if len(value) > 10 {
		return value[:10] + "..."
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func maskIPAddress(value string) string {
	address := net.ParseIP(strings.TrimSpace(value))
	if address == nil {
		return "unknown"
	}
	if ipv4 := address.To4(); ipv4 != nil {
		return fmt.Sprintf("%d.%d.%d.x", ipv4[0], ipv4[1], ipv4[2])
	}
	return address.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
