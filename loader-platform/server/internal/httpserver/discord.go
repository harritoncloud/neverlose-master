package httpserver

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nl-auth/internal/store"
)

const discordEphemeral = 1 << 6

type discordInteraction struct {
	Type          int                    `json:"type"`
	ApplicationID string                 `json:"application_id"`
	GuildID       string                 `json:"guild_id"`
	Member        discordMember          `json:"member"`
	User          discordUser            `json:"user"`
	Data          discordInteractionData `json:"data"`
}

type discordMember struct {
	User  discordUser `json:"user"`
	Roles []string    `json:"roles"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type discordInteractionData struct {
	Name    string                 `json:"name"`
	Options []discordCommandOption `json:"options"`
}

type discordCommandOption struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

func (s *Server) registerDiscordRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/discord/interactions", s.discordInteraction)
}

func (s *Server) discordInteraction(writer http.ResponseWriter, request *http.Request) {
	publicKey, err := hex.DecodeString(s.cfg.DiscordPublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	timestamp := request.Header.Get("X-Signature-Timestamp")
	signature, err := hex.DecodeString(request.Header.Get("X-Signature-Ed25519"))
	if err != nil || len(signature) != ed25519.SignatureSize || !recentDiscordTimestamp(timestamp) ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), append([]byte(timestamp), body...), signature) {
		writeError(writer, http.StatusUnauthorized, "invalid_signature", "Invalid signature")
		return
	}

	var interaction discordInteraction
	if err := json.Unmarshal(body, &interaction); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if interaction.Type == 1 {
		writeJSON(writer, http.StatusOK, map[string]int{"type": 1})
		return
	}
	if interaction.Type != 2 {
		s.discordReply(writer, "Unsupported interaction.")
		return
	}
	if s.cfg.DiscordApplication == "" || s.cfg.DiscordGuildID == "" ||
		interaction.ApplicationID != s.cfg.DiscordApplication || interaction.GuildID != s.cfg.DiscordGuildID {
		s.discordReply(writer, "Access denied.")
		return
	}
	actorID := discordActorID(interaction)
	actor := "discord:" + actorID
	options := discordOptions(interaction.Data.Options)
	if actorID == "" {
		s.discordReply(writer, "Discord user could not be identified.")
		return
	}

	switch interaction.Data.Name {
	case "redeem":
		if err := s.loaderTemplateAvailable(); err != nil {
			s.logger.Error("Discord redeem blocked: loader template unavailable", "error", err)
			s.discordReply(writer, "Loader is temporarily unavailable. Try again later.")
			return
		}
		issue, err := s.store.RedeemLicense(
			request.Context(),
			optionString(options, "key"),
			actorID,
			s.cfg.LoaderDownloadTTL,
			s.loaderCertificate,
			clientIP(request),
		)
		if err != nil {
			s.discordRedeemError(writer, err)
			return
		}
		s.discordLoaderReply(writer, issue, "License linked. Your personal loader is ready:")
		return
	case "loader":
		if err := s.loaderTemplateAvailable(); err != nil {
			s.logger.Error("Discord loader link blocked: loader template unavailable", "error", err)
			s.discordReply(writer, "Loader is temporarily unavailable. Try again later.")
			return
		}
		issue, err := s.store.RenewLoaderDownloadByDiscordID(request.Context(), actorID, s.cfg.LoaderDownloadTTL, clientIP(request))
		if err != nil {
			s.discordReply(writer, "No active personal loader was found. Redeem a license first.")
			return
		}
		s.discordLoaderReply(writer, issue, "A new one-time download link is ready:")
		return
	}

	if s.cfg.DiscordAdminRoleID == "" || !contains(interaction.Member.Roles, s.cfg.DiscordAdminRoleID) {
		s.discordReply(writer, "Access denied.")
		return
	}

	switch interaction.Data.Name {
	case "license-create":
		days := optionInt(options, "days", 30)
		devices := optionInt(options, "devices", 1)
		if days < 0 || days > 3650 || devices < 1 || devices > 8 {
			s.discordReply(writer, "Invalid days or device limit.")
			return
		}
		targetDiscordID := optionString(options, "user")
		if targetDiscordID == "" {
			s.discordReply(writer, "Discord user is required.")
			return
		}
		key, err := s.store.IssueLicenseForDiscord(request.Context(), time.Duration(days)*24*time.Hour, devices, optionString(options, "note"), actor, targetDiscordID)
		if err != nil {
			s.logger.Error("Discord license issue failed", "error", err)
			s.discordReply(writer, "License creation failed.")
			return
		}
		message := "License created (shown once): `" + key + "`\nAssigned to <@" + targetDiscordID + ">."
		s.discordReply(writer, message)
	case "license-reissue":
		days := optionInt(options, "days", 30)
		devices := optionInt(options, "devices", 1)
		discordID := optionString(options, "user")
		if days < 0 || days > 3650 || devices < 1 || devices > 8 {
			s.discordReply(writer, "Invalid days or device limit.")
			return
		}
		key, err := s.store.ReissueLicenseForDiscord(
			request.Context(),
			discordID,
			time.Duration(days)*24*time.Hour,
			devices,
			optionString(options, "note"),
			actor,
			clientIP(request),
		)
		if err != nil {
			s.logger.Error("Discord license reissue failed", "error", err)
			s.discordReply(writer, "License reissue failed.")
			return
		}
		s.discordReply(writer, "Previous license revoked. New key for <@"+discordID+"> (shown once): `"+key+"`")
	case "license-revoke":
		licenseID := int64(optionInt(options, "id", 0))
		if licenseID <= 0 || s.store.RevokeLicense(request.Context(), licenseID, actor, clientIP(request)) != nil {
			s.discordReply(writer, "License was not found or is already revoked.")
			return
		}
		s.discordReply(writer, "License revoked and sessions closed.")
	case "hwid-reset":
		discordID := optionString(options, "user")
		count, err := s.store.ResetDevicesByDiscordID(request.Context(), discordID, actor, clientIP(request))
		if err != nil {
			s.discordReply(writer, "User was not found.")
			return
		}
		s.discordReply(writer, strconv.FormatInt(count, 10)+" device binding(s) removed.")
	case "user-status":
		discordID := optionString(options, "user")
		status := strings.ToLower(optionString(options, "status"))
		if err := s.store.SetUserStatusByDiscordID(request.Context(), discordID, status, actor, clientIP(request)); err != nil {
			s.discordReply(writer, "Could not update user status.")
			return
		}
		s.discordReply(writer, "User status updated.")
	default:
		s.discordReply(writer, "Unknown command.")
	}
}

func (s *Server) discordRedeemError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLicenseUnavailable):
		s.discordReply(writer, "License key is invalid, expired, revoked, or assigned to another Discord user.")
	case errors.Is(err, store.ErrLicenseBound):
		s.discordReply(writer, "This license is already linked to another account.")
	case errors.Is(err, store.ErrDiscordBound):
		s.discordReply(writer, "Your Discord account already has an active license. Use `/loader` for a new download link.")
	default:
		s.logger.Error("Discord license redemption failed", "error", err)
		s.discordReply(writer, "License redemption failed. Try again later.")
	}
}

func (s *Server) discordLoaderReply(writer http.ResponseWriter, issue store.LoaderIssue, heading string) {
	link := strings.TrimRight(s.cfg.PublicURL, "/") + "/loader/" + url.PathEscape(issue.DownloadToken)
	s.discordReply(writer, fmt.Sprintf(
		"%s\n<%s>\nExpires <t:%d:R>. Download and run this personal loader; device verification is automatic.",
		heading, link, issue.ExpiresAt.Unix()))
}

func discordActorID(interaction discordInteraction) string {
	if interaction.Member.User.ID != "" {
		return interaction.Member.User.ID
	}
	return interaction.User.ID
}

func (s *Server) discordReply(writer http.ResponseWriter, content string) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"type": 4,
		"data": map[string]any{
			"content": content,
			"flags":   discordEphemeral,
		},
	})
}

func recentDiscordTimestamp(value string) bool {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	difference := time.Since(time.Unix(seconds, 0))
	return difference > -time.Minute && difference < 5*time.Minute
}

func discordOptions(options []discordCommandOption) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(options))
	for _, option := range options {
		result[option.Name] = option.Value
	}
	return result
}

func optionString(options map[string]json.RawMessage, name string) string {
	var value string
	_ = json.Unmarshal(options[name], &value)
	return strings.TrimSpace(value)
}

func optionInt(options map[string]json.RawMessage, name string, fallback int) int {
	raw, ok := options[name]
	if !ok {
		return fallback
	}
	var value int
	if err := json.Unmarshal(raw, &value); err == nil {
		return value
	}
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return int(number)
	}
	return fallback
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
