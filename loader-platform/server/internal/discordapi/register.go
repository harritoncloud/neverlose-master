package discordapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"nl-auth/internal/config"
)

func RegisterCommands(ctx context.Context, cfg config.Config) error {
	if cfg.DiscordApplication == "" || cfg.DiscordGuildID == "" || cfg.DiscordBotToken == "" {
		return errors.New("Discord application ID, guild ID, and bot token are required")
	}
	commands := []map[string]any{
		{
			"name": "redeem", "description": "Link a license and receive your personal loader",
			"options": []map[string]any{
				{"type": 3, "name": "key", "description": "License key", "required": true, "min_length": 20, "max_length": 64},
			},
		},
		{
			"name": "loader", "description": "Create a new one-time link for your personal loader",
		},
		{
			"name": "license-create", "description": "Create a new license key",
			"default_member_permissions": "0",
			"options": []map[string]any{
				{"type": 4, "name": "days", "description": "Validity in days, 0 for lifetime", "required": true, "min_value": 0, "max_value": 3650},
				{"type": 4, "name": "devices", "description": "Allowed devices", "required": true, "min_value": 1, "max_value": 8},
				{"type": 6, "name": "user", "description": "Discord user receiving this license", "required": true},
				{"type": 3, "name": "note", "description": "Internal note", "required": false, "max_length": 256},
			},
		},
		{
			"name": "license-reissue", "description": "Revoke a user's old license and issue a new key",
			"default_member_permissions": "0",
			"options": []map[string]any{
				{"type": 6, "name": "user", "description": "Discord user", "required": true},
				{"type": 4, "name": "days", "description": "Validity in days, 0 for lifetime", "required": true, "min_value": 0, "max_value": 3650},
				{"type": 4, "name": "devices", "description": "Allowed devices", "required": true, "min_value": 1, "max_value": 8},
				{"type": 3, "name": "note", "description": "Internal note", "required": false, "max_length": 256},
			},
		},
		{
			"name": "license-revoke", "description": "Revoke a license and its sessions",
			"default_member_permissions": "0",
			"options":                    []map[string]any{{"type": 4, "name": "id", "description": "License ID from the admin panel", "required": true, "min_value": 1}},
		},
		{
			"name": "hwid-reset", "description": "Remove device bindings for a user",
			"default_member_permissions": "0",
			"options":                    []map[string]any{{"type": 6, "name": "user", "description": "Discord user", "required": true}},
		},
		{
			"name": "user-status", "description": "Change account status",
			"default_member_permissions": "0",
			"options": []map[string]any{
				{"type": 6, "name": "user", "description": "Discord user", "required": true},
				{"type": 3, "name": "status", "description": "New status", "required": true, "choices": []map[string]string{{"name": "Active", "value": "active"}, {"name": "Disabled", "value": "disabled"}, {"name": "Banned", "value": "banned"}}},
			},
		},
	}
	payload, err := json.Marshal(commands)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf(
		"https://discord.com/api/v10/applications/%s/guilds/%s/commands",
		url.PathEscape(cfg.DiscordApplication),
		url.PathEscape(cfg.DiscordGuildID),
	)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bot "+cfg.DiscordBotToken)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Discord API returned %s: %s", response.Status, string(body))
	}
	return nil
}
