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
	"strings"
	"time"
)

// SendChannelMessage sends a plain security notification without allowing
// mentions. Authentication data is supplied by the server environment only.
func SendChannelMessage(ctx context.Context, botToken, channelID, content string) error {
	botToken = strings.TrimSpace(botToken)
	channelID = strings.TrimSpace(channelID)
	content = strings.TrimSpace(content)
	if botToken == "" || channelID == "" {
		return errors.New("Discord security notification is not configured")
	}
	if content == "" || len(content) > 2000 {
		return errors.New("Discord message has an invalid size")
	}
	payload, err := json.Marshal(map[string]any{
		"content": content,
		"allowed_mentions": map[string]any{
			"parse": []string{},
		},
	})
	if err != nil {
		return err
	}
	endpoint := "https://discord.com/api/v10/channels/" + url.PathEscape(channelID) + "/messages"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bot "+botToken)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Discord API returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
