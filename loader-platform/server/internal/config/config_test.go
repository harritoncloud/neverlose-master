package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePublicURL(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		secure bool
		valid  bool
	}{
		{name: "https", input: "https://auth.example.test", want: "https://auth.example.test", secure: true, valid: true},
		{name: "trailing slash", input: "https://auth.example.test/", want: "https://auth.example.test", secure: true, valid: true},
		{name: "ipv4 loopback", input: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080", valid: true},
		{name: "ipv6 loopback", input: "http://[::1]:8080", want: "http://[::1]:8080", valid: true},
		{name: "localhost", input: "http://localhost:8080", want: "http://localhost:8080", valid: true},
		{name: "public http", input: "http://auth.example.test"},
		{name: "path", input: "https://auth.example.test/api"},
		{name: "query", input: "https://auth.example.test?x=1"},
		{name: "fragment", input: "https://auth.example.test/#x"},
		{name: "credentials", input: "https://user:pass@auth.example.test"},
		{name: "wrong scheme", input: "ftp://auth.example.test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, secure, err := validatePublicURL(test.input)
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid URL was accepted")
			}
			if test.valid && (got != test.want || secure != test.secure) {
				t.Fatalf("got=(%q,%t) want=(%q,%t)", got, secure, test.want, test.secure)
			}
		})
	}
}

func TestLoadDiscordBotToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discord-token")
	valid := strings.Repeat("a", 24) + "." + strings.Repeat("b", 32)
	if err := os.WriteFile(path, []byte(valid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadDiscordBotToken(path)
	if err != nil || loaded != valid {
		t.Fatalf("token=%q error=%v", loaded, err)
	}
	if err := os.WriteFile(path, []byte("invalid token with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiscordBotToken(path); err == nil {
		t.Fatal("token with embedded whitespace was accepted")
	}
}

func TestValidateDiscordConfig(t *testing.T) {
	valid := Config{
		DiscordPublicKeyHex: strings.Repeat("a1", 32),
		DiscordAdminRoleID:  "100000000000000003",
		DiscordApplication:  "100000000000000004",
		DiscordGuildID:      "100000000000000005",
	}
	if err := validateDiscordConfig(Config{}); err != nil {
		t.Fatalf("disabled Discord integration was rejected: %v", err)
	}
	if err := validateDiscordConfig(valid); err != nil {
		t.Fatalf("valid Discord integration was rejected: %v", err)
	}

	partial := valid
	partial.DiscordGuildID = ""
	if err := validateDiscordConfig(partial); err == nil {
		t.Fatal("partial Discord integration was accepted")
	}
	invalidID := valid
	invalidID.DiscordGuildID = "not-a-snowflake"
	if err := validateDiscordConfig(invalidID); err == nil {
		t.Fatal("invalid Discord guild ID was accepted")
	}
	invalidKey := valid
	invalidKey.DiscordPublicKeyHex = "00"
	if err := validateDiscordConfig(invalidKey); err == nil {
		t.Fatal("invalid Discord public key was accepted")
	}
	securityAlerts := valid
	securityAlerts.DiscordSecurityChannelID = "1349059000000000000"
	securityAlerts.DiscordBotToken = strings.Repeat("t", 48)
	if err := validateDiscordConfig(securityAlerts); err != nil {
		t.Fatalf("valid Discord security channel was rejected: %v", err)
	}
	missingToken := valid
	missingToken.DiscordSecurityChannelID = "1349059000000000000"
	if err := validateDiscordConfig(missingToken); err == nil {
		t.Fatal("Discord security channel without bot token was accepted")
	}
	invalidChannel := securityAlerts
	invalidChannel.DiscordSecurityChannelID = "invalid"
	if err := validateDiscordConfig(invalidChannel); err == nil {
		t.Fatal("invalid Discord security channel was accepted")
	}
}
