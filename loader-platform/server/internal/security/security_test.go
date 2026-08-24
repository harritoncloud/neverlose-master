package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(encoded, "correct-horse-battery-staple") {
		t.Fatal("valid password was rejected")
	}
	if VerifyPassword(encoded, "incorrect-password") {
		t.Fatal("invalid password was accepted")
	}
}

func TestLicenseAndHWIDNormalization(t *testing.T) {
	key, err := LicenseKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "NL-") {
		t.Fatalf("unexpected license format: %s", key)
	}
	if _, err := NormalizeLicense(strings.ToLower(key)); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("test-device"))
	normalized, err := NormalizeHWID(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if normalized != hex.EncodeToString(digest[:]) {
		t.Fatal("HWID normalization changed the digest")
	}
}
