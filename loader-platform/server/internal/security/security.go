package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
)

func RandomToken(size int) (string, error) {
	if size < 16 {
		return "", errors.New("token size is too small")
	}
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func Digest(pepper []byte, value string) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", errors.New("password must contain 12 to 256 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}

	var memory uint64
	var iterations uint64
	var threads uint64
	for _, parameter := range strings.Split(parts[3], ",") {
		keyValue := strings.SplitN(parameter, "=", 2)
		if len(keyValue) != 2 {
			return false
		}
		value, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return false
		}
		switch keyValue[0] {
		case "m":
			memory = value
		case "t":
			iterations = value
		case "p":
			threads = value
		}
	}
	if memory == 0 || memory > 256*1024 || iterations == 0 || iterations > 10 || threads == 0 || threads > 8 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func NormalizeUsername(value string) (display string, canonical string, err error) {
	display = strings.TrimSpace(value)
	if len(display) < 3 || len(display) > 32 {
		return "", "", errors.New("username must contain 3 to 32 characters")
	}
	for _, char := range display {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.') {
			return "", "", errors.New("username contains unsupported characters")
		}
	}
	return display, strings.ToLower(display), nil
}

func NormalizeLicense(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) < 20 || len(value) > 64 {
		return "", errors.New("invalid license key")
	}
	for _, char := range value {
		if !((char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
			return "", errors.New("invalid license key")
		}
	}
	return value, nil
}

func NormalizeHWID(value string) (string, error) {
	value = strings.TrimSpace(value)
	var decoded []byte
	var err error
	if len(value) == 64 {
		decoded, err = hex.DecodeString(value)
	} else {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(value)
		}
	}
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("hwid_hash must be a SHA-256 value")
	}
	return hex.EncodeToString(decoded), nil
}

func LicenseKey() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	parts := make([]string, 5)
	for part := range parts {
		chunk := make([]byte, 4)
		for index := range chunk {
			chunk[index] = alphabet[int(raw[part*4+index])%len(alphabet)]
		}
		parts[part] = string(chunk)
	}
	return "NL-" + strings.Join(parts, "-"), nil
}
