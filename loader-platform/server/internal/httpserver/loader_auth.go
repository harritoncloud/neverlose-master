package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nl-auth/internal/security"
)

const minimumLoaderClientVersion = "1.6.0"

type loaderSessionRequest struct {
	CertificatePayload   string `json:"certificate_payload"`
	CertificateSignature string `json:"certificate_signature"`
	HWIDHash             string `json:"hwid_hash"`
	DevicePublicKey      string `json:"device_public_key"`
	DeviceSignature      string `json:"device_signature"`
	PairingCode          string `json:"pairing_code"`
	ClientNonce          string `json:"client_nonce"`
	ClientVersion        string `json:"client_version"`
	Challenge            string `json:"server_challenge"`
}

type loaderCertificateData struct {
	LoaderID  string
	LicenseID int64
	IssuedAt  time.Time
}

func (s *Server) loaderSession(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "loader-login", 8, 10*time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	var input loaderSessionRequest
	if err := decodeJSON(writer, request, &input, 24<<10); err != nil {
		return
	}
	if !validNonce(input.ClientNonce) || !validClientVersion(input.ClientVersion) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if !clientVersionAtLeast(input.ClientVersion, minimumLoaderClientVersion) {
		writeError(writer, http.StatusUpgradeRequired, "loader_update_required", "Download a fresh personal loader through Discord")
		return
	}
	payload, err := decodeBase64(input.CertificatePayload, 1, 4096)
	if err != nil {
		s.loaderAuthDenied(writer)
		return
	}
	certificateSignature, err := decodeBase64(input.CertificateSignature, 64, 64)
	if err != nil || !s.artifacts.Verify(payload, certificateSignature) {
		s.loaderAuthDenied(writer)
		return
	}
	certificate, err := parseLoaderCertificate(payload, s.cfg.PublicURL, time.Now().UTC())
	if err != nil {
		s.loaderAuthDenied(writer)
		return
	}
	normalizedHWID, err := security.NormalizeHWID(input.HWIDHash)
	if err != nil {
		s.loaderAuthDenied(writer)
		return
	}
	publicKeySEC1, devicePublicKey, err := decodeP256PublicKey(input.DevicePublicKey)
	if err != nil {
		s.loaderAuthDenied(writer)
		return
	}
	deviceSignature, err := decodeBase64(input.DeviceSignature, 64, 64)
	if err != nil {
		s.loaderAuthDenied(writer)
		return
	}
	if err := s.store.ConsumeChallenge(request.Context(), input.Challenge); err != nil {
		writeError(writer, http.StatusUnauthorized, "challenge_invalid", "Authentication challenge is invalid")
		return
	}
	message := loaderAuthMessage(
		s.cfg.PublicURL,
		input.Challenge,
		certificate.LoaderID,
		payload,
		normalizedHWID,
		publicKeySEC1,
		strings.TrimSpace(input.PairingCode),
		input.ClientNonce,
		strings.TrimSpace(input.ClientVersion),
	)
	if !verifyRawP256(devicePublicKey, message, deviceSignature) {
		s.loaderAuthDenied(writer)
		return
	}
	result, err := s.store.LoginLoader(
		request.Context(),
		certificate.LoaderID,
		payload,
		certificateSignature,
		normalizedHWID,
		publicKeySEC1,
		strings.TrimSpace(input.PairingCode),
		s.clientContext(request, credentialsRequest{
			ClientNonce:   input.ClientNonce,
			ClientVersion: strings.TrimSpace(input.ClientVersion),
		}),
	)
	if err != nil {
		s.authError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusCreated, sessionResponse(result))
}

func parseLoaderCertificate(payload []byte, audience string, now time.Time) (loaderCertificateData, error) {
	if len(payload) == 0 || len(payload) > 4096 || strings.ContainsRune(string(payload), '\r') {
		return loaderCertificateData{}, errors.New("invalid loader certificate")
	}
	lines := strings.Split(string(payload), "\n")
	if len(lines) != 6 || lines[0] != "nl-loader-certificate-v1" || lines[5] != "" {
		return loaderCertificateData{}, errors.New("invalid loader certificate format")
	}
	if lines[1] != "audience="+audience || !strings.HasPrefix(lines[2], "loader_id=") ||
		!strings.HasPrefix(lines[3], "license_id=") || !strings.HasPrefix(lines[4], "issued_at=") {
		return loaderCertificateData{}, errors.New("invalid loader certificate fields")
	}
	loaderID := strings.TrimPrefix(lines[2], "loader_id=")
	decodedLoaderID, err := base64.RawURLEncoding.DecodeString(loaderID)
	if err != nil || len(decodedLoaderID) != 18 {
		return loaderCertificateData{}, errors.New("invalid loader ID")
	}
	licenseID, err := strconv.ParseInt(strings.TrimPrefix(lines[3], "license_id="), 10, 64)
	if err != nil || licenseID <= 0 {
		return loaderCertificateData{}, errors.New("invalid license ID")
	}
	issuedUnix, err := strconv.ParseInt(strings.TrimPrefix(lines[4], "issued_at="), 10, 64)
	if err != nil || issuedUnix <= 0 {
		return loaderCertificateData{}, errors.New("invalid certificate timestamp")
	}
	issuedAt := time.Unix(issuedUnix, 0).UTC()
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return loaderCertificateData{}, errors.New("certificate timestamp is in the future")
	}
	return loaderCertificateData{LoaderID: loaderID, LicenseID: licenseID, IssuedAt: issuedAt}, nil
}

func loaderAuthMessage(audience, challenge, loaderID string, certificatePayload []byte, normalizedHWID string, publicKeySEC1 []byte, pairingCode, clientNonce, clientVersion string) []byte {
	certificateDigest := sha256.Sum256(certificatePayload)
	pairingDigest := sha256.Sum256([]byte(pairingCode))
	return []byte(fmt.Sprintf(
		"nl-loader-auth-v2\naudience=%s\nchallenge=%s\nloader_id=%s\ncertificate_sha256=%s\nhwid_sha256=%s\ndevice_public_key=%s\npairing_code_sha256=%s\nclient_nonce=%s\nclient_version=%s\n",
		audience,
		challenge,
		loaderID,
		hex.EncodeToString(certificateDigest[:]),
		normalizedHWID,
		base64.RawStdEncoding.EncodeToString(publicKeySEC1),
		hex.EncodeToString(pairingDigest[:]),
		clientNonce,
		clientVersion,
	))
}

func artifactTicketMessage(audience, challenge, platform string, clientPublicKey []byte, clientNonce string) []byte {
	return []byte(fmt.Sprintf(
		"nl-artifact-ticket-v1\naudience=%s\nchallenge=%s\nplatform=%s\nclient_public_key=%s\nclient_nonce=%s\n",
		audience,
		challenge,
		platform,
		base64.RawStdEncoding.EncodeToString(clientPublicKey),
		clientNonce,
	))
}

func parseP256PublicKey(publicKeySEC1 []byte) (*ecdsa.PublicKey, error) {
	if len(publicKeySEC1) != 65 {
		return nil, errors.New("invalid P-256 public key")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeySEC1)
	if x == nil || y == nil {
		return nil, errors.New("invalid P-256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func decodeP256PublicKey(value string) ([]byte, *ecdsa.PublicKey, error) {
	publicKeySEC1, err := decodeBase64(value, 65, 65)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := parseP256PublicKey(publicKeySEC1)
	if err != nil {
		return nil, nil, err
	}
	return publicKeySEC1, publicKey, nil
}

func verifyRawP256(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil || len(signature) != 64 {
		return false
	}
	digest := sha256.Sum256(message)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return r.Sign() > 0 && s.Sign() > 0 && ecdsa.Verify(publicKey, digest[:], r, s)
}

func decodeBase64(value string, minimum, maximum int) ([]byte, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		return nil, errors.New("invalid base64 value")
	}
	return decoded, nil
}

func validClientVersion(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 64 && !strings.ContainsAny(value, "\r\n\x00")
}

func clientVersionAtLeast(value, minimum string) bool {
	current, ok := parseClientVersion(value)
	if !ok {
		return false
	}
	required, ok := parseClientVersion(minimum)
	if !ok {
		return false
	}
	for index := range current {
		if current[index] != required[index] {
			return current[index] > required[index]
		}
	}
	return true
}

func parseClientVersion(value string) ([3]uint64, bool) {
	var result [3]uint64
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != len(result) {
		return result, false
	}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, false
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return result, false
		}
		result[index] = parsed
	}
	return result, true
}

func (s *Server) loaderAuthDenied(writer http.ResponseWriter) {
	writeError(writer, http.StatusUnauthorized, "invalid_loader", "Loader authentication failed")
}
