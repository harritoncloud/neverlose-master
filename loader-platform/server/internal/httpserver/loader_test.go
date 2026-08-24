package httpserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/store"
)

func TestLoaderTemplateValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nl-loader.exe")
	templateBytes := make([]byte, minLoaderTemplate)
	copy(templateBytes, "MZ")
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	server := &Server{cfg: config.Config{LoaderTemplatePath: path}}
	if err := server.loaderTemplateAvailable(); err != nil {
		t.Fatalf("valid template was rejected: %v", err)
	}
	copy(templateBytes[len(templateBytes)-len(loaderFooterMagicV1):], loaderFooterMagicV1)
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.loaderTemplateAvailable(); err == nil {
		t.Fatal("legacy personalized executable was accepted as a generic template")
	}
	copy(templateBytes[len(templateBytes)-len(loaderFooterMagic):], loaderFooterMagic)
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.loaderTemplateAvailable(); err == nil {
		t.Fatal("personalized executable was accepted as a generic template")
	}
	copy(templateBytes[len(templateBytes)-len(loaderImageFooterMagic):], loaderImageFooterMagic)
	if err := os.WriteFile(path, templateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.loaderTemplateAvailable(); err == nil {
		t.Fatal("protected personalized executable was accepted as a generic template")
	}
}

func TestPersonalizeLoaderFooter(t *testing.T) {
	templateBytes := []byte{'M', 'Z', 0x90, 0x00}
	payload := []byte("signed-personalization")
	signature := bytes.Repeat([]byte{0x5a}, 64)
	enrollmentSecret := "automatic-enrollment-token-1234"
	heartbeatToken := "heartbeat-token-value-0000000000"
	result, err := personalizeLoader(templateBytes, store.LoaderPackage{
		LoaderID:             "loader-id",
		CertificatePayload:   payload,
		CertificateSignature: signature,
		EnrollmentSecret:     enrollmentSecret,
		HeartbeatToken:       heartbeatToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result[:len(templateBytes)], templateBytes) {
		t.Fatal("loader template was modified")
	}
	if !bytes.Equal(result[len(result)-len(loaderFooterMagicV3):], []byte(loaderFooterMagicV3)) {
		t.Fatal("loader footer magic is missing")
	}
	heartbeatLengthOffset := len(result) - len(loaderFooterMagicV3) - 4
	if got := binary.LittleEndian.Uint32(result[heartbeatLengthOffset : heartbeatLengthOffset+4]); got != uint32(len(heartbeatToken)) {
		t.Fatalf("heartbeat length=%d want=%d", got, len(heartbeatToken))
	}
	enrollmentLengthOffset := heartbeatLengthOffset - 4
	if got := binary.LittleEndian.Uint32(result[enrollmentLengthOffset : enrollmentLengthOffset+4]); got != uint32(len(enrollmentSecret)) {
		t.Fatalf("enrollment length=%d want=%d", got, len(enrollmentSecret))
	}
	payloadLengthOffset := enrollmentLengthOffset - 4
	if got := binary.LittleEndian.Uint32(result[payloadLengthOffset : payloadLengthOffset+4]); got != uint32(len(payload)) {
		t.Fatalf("payload length=%d want=%d", got, len(payload))
	}
	payloadOffset := len(templateBytes)
	if !bytes.Equal(result[payloadOffset:payloadOffset+len(payload)], payload) {
		t.Fatal("certificate payload changed")
	}
	signatureOffset := payloadOffset + len(payload)
	if !bytes.Equal(result[signatureOffset:signatureOffset+64], signature) {
		t.Fatal("certificate signature changed")
	}
	enrollmentOffset := signatureOffset + len(signature)
	if string(result[enrollmentOffset:enrollmentOffset+len(enrollmentSecret)]) != enrollmentSecret {
		t.Fatal("enrollment secret changed")
	}
	heartbeatOffset := enrollmentOffset + len(enrollmentSecret)
	if string(result[heartbeatOffset:heartbeatOffset+len(heartbeatToken)]) != heartbeatToken {
		t.Fatal("heartbeat token changed")
	}
}

func TestProtectLoaderImage(t *testing.T) {
	image := []byte("MZ-personalized-loader-image")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := artifacts.New(t.TempDir(), bytes.Repeat([]byte{0x42}, 32), privateKey, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := protectLoaderImage(image, manager.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(protected[:len(image)], image) {
		t.Fatal("protected loader image prefix changed")
	}
	if !bytes.Equal(protected[len(protected)-len(loaderImageFooterMagic):], []byte(loaderImageFooterMagic)) {
		t.Fatal("protected loader image footer is missing")
	}
	lengthOffset := len(protected) - len(loaderImageFooterMagic) - 4
	manifestLength := int(binary.LittleEndian.Uint32(protected[lengthOffset : lengthOffset+4]))
	signatureOffset := lengthOffset - 64
	manifestOffset := signatureOffset - manifestLength
	if manifestOffset != len(image) {
		t.Fatalf("manifest offset=%d want=%d", manifestOffset, len(image))
	}
	manifest := protected[manifestOffset:signatureOffset]
	if !manager.Verify(manifest, protected[signatureOffset:lengthOffset]) {
		t.Fatal("loader image signature verification failed")
	}
	digest := sha256.Sum256(image)
	expectedManifest := fmt.Sprintf(
		"nl-loader-image-v1\nimage_size=%d\nimage_sha256=%s\n",
		len(image),
		hex.EncodeToString(digest[:]),
	)
	if string(manifest) != expectedManifest {
		t.Fatalf("manifest=%q want=%q", manifest, expectedManifest)
	}
}

func TestLoaderCertificateAndDeviceProof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	loaderID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 18))
	audience := "https://auth.example.test"
	payload := []byte(fmt.Sprintf(
		"nl-loader-certificate-v1\naudience=%s\nloader_id=%s\nlicense_id=42\nissued_at=%d\n",
		audience,
		loaderID,
		now.Unix(),
	))
	parsed, err := parseLoaderCertificate(payload, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.LoaderID != loaderID || parsed.LicenseID != 42 || !parsed.IssuedAt.Equal(now) {
		t.Fatal("loader certificate fields changed")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	hwidDigest := sha256.Sum256([]byte("hwid"))
	message := loaderAuthMessage(
		audience,
		"challenge-token-with-enough-entropy",
		loaderID,
		payload,
		hex.EncodeToString(hwidDigest[:]),
		publicKey,
		"pairing-code-example-1234",
		base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 24)),
		"test-loader",
	)
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	if !verifyRawP256(&privateKey.PublicKey, message, signature) {
		t.Fatal("valid device proof was rejected")
	}
	signature[0] ^= 1
	if verifyRawP256(&privateKey.PublicKey, message, signature) {
		t.Fatal("modified device proof was accepted")
	}

	ticketMessage := artifactTicketMessage(
		audience,
		"fresh-artifact-challenge",
		"windows-x86",
		publicKey,
		base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 24)),
	)
	expectedTicketMessage := fmt.Sprintf(
		"nl-artifact-ticket-v1\naudience=%s\nchallenge=fresh-artifact-challenge\nplatform=windows-x86\nclient_public_key=%s\nclient_nonce=%s\n",
		audience,
		base64.RawStdEncoding.EncodeToString(publicKey),
		base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 24)),
	)
	if string(ticketMessage) != expectedTicketMessage {
		t.Fatal("artifact ticket proof is not canonical")
	}
}

func TestLoaderClientMinimumVersion(t *testing.T) {
	tests := []struct {
		version string
		allowed bool
	}{
		{version: "1.5.9"},
		{version: "1.6.0", allowed: true},
		{version: "1.6.1", allowed: true},
		{version: "2.0.0", allowed: true},
		{version: "01.6.0"},
		{version: "1.2"},
		{version: "test-loader"},
	}
	for _, test := range tests {
		if got := clientVersionAtLeast(test.version, minimumLoaderClientVersion); got != test.allowed {
			t.Fatalf("version %q allowed=%t want=%t", test.version, got, test.allowed)
		}
	}
}
