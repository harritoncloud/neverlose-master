package httpserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"nl-auth/internal/artifacts"
	"nl-auth/internal/config"
	"nl-auth/internal/store"
)

func TestBuildPersonalizedFixture(t *testing.T) {
	if os.Getenv("NL_BUILD_PERSONALIZED_FIXTURE") != "1" {
		t.Skip("fixture build disabled")
	}
	templatePath := os.Getenv("NL_FIXTURE_TEMPLATE")
	outputPath := os.Getenv("NL_FIXTURE_OUTPUT")
	if templatePath == "" || outputPath == "" {
		t.Fatal("fixture paths are required")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := artifacts.New(t.TempDir(), cfg.ArtifactKey, cfg.SigningKey, cfg.MaxArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	templateBytes, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatal(err)
	}
	loaderID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 18))
	payload := []byte(fmt.Sprintf(
		"nl-loader-certificate-v1\naudience=%s\nloader_id=%s\nlicense_id=1\nissued_at=%d\n",
		cfg.PublicURL, loaderID, time.Now().UTC().Unix(),
	))
	signature, err := manager.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	personalized, err := personalizeLoader(templateBytes, store.LoaderPackage{
		LoaderID:             loaderID,
		CertificatePayload:   payload,
		CertificateSignature: signature,
		EnrollmentSecret:     "automatic-fixture-secret-1234",
		HeartbeatToken:       "automatic-fixture-heartbeat-0000",
	})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := protectLoaderImage(personalized, manager.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, protected, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_loader_id=%s", loaderID)
}
