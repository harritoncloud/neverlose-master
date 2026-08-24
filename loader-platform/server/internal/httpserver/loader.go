package httpserver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nl-auth/internal/store"
)

const (
	loaderFooterMagicV1    = "NLPERS01"
	loaderFooterMagic      = "NLPERS02"
	loaderFooterMagicV3    = "NLPERS03"
	loaderImageFooterMagic = "NLIMAGE1"
	minLoaderTemplate      = 1 << 20
	maxLoaderTemplate      = 64 << 20
)

var loaderDownloadTemplate = template.Must(template.New("loader-download").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Personal loader</title>
<style>
:root{color-scheme:dark;font-family:Segoe UI,sans-serif}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#090d16;color:#eef3ff}.card{width:min(420px,calc(100% - 32px));padding:28px;border:1px solid #26324b;border-radius:18px;background:#101827;box-shadow:0 24px 80px #0008}h1{margin:0 0 10px;font-size:24px}p{color:#aebbd3;line-height:1.5}.meta{font:12px Consolas,monospace;color:#7485a8;overflow-wrap:anywhere}button{width:100%;margin-top:16px;padding:13px;border:0;border-radius:10px;background:#4f7cff;color:white;font-weight:700;cursor:pointer}button:hover{background:#6790ff}
</style>
</head>
<body><main class="card"><h1>Personal loader is ready</h1><p>This link creates one download and then expires.</p><div class="meta">Loader: {{.LoaderID}}<br>Expires: {{.ExpiresAt}}</div><form method="post"><button type="submit">Download loader</button></form></main></body>
</html>`))

type loaderPageData struct {
	LoaderID  string
	ExpiresAt string
}

func (s *Server) registerLoaderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /loader/{token}", s.loaderDownloadPage)
	mux.HandleFunc("POST /loader/{token}", s.loaderDownload)
	mux.HandleFunc("POST /api/v1/loader/heartbeat", s.loaderHeartbeat)
	mux.HandleFunc("POST /api/v1/loader/violation", s.loaderViolation)
}

type loaderHeartbeatRequest struct {
	LoaderID      string `json:"loader_id"`
	HeartbeatToken string `json:"heartbeat_token"`
}

func (s *Server) loaderHeartbeat(writer http.ResponseWriter, request *http.Request) {
	var input loaderHeartbeatRequest
	if err := decodeJSON(writer, request, &input, 2<<10); err != nil {
		return
	}
	input.LoaderID = strings.TrimSpace(input.LoaderID)
	input.HeartbeatToken = strings.TrimSpace(input.HeartbeatToken)
	if !s.allowRequest(request, "heartbeat:"+input.LoaderID, 30, time.Hour) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	if err := s.store.ValidateHeartbeat(request.Context(), input.LoaderID, input.HeartbeatToken, s.cfg.HeartbeatTTL); err != nil {
		writeError(writer, http.StatusForbidden, "license_inactive", "License is not active")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"status":     "active",
		"renewed_for": int64(s.cfg.HeartbeatTTL.Seconds()),
	})
}

type loaderViolationRequest struct {
	LoaderID       string `json:"loader_id"`
	HeartbeatToken string `json:"heartbeat_token"`
	Reason         string `json:"reason"`
}

func (s *Server) loaderViolation(writer http.ResponseWriter, request *http.Request) {
	var input loaderViolationRequest
	if err := decodeJSON(writer, request, &input, 2<<10); err != nil {
		return
	}
	input.LoaderID = strings.TrimSpace(input.LoaderID)
	input.HeartbeatToken = strings.TrimSpace(input.HeartbeatToken)
	if !s.allowRequest(request, "violation:"+input.LoaderID, 10, time.Hour) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	if err := s.store.ReportViolation(request.Context(), input.LoaderID, input.HeartbeatToken, input.Reason, clientIP(request)); err != nil {
		writeError(writer, http.StatusForbidden, "violation_rejected", "Violation report was rejected")
		return
	}
	s.queueSecurityNotification()
	writeJSON(writer, http.StatusOK, map[string]any{"status": "recorded"})
}

func (s *Server) loaderDownloadPage(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "loader-page", 30, time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	if _, err := s.readLoaderTemplate(); err != nil {
		s.logger.Error("loader template is unavailable", "error", err)
		writeError(writer, http.StatusServiceUnavailable, "loader_unavailable", "Loader is temporarily unavailable")
		return
	}
	info, err := s.store.PeekLoaderDownload(request.Context(), request.PathValue("token"))
	if err != nil {
		writeError(writer, http.StatusGone, "link_unavailable", "This download link is invalid or expired")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if err := loaderDownloadTemplate.Execute(writer, loaderPageData{
		LoaderID:  info.LoaderID,
		ExpiresAt: info.ExpiresAt.Format(time.RFC3339),
	}); err != nil {
		s.logger.Error("loader page rendering failed", "error", err)
	}
}

func (s *Server) loaderDownload(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "loader-download", 10, time.Minute) {
		writeError(writer, http.StatusTooManyRequests, "rate_limited", "Try again later")
		return
	}
	templateBytes, err := s.readLoaderTemplate()
	if err != nil {
		s.logger.Error("loader template is unavailable", "error", err)
		writeError(writer, http.StatusServiceUnavailable, "loader_unavailable", "Loader is temporarily unavailable")
		return
	}
	personalization, err := s.store.ConsumeLoaderDownload(request.Context(), request.PathValue("token"), s.cfg.HeartbeatTTL)
	if err != nil {
		writeError(writer, http.StatusGone, "link_unavailable", "This download link is invalid or expired")
		return
	}
	personalized, err := personalizeLoader(templateBytes, personalization)
	if err != nil {
		s.logger.Error("loader personalization failed", "error", err)
		writeError(writer, http.StatusServiceUnavailable, "loader_unavailable", "Loader is temporarily unavailable")
		return
	}
	executable, err := protectLoaderImage(personalized, s.artifacts.Sign)
	if err != nil {
		s.logger.Error("loader image signing failed", "error", err)
		writeError(writer, http.StatusServiceUnavailable, "loader_unavailable", "Loader is temporarily unavailable")
		return
	}
	filename := "nl-loader-" + personalization.LoaderID
	if len(filename) > 34 {
		filename = filename[:34]
	}
	filename += ".exe"
	writer.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	writer.Header().Set("Content-Length", strconv.Itoa(len(executable)))
	writer.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(executable)
}

func (s *Server) loaderCertificate(loaderID string, licenseID int64, issuedAt time.Time) ([]byte, []byte, error) {
	payload := []byte(fmt.Sprintf(
		"nl-loader-certificate-v1\naudience=%s\nloader_id=%s\nlicense_id=%d\nissued_at=%d\n",
		s.cfg.PublicURL,
		loaderID,
		licenseID,
		issuedAt.Unix(),
	))
	signature, err := s.artifacts.Sign(payload)
	return payload, signature, err
}

func (s *Server) readLoaderTemplate() ([]byte, error) {
	if err := s.loaderTemplateAvailable(); err != nil {
		return nil, err
	}
	return os.ReadFile(s.cfg.LoaderTemplatePath)
}

func (s *Server) loaderTemplateAvailable() error {
	info, err := os.Lstat(s.cfg.LoaderTemplatePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < minLoaderTemplate || info.Size() > maxLoaderTemplate {
		return errors.New("loader template must be a regular file between 1 MiB and 64 MiB")
	}
	file, err := os.Open(s.cfg.LoaderTemplatePath)
	if err != nil {
		return err
	}
	defer file.Close()
	var signature [2]byte
	if _, err := file.ReadAt(signature[:], 0); err != nil || string(signature[:]) != "MZ" {
		return errors.New("loader template is not a PE executable")
	}
	var footer [len(loaderFooterMagic)]byte
	if _, err := file.ReadAt(footer[:], info.Size()-int64(len(footer))); err != nil {
		return err
	}
	if string(footer[:]) == loaderFooterMagic || string(footer[:]) == loaderFooterMagicV1 ||
		string(footer[:]) == loaderImageFooterMagic {
		return errors.New("loader template is already personalized")
	}
	return nil
}

func personalizeLoader(templateBytes []byte, personalization store.LoaderPackage) ([]byte, error) {
	if !validEnrollmentSecret(personalization.EnrollmentSecret) {
		return nil, errors.New("invalid loader enrollment secret")
	}
	if !validEnrollmentSecret(personalization.HeartbeatToken) {
		return nil, errors.New("invalid loader heartbeat token")
	}
	result := make([]byte, 0, len(templateBytes)+len(personalization.CertificatePayload)+
		len(personalization.CertificateSignature)+len(personalization.EnrollmentSecret)+
		len(personalization.HeartbeatToken)+20)
	result = append(result, templateBytes...)
	result = append(result, personalization.CertificatePayload...)
	result = append(result, personalization.CertificateSignature...)
	result = append(result, personalization.EnrollmentSecret...)
	result = append(result, personalization.HeartbeatToken...)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(personalization.CertificatePayload)))
	result = append(result, length...)
	binary.LittleEndian.PutUint32(length, uint32(len(personalization.EnrollmentSecret)))
	result = append(result, length...)
	binary.LittleEndian.PutUint32(length, uint32(len(personalization.HeartbeatToken)))
	result = append(result, length...)
	result = append(result, loaderFooterMagicV3...)
	return result, nil
}

func validEnrollmentSecret(value string) bool {
	if len(value) < 20 || len(value) > 64 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func protectLoaderImage(image []byte, sign func([]byte) ([]byte, error)) ([]byte, error) {
	if len(image) == 0 || len(image) > maxLoaderTemplate+(16<<10) || sign == nil {
		return nil, errors.New("invalid loader image")
	}
	digest := sha256.Sum256(image)
	manifest := []byte(fmt.Sprintf(
		"nl-loader-image-v1\nimage_size=%d\nimage_sha256=%s\n",
		len(image),
		hex.EncodeToString(digest[:]),
	))
	signature, err := sign(manifest)
	if err != nil {
		return nil, fmt.Errorf("sign loader image: %w", err)
	}
	if len(signature) != 64 || len(manifest) > 4096 {
		return nil, errors.New("invalid loader image signature")
	}

	result := make([]byte, 0, len(image)+len(manifest)+len(signature)+4+len(loaderImageFooterMagic))
	result = append(result, image...)
	result = append(result, manifest...)
	result = append(result, signature...)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(manifest)))
	result = append(result, length...)
	result = append(result, loaderImageFooterMagic...)
	return result, nil
}
