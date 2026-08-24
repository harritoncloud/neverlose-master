package httpserver

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nl-auth/internal/store"
)

const adminSessionTTL = 4 * time.Hour

type adminPageData struct {
	Title        string
	Username     string
	CSRF         string
	Error        string
	Message      string
	IssuedKey    string
	Counts       store.DashboardCounts
	Licenses     []store.LicenseView
	CookieSecure bool
}

var adminTemplates = template.Must(template.New("admin").Funcs(template.FuncMap{
	"date": func(value time.Time) string { return value.Local().Format("2006-01-02 15:04") },
	"expiry": func(value *time.Time) string {
		if value == nil {
			return "Lifetime"
		}
		return value.Local().Format("2006-01-02 15:04")
	},
}).Parse(adminTemplateSource))

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", s.adminLoginPage)
	mux.HandleFunc("POST /admin/login", s.adminLogin)
	mux.HandleFunc("GET /admin", s.adminDashboard)
	mux.HandleFunc("POST /admin/logout", s.adminLogout)
	mux.HandleFunc("POST /admin/licenses", s.adminIssueLicense)
	mux.HandleFunc("POST /admin/licenses/{id}/revoke", s.adminRevokeLicense)
	mux.HandleFunc("POST /admin/devices/reset", s.adminResetDevices)
	mux.HandleFunc("POST /admin/users/status", s.adminUserStatus)
}

func (s *Server) adminLoginPage(writer http.ResponseWriter, request *http.Request) {
	data := adminPageData{Title: "Sign in", CookieSecure: s.cfg.CookieSecure}
	s.renderAdmin(writer, "login", data)
}

func (s *Server) adminLogin(writer http.ResponseWriter, request *http.Request) {
	if !s.allowRequest(request, "admin-login", 6, 15*time.Minute) {
		s.renderAdmin(writer, "login", adminPageData{Title: "Sign in", Error: "Too many attempts. Try again later."})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 8<<10)
	if err := request.ParseForm(); err != nil {
		s.renderAdmin(writer, "login", adminPageData{Title: "Sign in", Error: "Invalid request."})
		return
	}
	token, csrf, expiresAt, err := s.store.AuthenticateAdmin(
		request.Context(),
		request.FormValue("username"),
		request.FormValue("password"),
		clientIP(request),
		adminSessionTTL,
	)
	if err != nil {
		time.Sleep(250 * time.Millisecond)
		s.renderAdmin(writer, "login", adminPageData{Title: "Sign in", Error: "Invalid credentials."})
		return
	}
	s.setAdminCookies(writer, token, csrf, expiresAt)
	http.Redirect(writer, request, "/admin", http.StatusSeeOther)
}

func (s *Server) adminDashboard(writer http.ResponseWriter, request *http.Request) {
	_, username, csrf, ok := s.requireAdmin(writer, request, false)
	if !ok {
		return
	}
	s.renderDashboard(writer, request, username, csrf, "", "", "")
}

func (s *Server) adminLogout(writer http.ResponseWriter, request *http.Request) {
	_, _, _, ok := s.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	if cookie, err := request.Cookie(s.adminCookieName()); err == nil {
		_ = s.store.LogoutAdmin(request.Context(), cookie.Value)
	}
	s.clearAdminCookies(writer)
	http.Redirect(writer, request, "/admin/login", http.StatusSeeOther)
}

func (s *Server) adminIssueLicense(writer http.ResponseWriter, request *http.Request) {
	_, username, csrf, ok := s.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(request.FormValue("days")))
	if err != nil || days < 0 || days > 3650 {
		s.renderDashboard(writer, request, username, csrf, "", "Validity must be between 0 and 3650 days.", "")
		return
	}
	maxDevices, err := strconv.Atoi(strings.TrimSpace(request.FormValue("max_devices")))
	if err != nil || maxDevices < 1 || maxDevices > 8 {
		s.renderDashboard(writer, request, username, csrf, "", "Device limit must be between 1 and 8.", "")
		return
	}
	key, err := s.store.IssueLicense(request.Context(), time.Duration(days)*24*time.Hour, maxDevices, request.FormValue("note"), username)
	if err != nil {
		s.logger.Error("license issue failed", "error", err)
		s.renderDashboard(writer, request, username, csrf, "", "Could not issue license.", "")
		return
	}
	s.renderDashboard(writer, request, username, csrf, key, "", "License created. It will not be shown again.")
}

func (s *Server) adminRevokeLicense(writer http.ResponseWriter, request *http.Request) {
	_, username, csrf, ok := s.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	licenseID, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
	if err != nil || licenseID <= 0 {
		s.renderDashboard(writer, request, username, csrf, "", "Invalid license.", "")
		return
	}
	if err := s.store.RevokeLicense(request.Context(), licenseID, username, clientIP(request)); err != nil {
		message := "Could not revoke license."
		if errors.Is(err, sql.ErrNoRows) {
			message = "License was already revoked or does not exist."
		}
		s.renderDashboard(writer, request, username, csrf, "", message, "")
		return
	}
	s.renderDashboard(writer, request, username, csrf, "", "", "License revoked and active sessions closed.")
}

func (s *Server) adminResetDevices(writer http.ResponseWriter, request *http.Request) {
	_, username, csrf, ok := s.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	count, err := s.store.ResetDevices(request.Context(), request.FormValue("username"), username, clientIP(request))
	if err != nil {
		s.renderDashboard(writer, request, username, csrf, "", "User was not found.", "")
		return
	}
	s.renderDashboard(writer, request, username, csrf, "", "", strconv.FormatInt(count, 10)+" device binding(s) removed.")
}

func (s *Server) adminUserStatus(writer http.ResponseWriter, request *http.Request) {
	_, username, csrf, ok := s.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	status := strings.ToLower(strings.TrimSpace(request.FormValue("status")))
	if err := s.store.SetUserStatus(request.Context(), request.FormValue("username"), status, username, clientIP(request)); err != nil {
		s.renderDashboard(writer, request, username, csrf, "", "Could not update user status.", "")
		return
	}
	s.renderDashboard(writer, request, username, csrf, "", "", "User status updated.")
}

func (s *Server) requireAdmin(writer http.ResponseWriter, request *http.Request, requireCSRF bool) (int64, string, string, bool) {
	sessionCookie, err := request.Cookie(s.adminCookieName())
	if err != nil {
		http.Redirect(writer, request, "/admin/login", http.StatusSeeOther)
		return 0, "", "", false
	}
	csrfCookie, err := request.Cookie(s.adminCSRFCookieName())
	if err != nil {
		s.clearAdminCookies(writer)
		http.Redirect(writer, request, "/admin/login", http.StatusSeeOther)
		return 0, "", "", false
	}
	csrf := csrfCookie.Value
	if requireCSRF {
		request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
		if err := request.ParseForm(); err != nil || request.FormValue("csrf") != csrf {
			writeError(writer, http.StatusForbidden, "csrf_failed", "Request verification failed")
			return 0, "", "", false
		}
	}
	accountID, username, err := s.store.ValidateAdminSession(request.Context(), sessionCookie.Value, csrf, requireCSRF)
	if err != nil {
		s.clearAdminCookies(writer)
		http.Redirect(writer, request, "/admin/login", http.StatusSeeOther)
		return 0, "", "", false
	}
	return accountID, username, csrf, true
}

func (s *Server) renderDashboard(writer http.ResponseWriter, request *http.Request, username, csrf, issuedKey, errorMessage, message string) {
	counts, err := s.store.Dashboard(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	licenses, err := s.store.ListLicenses(request.Context(), 100)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "Request failed")
		return
	}
	s.renderAdmin(writer, "dashboard", adminPageData{
		Title:     "Dashboard",
		Username:  username,
		CSRF:      csrf,
		IssuedKey: issuedKey,
		Error:     errorMessage,
		Message:   message,
		Counts:    counts,
		Licenses:  licenses,
	})
}

func (s *Server) renderAdmin(writer http.ResponseWriter, name string, data adminPageData) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTemplates.ExecuteTemplate(writer, name, data); err != nil {
		s.logger.Error("admin template failed", "template", name, "error", err)
	}
}

func (s *Server) setAdminCookies(writer http.ResponseWriter, token, csrf string, expiresAt time.Time) {
	common := func(name, value string) *http.Cookie {
		return &http.Cookie{
			Name:     name,
			Value:    value,
			Path:     "/",
			Expires:  expiresAt,
			MaxAge:   int(time.Until(expiresAt).Seconds()),
			HttpOnly: true,
			Secure:   s.cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
		}
	}
	http.SetCookie(writer, common(s.adminCookieName(), token))
	http.SetCookie(writer, common(s.adminCSRFCookieName(), csrf))
}

func (s *Server) clearAdminCookies(writer http.ResponseWriter) {
	for _, name := range []string{s.adminCookieName(), s.adminCSRFCookieName()} {
		http.SetCookie(writer, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   s.cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

func (s *Server) adminCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-nl_admin"
	}
	return "nl_admin"
}

func (s *Server) adminCSRFCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-nl_admin_csrf"
	}
	return "nl_admin_csrf"
}

const adminTemplateSource = `
{{define "head"}}
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} | NL Auth</title>
<style>
:root{color-scheme:dark;--bg:#0a0d12;--panel:#111720;--line:#253142;--text:#eef4ff;--muted:#8ea0b8;--accent:#54d6b2;--danger:#ff6b7d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#16212d 0,#0a0d12 44%);color:var(--text);font:14px/1.5 "Segoe UI",sans-serif;min-height:100vh}
main{width:min(1120px,calc(100% - 32px));margin:40px auto}.panel{background:rgba(17,23,32,.96);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 24px 70px #0008}
h1,h2{margin:0 0 16px}h1{font-size:26px}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}.stat{padding:18px;border:1px solid var(--line);border-radius:12px;background:#0d131b}.stat b{display:block;font-size:26px;color:var(--accent)}
input,select,button{font:inherit;color:var(--text);border:1px solid var(--line);border-radius:9px;background:#0a1017;padding:10px 12px}button{cursor:pointer;background:#183e38;border-color:#2a7164;font-weight:700}button.danger{background:#3d1820;border-color:#7a3040}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row input{min-width:150px;flex:1}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center}.notice{padding:12px 14px;border-radius:10px;margin:14px 0;border:1px solid #317966;background:#12352f}.error{border-color:#8d3444;background:#39171e}.key{font:700 16px ui-monospace,monospace;word-break:break-all;color:#b9ffe9}
table{width:100%;border-collapse:collapse;margin-top:18px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--muted);font-size:12px;text-transform:uppercase}.forms{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:20px}.forms .panel{padding:18px}.login{width:min(420px,calc(100% - 32px));margin:12vh auto}.login label{display:block;margin:12px 0 5px}.login input{width:100%}.login button{width:100%;margin-top:18px}
@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}.forms{grid-template-columns:1fr}table{display:block;overflow:auto}.toolbar{align-items:flex-start}}
</style></head><body>
{{end}}
{{define "login"}}{{template "head" .}}<main class="login"><section class="panel"><h1>NL Auth</h1><p class="muted">Restricted administration panel</p>{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}<form method="post" action="/admin/login"><label>Username</label><input name="username" required autocomplete="username"><label>Password</label><input type="password" name="password" required autocomplete="current-password"><button type="submit">Sign in</button></form></section></main></body></html>{{end}}
{{define "dashboard"}}{{template "head" .}}<main><div class="toolbar"><div><h1>NL Auth</h1><span class="muted">Signed in as {{.Username}}</span></div><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form></div>
{{if .Message}}<div class="notice">{{.Message}}</div>{{end}}{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}{{if .IssuedKey}}<div class="notice"><b>New license, shown once:</b><div class="key">{{.IssuedKey}}</div></div>{{end}}
<div class="grid"><div class="stat"><b>{{.Counts.Users}}</b>users</div><div class="stat"><b>{{.Counts.ActiveLicenses}}</b>active licenses</div><div class="stat"><b>{{.Counts.Devices}}</b>devices</div><div class="stat"><b>{{.Counts.ActiveSessions}}</b>sessions</div></div>
<div class="forms"><section class="panel"><h2>Issue license</h2><form class="row" method="post" action="/admin/licenses"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="number" name="days" min="0" max="3650" value="30" aria-label="Days"><input type="number" name="max_devices" min="1" max="8" value="1" aria-label="Devices"><input name="note" maxlength="256" placeholder="Note"><button type="submit">Create</button></form></section>
<section class="panel"><h2>Device reset</h2><form class="row" method="post" action="/admin/devices/reset"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="username" required placeholder="Username"><button type="submit">Reset HWID</button></form></section>
<section class="panel"><h2>User status</h2><form class="row" method="post" action="/admin/users/status"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="username" required placeholder="Username"><select name="status"><option value="active">Active</option><option value="disabled">Disabled</option><option value="banned">Banned</option></select><button type="submit">Update</button></form></section></div>
<section class="panel" style="margin-top:14px"><h2>Recent licenses</h2><table><thead><tr><th>Prefix</th><th>User</th><th>Status</th><th>Expires</th><th>Devices</th><th>Note</th><th>Created</th><th></th></tr></thead><tbody>{{range .Licenses}}<tr><td class="key">{{.Prefix}}...</td><td>{{if .Username}}{{.Username}}{{else}}unbound{{end}}</td><td>{{.Status}}</td><td>{{expiry .ExpiresAt}}</td><td>{{.DeviceCount}} / {{.MaxDevices}}</td><td>{{.Note}}</td><td>{{date .CreatedAt}}</td><td>{{if eq .Status "active"}}<form method="post" action="/admin/licenses/{{.ID}}/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="danger" type="submit">Revoke</button></form>{{end}}</td></tr>{{else}}<tr><td colspan="8" class="muted">No licenses yet.</td></tr>{{end}}</tbody></table></section></main></body></html>{{end}}
`
