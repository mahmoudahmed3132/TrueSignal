package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/truesignal/sdk-go"
)

type event struct {
	severity, trigger, source, target string
	details                           map[string]any
}

type fakeReporter struct {
	mu     sync.Mutex
	events []event
}

func (f *fakeReporter) ReportEventSeverity(severity, trigger, source, target string, d sdk.EventDetails) bool {
	m := map[string]any{}
	for _, kv := range d {
		m[kv.Key] = kv.Value
	}
	f.mu.Lock()
	f.events = append(f.events, event{severity, trigger, source, target, m})
	f.mu.Unlock()
	return true
}

func (f *fakeReporter) last() event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events[len(f.events)-1]
}

func newTestDecoy(t *testing.T, skin Skin) (*decoy, *fakeReporter, http.Handler) {
	t.Helper()
	fr := &fakeReporter{}
	d := &decoy{ts: fr, skin: skin, passwordMode: "hash", passwordKey: []byte("k"), probes: newProbeLimiter(time.Minute)}
	return d, fr, d.routes()
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	r.RemoteAddr = "203.0.113.7:51000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func post(path string, form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestBuiltinSkinsRenderAndCapture(t *testing.T) {
	for _, name := range []string{"router", "nas", "vpn", "webmail", "admin"} {
		t.Run(name, func(t *testing.T) {
			skin, err := loadSkin(name, "", "Netgear", "")
			if err != nil {
				t.Fatal(err)
			}
			_, fr, h := newTestDecoy(t, skin)

			w := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, `action="`+skin.LoginPath+`"`) || strings.Contains(body, `class="error"`) {
				t.Fatalf("GET / = %d\n%s", w.Code, body)
			}
			for _, f := range skin.Fields {
				if !strings.Contains(body, `name="`+f.Name+`"`) {
					t.Errorf("field %s missing", f.Name)
				}
			}
			if w.Header().Get("Server") != skin.ServerHeader || strings.Contains(body, "ZgotmplZ") {
				t.Errorf("server header %q or unsafe template value", w.Header().Get("Server"))
			}
			if e := fr.last(); e.trigger != "web_page_view" || e.details["skin"] != name {
				t.Errorf("page view = %+v", e)
			}

			form := url.Values{skin.UserField: {"svc_backup"}, skin.PassField: {"Winter2026!"}, "realm": {"Admins"}}
			w = serve(h, post(skin.LoginPath, form))
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `class="error"`) {
				t.Fatalf("login = %d", w.Code)
			}
			e := fr.last()
			if e.trigger != "web_login_attempt" || e.severity != "" || e.details["attempted_username"] != "svc_backup" ||
				e.details["attempted_password_hmac"] == nil || e.details["auth"] != "form" || e.details["skin"] != name {
				t.Fatalf("login event = %+v", e)
			}
			for k, v := range e.details {
				if s, ok := v.(string); ok && strings.Contains(s, "Winter2026!") {
					t.Fatalf("cleartext password in %s", k)
				}
			}
			if _, has := e.details["form_realm"]; has != (name == "vpn") {
				t.Errorf("form_realm present=%v for %s", has, name)
			}
		})
	}
}

func TestRouterSkinKeepsBrandFooter(t *testing.T) {
	skin, _ := loadSkin("", "", "Cisco", "")
	_, _, h := newTestDecoy(t, skin)
	body := serve(h, httptest.NewRequest(http.MethodGet, "/", nil)).Body.String()
	if skin.Name != "router" || !strings.Contains(body, "RV340") || !strings.Contains(body, "Cisco Router Login") {
		t.Fatalf("router default lost the brand profile:\n%s", body)
	}
}

func TestProbeAndMethodHandling(t *testing.T) {
	skin, _ := loadSkin("admin", "", "", "")
	_, fr, h := newTestDecoy(t, skin)
	if w := serve(h, httptest.NewRequest(http.MethodGet, "/.env", nil)); w.Code != 404 {
		t.Fatalf("probe = %d", w.Code)
	}
	if e := fr.last(); e.trigger != "web_path_probe" || e.details["path"] != "/.env" {
		t.Fatalf("probe event = %+v", e)
	}
	if w := serve(h, httptest.NewRequest(http.MethodGet, "/admin/login", nil)); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET login = %d", w.Code)
	}
}

func TestBasicSkinCapturesAuthorization(t *testing.T) {
	skin, _ := loadSkin("basic", "Core Switch", "", "")
	_, fr, h := newTestDecoy(t, skin)

	w := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Basic realm="Core Switch"` {
		t.Fatalf("challenge = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	r := httptest.NewRequest(http.MethodGet, "/cgi-bin/config", nil)
	r.SetBasicAuth("admin", "Winter2026!")
	if w = serve(h, r); w.Code != 401 {
		t.Fatalf("auth attempt = %d", w.Code)
	}
	e := fr.last()
	if e.trigger != "web_login_attempt" || e.details["auth"] != "basic" || e.details["attempted_username"] != "admin" ||
		e.details["attempted_password_hmac"] == nil || e.details["path"] != "/cgi-bin/config" {
		t.Fatalf("basic event = %+v", e)
	}
}

func TestTemplateEscapesSkinValues(t *testing.T) {
	skin, err := loadSkin("", "", "", `{"product":"<script>alert(1)</script>","accent":"#112233","login_path":"/sso/login",
		"fields":[{"name":"user","label":"\"><img src=x onerror=alert(1)>","type":"text"},{"name":"pass","label":"Password","type":"password"}],
		"user_field":"user","pass_field":"pass","footer":[["Build","<b>1</b>"]]}`)
	if err != nil {
		t.Fatal(err)
	}
	_, fr, h := newTestDecoy(t, skin)
	body := serve(h, httptest.NewRequest(http.MethodGet, "/", nil)).Body.String()
	for _, bad := range []string{"<script>alert", "<img src=x", "<b>1</b>"} {
		if strings.Contains(body, bad) {
			t.Fatalf("unescaped %q in page", bad)
		}
	}
	serve(h, post("/sso/login", url.Values{"user": {"jdoe"}, "pass": {"x"}}))
	if e := fr.last(); e.details["attempted_username"] != "jdoe" || e.details["skin"] != "custom" {
		t.Fatalf("custom skin event = %+v", e)
	}
}

func TestCustomSkinValidation(t *testing.T) {
	ok := `"product":"P","fields":[{"name":"username","label":"U"},{"name":"password","label":"P","type":"password"}]`
	if _, err := parseCustomSkin("{" + ok + "}"); err != nil {
		t.Fatalf("valid skin rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown key":     `{` + ok + `,"script":"x"}`,
		"css injection":   `{` + ok + `,"accent":"red;}body{display:none"}`,
		"root login path": `{` + ok + `,"login_path":"/"}`,
		"relative path":   `{` + ok + `,"login_path":"login"}`,
		"header split":    `{` + ok + `,"server_header":"x\r\nSet-Cookie: a=b"}`,
		"no product":      `{"fields":[{"name":"username"},{"name":"password"}]}`,
		"bad field type":  `{"product":"P","fields":[{"name":"username","type":"hidden"},{"name":"password"}]}`,
		"dup field":       `{"product":"P","fields":[{"name":"username"},{"name":"username"}],"pass_field":"username"}`,
		"missing pass":    `{"product":"P","fields":[{"name":"username"}]}`,
		"oversize":        `{"product":"` + strings.Repeat("a", 17<<10) + `"}`,
	} {
		if _, err := parseCustomSkin(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := loadSkin("sharepoint", "", "", ""); err == nil {
		t.Error("unknown built-in accepted")
	}
}
