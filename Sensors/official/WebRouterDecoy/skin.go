package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"regexp"
	"strings"
)

// The skin engine: a login page is data (product, colours, fields, footer,
// headers), rendered by one html/template, so every value is auto-escaped and
// a new look needs no code. Built-in skins cover the usual decoy surfaces;
// TS_SKIN_JSON defines a custom one.

// Field is one input on the login form.
type Field struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	Type         string   `json:"type"` // text | password | email | select
	Autocomplete string   `json:"autocomplete,omitempty"`
	Options      []string `json:"options,omitempty"` // for select
}

// Skin describes one login surface.
type Skin struct {
	Name         string      `json:"name"`
	Product      string      `json:"product"`         // header brand text
	Title        string      `json:"title"`           // <title>
	PanelTitle   string      `json:"panel_title"`     // heading above the form
	Intro        string      `json:"intro"`           // text under the heading
	ErrorText    string      `json:"error_text"`      // shown after a failed login
	Button       string      `json:"button"`          // submit label
	Accent       string      `json:"accent"`          // #rrggbb
	Fields       []Field     `json:"fields"`          // form inputs, in order
	UserField    string      `json:"user_field"`      // field carrying the account name
	PassField    string      `json:"pass_field"`      // field carrying the password
	Footer       [][2]string `json:"footer"`          // label/value rows under the panel
	ServerHeader string      `json:"server_header"`   // HTTP Server header
	LoginPath    string      `json:"login_path"`      // form POST target
	Basic        bool        `json:"basic,omitempty"` // HTTP Basic auth instead of a form
	Realm        string      `json:"realm,omitempty"` // Basic auth realm
}

var (
	fieldNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	accentRe    = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	pathRe      = regexp.MustCompile(`^/[A-Za-z0-9/_.-]{0,63}$`)
)

func userPassFields(userLabel string) []Field {
	return []Field{
		{Name: "username", Label: userLabel, Type: "text", Autocomplete: "username"},
		{Name: "password", Label: "Password", Type: "password", Autocomplete: "current-password"},
	}
}

// builtinSkin returns a named built-in skin. product overrides the product
// name when set; for the router skin, brand drives the model/firmware footer.
func builtinSkin(name, product, brand string) (Skin, bool) {
	var s Skin
	switch name {
	case "router":
		model, firmware := brandProfile(brand)
		s = Skin{
			Product: brand, Title: brand + " Router Login", PanelTitle: "Router Login",
			Intro:     "Enter administrator credentials to access the device management interface.",
			ErrorText: "Login failed. Incorrect username or password.", Button: "Login", Accent: "#2c5d90",
			Fields:       userPassFields("Username"),
			Footer:       [][2]string{{"Model", model}, {"Firmware Version", firmware}, {"Hardware Version", "1.0"}},
			ServerHeader: "httpd",
		}
	case "nas":
		s = Skin{
			Product: "Storage Manager", Title: "Storage Manager - Sign In", PanelTitle: "Sign in to Storage Manager",
			Intro:     "Use your NAS account to manage shared folders, backups and users.",
			ErrorText: "The account or password is invalid. Please try again.", Button: "Sign In", Accent: "#1f7a5c",
			Fields:       userPassFields("Account"),
			Footer:       [][2]string{{"Model", "NS-4200"}, {"Version", "7.2.1-69057 Update 3"}},
			ServerHeader: "nginx",
		}
	case "vpn":
		s = Skin{
			Product: "Secure Access Portal", Title: "Secure Access SSL VPN", PanelTitle: "SSL VPN Login",
			Intro:     "Authorized users only. All access is logged.",
			ErrorText: "Permission denied. Check your username, password and realm.", Button: "Login", Accent: "#8a1c1c",
			Fields:       append(userPassFields("Username"), Field{Name: "realm", Label: "Realm", Type: "select", Options: []string{"Employees", "Contractors", "Admins"}}),
			Footer:       [][2]string{{"Gateway", "SSLVPN-GW01"}, {"Build", "7.0.12 b0523"}},
			ServerHeader: "xxxxxxxx-xxxxx", LoginPath: "/remote/login",
		}
	case "webmail":
		s = Skin{
			Product: "Web Mail", Title: "Web Mail - Login", PanelTitle: "Sign in to your mailbox",
			Intro:     "Enter your email address and password.",
			ErrorText: "Login failed. Please check your email address and password.", Button: "Sign in", Accent: "#2b579a",
			Fields: []Field{
				{Name: "email", Label: "Email address", Type: "email", Autocomplete: "username"},
				{Name: "password", Label: "Password", Type: "password", Autocomplete: "current-password"},
			},
			UserField:    "email",
			Footer:       [][2]string{{"Server", "mail01"}},
			ServerHeader: "Apache", LoginPath: "/mail/login",
		}
	case "admin":
		s = Skin{
			Product: "Administration Console", Title: "Administration Console", PanelTitle: "Administrator sign-in",
			Intro:     "This system is for authorized administrators only.",
			ErrorText: "Invalid username or password.", Button: "Sign in", Accent: "#3d4b5c",
			Fields:       userPassFields("Username"),
			Footer:       [][2]string{{"Version", "4.12.3"}},
			ServerHeader: "Apache-Coyote/1.1", LoginPath: "/admin/login",
		}
	case "basic":
		s = Skin{
			Product: "Network Device", Title: "401 Unauthorized", Basic: true, Realm: "Device Configuration",
			ServerHeader: "GoAhead-Webs",
		}
	default:
		return Skin{}, false
	}
	s.Name = name
	if product != "" {
		s.Product = product
		if !s.Basic {
			s.Title = product
		} else {
			s.Realm = product
		}
	}
	return s.withDefaults(), true
}

func (s Skin) withDefaults() Skin {
	if s.LoginPath == "" {
		s.LoginPath = "/login"
	}
	if s.UserField == "" {
		s.UserField = "username"
	}
	if s.PassField == "" {
		s.PassField = "password"
	}
	if s.Button == "" {
		s.Button = "Login"
	}
	if s.Accent == "" {
		s.Accent = "#2c5d90"
	}
	if s.Title == "" {
		s.Title = s.Product
	}
	for i := range s.Fields {
		if s.Fields[i].Type == "" {
			s.Fields[i].Type = "text"
		}
	}
	return s
}

// parseCustomSkin reads TS_SKIN_JSON. It is operator input, so it is
// validated strictly: anything that could break the page, the route table or
// capture (unknown field types, a missing user/password field) is rejected.
func parseCustomSkin(raw string) (Skin, error) {
	if len(raw) > 16<<10 {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON is larger than 16 KiB")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var s Skin
	if err := dec.Decode(&s); err != nil {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: %w", err)
	}
	if s.Name == "" {
		s.Name = "custom"
	}
	s = s.withDefaults()
	if s.Product == "" {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: product is required")
	}
	if !accentRe.MatchString(s.Accent) {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: accent must be #rrggbb")
	}
	if !pathRe.MatchString(s.LoginPath) || s.LoginPath == "/" {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: login_path must be a simple absolute path other than /")
	}
	for _, v := range []string{s.Name, s.Product, s.Title, s.PanelTitle, s.Intro, s.ErrorText, s.Button, s.ServerHeader, s.Realm} {
		if len(v) > 256 || strings.ContainsAny(v, "\r\n") {
			return Skin{}, fmt.Errorf("TS_SKIN_JSON: text values must be single-line and at most 256 bytes")
		}
	}
	if len(s.Footer) > 8 {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: at most 8 footer rows")
	}
	for _, row := range s.Footer {
		if len(row[0]) > 128 || len(row[1]) > 128 {
			return Skin{}, fmt.Errorf("TS_SKIN_JSON: footer values must be at most 128 bytes")
		}
	}
	if s.Basic {
		if s.Realm == "" {
			s.Realm = s.Product
		}
		return s, nil
	}
	if len(s.Fields) == 0 || len(s.Fields) > 8 {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: 1 to 8 fields required")
	}
	names := map[string]bool{}
	for _, f := range s.Fields {
		if !fieldNameRe.MatchString(f.Name) || names[f.Name] {
			return Skin{}, fmt.Errorf("TS_SKIN_JSON: bad or duplicate field name %q", f.Name)
		}
		if len(f.Label) > 128 || len(f.Options) > 16 {
			return Skin{}, fmt.Errorf("TS_SKIN_JSON: field %q label too long or more than 16 options", f.Name)
		}
		for _, o := range f.Options {
			if len(o) > 128 {
				return Skin{}, fmt.Errorf("TS_SKIN_JSON: field %q option longer than 128 bytes", f.Name)
			}
		}
		switch f.Type {
		case "text", "password", "email", "select":
		default:
			return Skin{}, fmt.Errorf("TS_SKIN_JSON: field %q has unsupported type %q", f.Name, f.Type)
		}
		names[f.Name] = true
	}
	if !names[s.UserField] || !names[s.PassField] {
		return Skin{}, fmt.Errorf("TS_SKIN_JSON: user_field and pass_field must name form fields")
	}
	return s, nil
}

// loadSkin picks the skin: TS_SKIN_JSON when set, else the named built-in.
func loadSkin(name, product, brand, custom string) (Skin, error) {
	if strings.TrimSpace(custom) != "" {
		return parseCustomSkin(custom)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "router"
	}
	s, ok := builtinSkin(name, product, brand)
	if !ok {
		return Skin{}, fmt.Errorf("unknown TS_SKIN %q (want router, nas, vpn, webmail, admin or basic)", name)
	}
	return s, nil
}

// pageData is what the template sees.
type pageData struct {
	Skin
	Failed bool
}

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: #e4e7eb; color: #333; }
.header { height: 64px; background: {{.Accent}}; display: flex; align-items: center; padding: 0 24px; color: #fff; }
.brand { font-size: 22px; font-weight: bold; letter-spacing: 0.4px; }
.container { width: 100%; max-width: 480px; margin: 72px auto; }
.panel { background: #fff; border: 1px solid #c3c9d1; }
.panel-header { background: #f3f5f7; border-bottom: 1px solid #d5dae0; padding: 12px 16px; font-weight: bold; color: #444; }
.panel-body { padding: 24px; }
.info { margin-bottom: 20px; font-size: 13px; color: #666; line-height: 1.5; }
.error { background: #fff2f2; border: 1px solid #d77; color: #a00000; padding: 10px; margin-bottom: 18px; font-size: 13px; }
.form-row { margin-bottom: 16px; }
label { display: block; margin-bottom: 6px; font-size: 13px; font-weight: bold; }
input, select { width: 100%; height: 34px; padding: 0 10px; border: 1px solid #aeb6bf; font-size: 13px; background: #fff; }
button { min-width: 100px; height: 34px; border: 0; background: {{.Accent}}; color: #fff; font-weight: bold; cursor: pointer; margin-top: 4px; }
.footer { margin-top: 14px; padding: 12px; background: #f7f7f7; border: 1px solid #cfd4da; font-size: 12px; color: #666; line-height: 1.6; }
.footer-row { display: flex; justify-content: space-between; }
@media (max-width: 600px) { .container { margin: 20px; width: auto; } }
</style>
</head>
<body>
<div class="header"><div class="brand">{{.Product}}</div></div>
<div class="container">
  <div class="panel">
    <div class="panel-header">{{.PanelTitle}}</div>
    <div class="panel-body">
      {{if .Intro}}<div class="info">{{.Intro}}</div>{{end}}
      {{if .Failed}}<div class="error">{{.ErrorText}}</div>{{end}}
      <form method="post" action="{{.LoginPath}}">
        {{range .Fields}}<div class="form-row">
          <label for="{{.Name}}">{{.Label}}</label>
          {{if eq .Type "select"}}<select id="{{.Name}}" name="{{.Name}}">{{range .Options}}<option>{{.}}</option>{{end}}</select>
          {{else}}<input id="{{.Name}}" name="{{.Name}}" type="{{.Type}}"{{if .Autocomplete}} autocomplete="{{.Autocomplete}}"{{end}} required>{{end}}
        </div>
        {{end}}<button type="submit">{{.Button}}</button>
      </form>
    </div>
  </div>
  {{if .Footer}}<div class="footer">{{range .Footer}}<div class="footer-row"><span>{{index . 0}}</span><span>{{index . 1}}</span></div>{{end}}</div>{{end}}
</div>
</body>
</html>`))

// basicTemplate is the body sent with a Basic-auth challenge.
var basicTemplate = template.Must(template.New("basic").Parse(`<!DOCTYPE html>
<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1><p>Authorization required to access {{.Realm}}.</p></body></html>`))
