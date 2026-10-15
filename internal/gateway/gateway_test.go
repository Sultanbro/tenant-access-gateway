package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sultanbro/tenant-access-gateway/internal/auth"
	"github.com/Sultanbro/tenant-access-gateway/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

type harness struct {
	g       *Gateway
	config  policy.Config
	private *rsa.PrivateKey
	key     []byte
}

func setup(t *testing.T, upstream http.Handler) *harness {
	t.Helper()
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	data, err := os.ReadFile("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range c.Services {
		s.Upstream = server.URL
		c.Services[name] = s
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("x", 32))
	g, err := New(c, auth.Verifier{PublicKey: &private.PublicKey, Issuer: "test-issuer", Audience: "gateway"}, map[string][]byte{"billing": key, "hr": []byte(strings.Repeat("h", 32))}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return &harness{g, c, private, key}
}
func (h *harness) token(subject, tenant string) string {
	token, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, auth.Claims{Tenant: tenant, RegisteredClaims: jwt.RegisteredClaims{Subject: subject, Issuer: "test-issuer", Audience: jwt.ClaimStrings{"gateway"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}).SignedString(h.private)
	return token
}
func (h *harness) call(method, path, subject, tenant, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if subject != "" {
		r.Header.Set("Authorization", "Bearer "+h.token(subject, tenant))
	}
	w := httptest.NewRecorder()
	h.g.ServeHTTP(w, r)
	return w
}
func TestHTTPAccessBoundary(t *testing.T) {
	var reached atomic.Int32
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(204) }))
	prefix := "/v1/tenants/acme/scopes/team-a/services/billing"
	for _, tt := range []struct {
		name, method, path, subject, tenant string
		status                              int
	}{
		{"read", "GET", prefix + "/invoices", "alice", "acme", 204},
		{"inherited read", "GET", prefix + "/invoices/1", "bob", "acme", 204},
		{"write denied", "POST", prefix + "/invoices", "alice", "acme", 403},
		{"write allowed", "POST", prefix + "/invoices", "bob", "acme", 204},
		{"deny override", "DELETE", prefix + "/invoices/1", "carol", "acme", 403},
		{"no membership", "GET", prefix + "/invoices", "mallory", "acme", 403},
		{"company isolation", "GET", prefix + "/invoices", "alice", "globex", 403},
		{"scope isolation", "GET", "/v1/tenants/acme/scopes/team-b/services/billing/invoices", "bob", "acme", 403},
		{"service isolation", "GET", "/v1/tenants/acme/scopes/team-a/services/hr/employees", "alice", "acme", 403},
		{"unknown route", "GET", prefix + "/admin", "carol", "acme", 404},
		{"unregistered verb", "OPTIONS", prefix + "/invoices", "carol", "acme", 404},
		{"encoded path", "GET", prefix + "/%69nvoices", "alice", "acme", 400},
		{"dot segment", "GET", prefix + "/../invoices", "alice", "acme", 404},
		{"double slash", "GET", prefix + "//invoices", "alice", "acme", 400},
		{"tenant query", "GET", prefix + "/invoices?tenant=globex", "alice", "acme", 400},
		{"anonymous", "GET", prefix + "/invoices", "", "", 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := reached.Load()
			w := h.call(tt.method, tt.path, tt.subject, tt.tenant, "")
			if w.Code != tt.status {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if tt.status != 204 && reached.Load() != before {
				t.Fatal("denied request reached upstream")
			}
		})
	}
}
func TestProxySignsContextAndDropsSpoofedHeaders(t *testing.T) {
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := auth.VerifyInternal([]byte(strings.Repeat("x", 32)), "billing", r.Method, r.URL.Path, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			t.Error(err)
		}
		if c.Tenant != "acme" || c.Scope != "team-a" || c.Subject != "bob" {
			t.Errorf("wrong context %+v", c)
		}
		for _, name := range []string{"X-Tenant-ID", "X-User-ID", "X-Roles", "Forwarded", "X-Forwarded-For", "Cookie"} {
			if r.Header.Get(name) != "" {
				t.Errorf("forwarded spoofed %s", name)
			}
		}
		data, _ := io.ReadAll(r.Body)
		if string(data) != `{"amount_cents":100}` {
			t.Errorf("wrong body %s", data)
		}
		w.Header().Set("Set-Cookie", "session=upstream")
		w.Header().Set("X-Request-ID", "spoofed")
		w.WriteHeader(201)
	}))
	r := httptest.NewRequest("POST", "/v1/tenants/acme/scopes/team-a/services/billing/invoices", strings.NewReader(`{"amount_cents":100}`))
	r.Header.Set("Authorization", "Bearer "+h.token("bob", "acme"))
	for _, name := range []string{"X-Tenant-ID", "X-User-ID", "X-Roles", "Forwarded", "X-Forwarded-For", "Cookie", "X-Request-ID"} {
		r.Header.Set(name, "spoofed")
	}
	w := httptest.NewRecorder()
	h.g.ServeHTTP(w, r)
	if w.Code != 201 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Request-ID") == "spoofed" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}
func TestUpstreamFailureTimeoutAndBodyLimit(t *testing.T) {
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("redirect") == "1" {
			http.Redirect(w, r, "https://example.org", 302)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(200)
		}
	}))
	h.g.Timeout = 20 * time.Millisecond
	path := "/v1/tenants/acme/scopes/team-a/services/billing/invoices"
	if w := h.call("GET", path, "alice", "acme", ""); w.Code != 504 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := h.call("GET", path+"?redirect=1", "alice", "acme", ""); w.Code != 502 {
		t.Fatal(w.Code)
	}
	if w := h.call("POST", path, "bob", "acme", strings.Repeat("x", (1<<20)+1)); w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestAtomicReloadRevokesAndRejectsInvalidPolicy(t *testing.T) {
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	path := "/v1/tenants/acme/scopes/team-a/services/billing/invoices"
	raw, _ := json.Marshal(h.config)
	revoked, _ := policy.Decode(raw)
	tenant := revoked.Tenants["acme"]
	tenant.Bindings = nil
	revoked.Tenants["acme"] = tenant
	revoked.Version = "revoked"
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				w := h.call("GET", path, "alice", "acme", "")
				if w.Code != 204 && w.Code != 403 {
					t.Error(w.Code)
				}
			}
		})
	}
	if err := h.g.Reload(revoked); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if w := h.call("GET", path, "alice", "acme", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	invalid := h.config
	invalid.Version = ""
	if err := h.g.Reload(invalid); err == nil {
		t.Fatal("accepted invalid reload")
	}
	if w := h.call("GET", path, "alice", "acme", ""); w.Code != 403 {
		t.Fatal("invalid reload changed active policy")
	}
}
