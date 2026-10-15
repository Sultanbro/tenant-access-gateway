package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sultanbro/tenant-access-gateway/internal/auth"
	"github.com/Sultanbro/tenant-access-gateway/internal/policy"
)

type Gateway struct {
	snapshot     atomic.Pointer[policy.Snapshot]
	verifier     auth.Verifier
	internalKeys map[string][]byte
	logger       *slog.Logger
	transport    *http.Transport
	slots        chan struct{}
	Timeout      time.Duration
}

func New(config policy.Config, v auth.Verifier, keys map[string][]byte, logger *slog.Logger) (*Gateway, error) {
	if v.PublicKey == nil || v.PublicKey.N.BitLen() < 2048 || v.Issuer == "" || v.Audience == "" {
		return nil, errors.New("RSA public key, issuer, audience and a 32-byte internal key required")
	}
	s, err := policy.Compile(config)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	seenKeys := map[string]bool{}
	for name := range config.Services {
		if seenKeys[string(keys[name])] {
			return nil, errors.New("upstream signing keys must be distinct")
		}
		seenKeys[string(keys[name])] = true
		if len(keys[name]) < 32 {
			return nil, errors.New("each upstream requires its own 32-byte signing key")
		}
	}
	keyCopy := make(map[string][]byte)
	for name, key := range keys {
		keyCopy[name] = append([]byte(nil), key...)
	}
	g := &Gateway{verifier: v, internalKeys: keyCopy, logger: logger, slots: make(chan struct{}, 128), Timeout: 5 * time.Second, transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second}}
	g.snapshot.Store(s)
	return g, nil
}
func (g *Gateway) Close() { g.transport.CloseIdleConnections() }
func (g *Gateway) Reload(config policy.Config) error {
	for name := range config.Services {
		if len(g.internalKeys[name]) < 32 {
			return errors.New("new upstream signing key requires restart")
		}
	}
	s, err := policy.Compile(config)
	if err != nil {
		return err
	}
	g.snapshot.Store(s)
	return nil
}
func reply(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

type observed struct {
	http.ResponseWriter
	status int
}

func (w *observed) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *observed) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(data)
}
func (w *observed) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (g *Gateway) ServeHTTP(original http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Method == "GET" {
		reply(original, 200, "ok")
		return
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		reply(original, 500, "request unavailable")
		return
	}
	requestID := hex.EncodeToString(random)
	w := &observed{ResponseWriter: original}
	w.Header().Set("X-Request-ID", requestID)
	started := time.Now()
	s := g.snapshot.Load()
	subject, tenant, scope, service, resource, action, decision := "", "", "", "", "", "", "deny"
	defer func() {
		g.logger.Info("access", "request_id", requestID, "subject", subject, "tenant", tenant, "scope", scope, "service", service, "resource", resource, "action", action, "decision", decision, "status", w.status, "policy_version", s.Config.Version, "duration_ms", time.Since(started).Milliseconds())
	}()
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reply(w, 429, "gateway busy")
		return
	}
	// Reject encoded and ambiguous paths before matching policy and upstream routes.
	if strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "//") || r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, ";") {
		reply(w, 400, "non-canonical request URL")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 8 || parts[0] != "v1" || parts[1] != "tenants" || parts[3] != "scopes" || parts[5] != "services" {
		reply(w, 404, "route not found")
		return
	}
	tenant, scope, service = parts[2], parts[4], parts[6]
	path := "/" + strings.Join(parts[7:], "/")
	if len(r.Header.Values("Authorization")) != 1 {
		reply(w, 401, "bearer token required")
		return
	}
	bearer := strings.Fields(r.Header.Get("Authorization"))
	if len(bearer) != 2 || bearer[0] != "Bearer" {
		reply(w, 401, "bearer token required")
		return
	}
	identity, err := g.verifier.Verify(bearer[1])
	if err != nil {
		reply(w, 401, "invalid bearer token")
		return
	}
	subject = identity.Subject
	if identity.Tenant != tenant {
		reply(w, 403, "tenant mismatch")
		return
	}
	route, found := s.Match(service, r.Method, path)
	if !found {
		reply(w, 404, "route not found")
		return
	}
	resource, action = route.Resource, route.Action
	if !s.Allowed(subject, tenant, scope, service, resource, action) {
		reply(w, 403, "access denied")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		reply(w, 400, "invalid query")
		return
	}
	for _, name := range []string{"tenant", "tenant_id", "scope", "scope_id", "subject", "user_id"} {
		if query.Has(name) {
			reply(w, 400, "identity selectors must not be passed in query")
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			reply(w, 413, "body exceeds 1 MiB")
		} else {
			reply(w, 400, "invalid body")
		}
		return
	}
	contextToken, err := auth.SignInternal(g.internalKeys[service], subject, tenant, scope, service, r.Method, path)
	if err != nil {
		reply(w, 500, "request unavailable")
		return
	}
	target, _ := url.Parse(s.Config.Services[service].Upstream)
	proxy := httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			// Allow-list request headers. Never propagate client identity, cookies or proxy headers.
			p.Out.Header = make(http.Header)
			for _, name := range []string{"Accept", "Content-Type", "If-Match", "Idempotency-Key"} {
				if value := p.In.Header.Get(name); value != "" {
					p.Out.Header.Set(name, value)
				}
			}
			p.Out.Header.Set("Authorization", "Bearer "+contextToken)
			p.Out.Header.Set("X-Request-ID", requestID)
			p.SetURL(target)
			p.Out.URL.Path = path
			p.Out.URL.RawPath = ""
			p.Out.URL.RawQuery = query.Encode()
		},
		Transport: g.transport,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if req.Context().Err() != nil {
				reply(w, 504, "upstream deadline exceeded")
			} else {
				reply(w, 502, "upstream unavailable")
			}
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Set-Cookie")
			res.Header.Del("Server")
			res.Header.Del("X-Request-ID")
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				return errors.New("upstream redirects are disabled")
			}
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.Timeout)
	defer cancel()
	forwarded := r.Clone(ctx)
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	forwarded.ContentLength = int64(len(body))
	forwarded.TransferEncoding = nil
	forwarded.Trailer = nil
	decision = "allow"
	proxy.ServeHTTP(w, forwarded)
}
