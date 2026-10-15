// Package policy compiles reviewed configuration into an immutable Casbin policy.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	defaultrolemanager "github.com/casbin/casbin/v2/rbac/default-role-manager"
)

const modelText = `[request_definition]
r = sub, dom, service, resource, action
[policy_definition]
p = sub, dom, service, resource, action, eft
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && (r.service == p.service || p.service == "*") && (r.resource == p.resource || p.resource == "*") && (r.action == p.action || p.action == "*")
`

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var actions = map[string]bool{"read": true, "create": true, "update": true, "delete": true, "*": true}

type Route struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}
type Service struct {
	Upstream string  `json:"upstream"`
	Routes   []Route `json:"routes"`
}
type Permission struct {
	Service  string `json:"service"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
}
type Role struct {
	Inherits    []string     `json:"inherits"`
	Permissions []Permission `json:"permissions"`
}
type Binding struct {
	Subject     string `json:"subject"`
	Role        string `json:"role"`
	Scope       string `json:"scope"`
	Descendants bool   `json:"descendants"`
}
type Tenant struct {
	Services []string          `json:"services"`
	Scopes   map[string]string `json:"scopes"`
	Roles    map[string]Role   `json:"roles"`
	Bindings []Binding         `json:"bindings"`
}
type Config struct {
	Version  string             `json:"version"`
	Services map[string]Service `json:"services"`
	Tenants  map[string]Tenant  `json:"tenants"`
}
type Snapshot struct {
	Config   Config
	enforcer *casbin.Enforcer
}

func Decode(data []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("expected one configuration object")
	}
	return c, nil
}
func graphCheck(name string, parents map[string][]string) error {
	state, depths := map[string]int{}, map[string]int{}
	var visit func(string) (int, error)
	visit = func(node string) (int, error) {
		if state[node] == 1 {
			return 0, fmt.Errorf("%s cycle at %s", name, node)
		}
		if state[node] == 2 {
			return depths[node], nil
		}
		next, exists := parents[node]
		if !exists {
			return 0, fmt.Errorf("unknown %s: %s", name, node)
		}
		if !identifier.MatchString(node) {
			return 0, fmt.Errorf("invalid %s name", name)
		}
		state[node] = 1
		depth := 1
		for _, parent := range next {
			value, err := visit(parent)
			if err != nil {
				return 0, err
			}
			if value+1 > depth {
				depth = value + 1
			}
		}
		if depth > 16 {
			return 0, fmt.Errorf("%s hierarchy exceeds 16 levels", name)
		}
		depths[node], state[node] = depth, 2
		return depth, nil
	}
	for node := range parents {
		if _, err := visit(node); err != nil {
			return err
		}
	}
	return nil
}
func canonicalTemplate(route string) (string, error) {
	if !strings.HasPrefix(route, "/") || route == "/" {
		return "", errors.New("route must start with / and have segments")
	}
	parts := strings.Split(route[1:], "/")
	for i, p := range parts {
		if p == "{id}" {
			parts[i] = "{}"
		} else if !identifier.MatchString(p) {
			return "", fmt.Errorf("invalid route segment %q", p)
		}
	}
	return strings.Join(parts, "/"), nil
}
func Compile(c Config) (*Snapshot, error) {
	if c.Version == "" || len(c.Version) > 64 || len(c.Services) == 0 || len(c.Services) > 50 || len(c.Tenants) == 0 || len(c.Tenants) > 100 {
		return nil, errors.New("invalid configuration size or version")
	}
	for name, service := range c.Services {
		u, err := url.Parse(service.Upstream)
		if !identifier.MatchString(name) || err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, fmt.Errorf("invalid upstream for %s (origin URL only)", name)
		}
		if len(service.Routes) == 0 || len(service.Routes) > 100 {
			return nil, errors.New("service needs 1..100 routes")
		}
		seen := map[string]bool{}
		for _, route := range service.Routes {
			shape, err := canonicalTemplate(route.Path)
			if err != nil {
				return nil, err
			}
			if !identifier.MatchString(route.Resource) || !actions[route.Action] || route.Action == "*" {
				return nil, errors.New("invalid route resource/action")
			}
			expected := map[string]string{"GET": "read", "HEAD": "read", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}
			if expected[route.Method] != route.Action {
				return nil, errors.New("route method must match CRUD action")
			}
			if seen[route.Method+shape] {
				return nil, errors.New("duplicate route")
			}
			seen[route.Method+shape] = true
			// Reject overlaps such as /invoices/latest and /invoices/{id}.
			for _, other := range service.Routes {
				if other.Method == route.Method && other.Path != route.Path && templatesOverlap(other.Path, route.Path) {
					return nil, errors.New("ambiguous route templates")
				}
			}
		}
	}
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, err
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}
	e.SetRoleManager(defaultrolemanager.NewRoleManager(32))
	// Bound generated policy size to keep configuration mistakes from exhausting memory.
	count := 0
	add := func(group bool, args ...string) error {
		count++
		if count > 100000 {
			return errors.New("expanded policy exceeds 100000 rules")
		}
		if group {
			_, err = e.AddGroupingPolicy(args)
		} else {
			_, err = e.AddPolicy(args)
		}
		return err
	}
	for name, t := range c.Tenants {
		if !identifier.MatchString(name) || len(t.Scopes) == 0 || len(t.Scopes) > 1000 || len(t.Roles) > 100 || len(t.Bindings) > 5000 {
			return nil, errors.New("invalid tenant limits")
		}
		enabled := map[string]bool{}
		for _, service := range t.Services {
			if _, ok := c.Services[service]; !ok {
				return nil, errors.New("tenant references unknown service")
			}
			enabled[service] = true
		}
		scopes := map[string][]string{}
		for scope, parent := range t.Scopes {
			scopes[scope] = nil
			if parent != "" {
				scopes[scope] = []string{parent}
			}
		}
		if err := graphCheck("scope", scopes); err != nil {
			return nil, err
		}
		roles := map[string][]string{}
		for role, def := range t.Roles {
			roles[role] = def.Inherits
		}
		if err := graphCheck("role", roles); err != nil {
			return nil, err
		}
		for scope := range t.Scopes {
			domain := name + "/" + scope
			for role, def := range t.Roles {
				for _, parent := range def.Inherits {
					if err := add(true, "role:"+role, "role:"+parent, domain); err != nil {
						return nil, err
					}
				}
				for _, p := range def.Permissions {
					if (p.Service != "*" && !enabled[p.Service]) || (p.Resource != "*" && !identifier.MatchString(p.Resource)) || !actions[p.Action] || (p.Effect != "allow" && p.Effect != "deny") {
						return nil, fmt.Errorf("invalid permission in %s/%s", name, role)
					}
					if err := add(false, "role:"+role, domain, p.Service, p.Resource, p.Action, p.Effect); err != nil {
						return nil, err
					}
				}
			}
		}
		for _, b := range t.Bindings {
			if !identifier.MatchString(b.Subject) {
				return nil, errors.New("invalid subject")
			}
			if _, ok := t.Roles[b.Role]; !ok {
				return nil, errors.New("binding references unknown role")
			}
			if _, ok := t.Scopes[b.Scope]; !ok {
				return nil, errors.New("binding references unknown scope")
			}
			for scope := range t.Scopes {
				if scope == b.Scope || (b.Descendants && descendant(t.Scopes, scope, b.Scope)) {
					if err := add(true, "user:"+b.Subject, "role:"+b.Role, name+"/"+scope); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if err := e.BuildRoleLinks(); err != nil {
		return nil, err
	}
	return &Snapshot{Config: c, enforcer: e}, nil
}
func descendant(parents map[string]string, child, ancestor string) bool {
	for child != "" {
		child = parents[child]
		if child == ancestor {
			return true
		}
	}
	return false
}
func templatesOverlap(a, b string) bool {
	x, y := strings.Split(a, "/"), strings.Split(b, "/")
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] && x[i] != "{id}" && y[i] != "{id}" {
			return false
		}
	}
	return true
}
func (s *Snapshot) Allowed(subject, tenant, scope, service, resource, action string) bool {
	t, ok := s.Config.Tenants[tenant]
	if !ok {
		return false
	}
	if _, ok = t.Scopes[scope]; !ok {
		return false
	}
	enabled := false
	for _, name := range t.Services {
		if name == service {
			enabled = true
		}
	}
	if !enabled {
		return false
	}
	allowed, err := s.enforcer.Enforce("user:"+subject, tenant+"/"+scope, service, resource, action)
	return err == nil && allowed
}
func (s *Snapshot) Match(service, method, path string) (Route, bool) {
	svc, ok := s.Config.Services[service]
	if !ok {
		return Route{}, false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if !identifier.MatchString(part) {
			return Route{}, false
		}
	}
	for _, route := range svc.Routes {
		if route.Method == method && templatesOverlap(route.Path, path) {
			return route, true
		}
	}
	return Route{}, false
}
