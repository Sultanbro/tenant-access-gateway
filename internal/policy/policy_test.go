package policy

import (
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T) Config {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestAccessMatrix(t *testing.T) {
	s, err := Compile(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		subject, tenant, scope, service, resource, action string
		allowed                                           bool
	}{
		{"alice", "acme", "division", "billing", "invoices", "read", true},
		{"alice", "acme", "team-a", "billing", "invoices", "read", true},
		{"alice", "acme", "team-b", "billing", "invoices", "read", true},
		{"alice", "acme", "root", "billing", "invoices", "read", false},
		{"alice", "acme", "team-a", "billing", "invoices", "create", false},
		{"bob", "acme", "team-a", "billing", "invoices", "read", true},
		{"bob", "acme", "team-a", "billing", "invoices", "create", true},
		{"bob", "acme", "team-a", "billing", "invoices", "update", true},
		{"bob", "acme", "team-a", "billing", "invoices", "delete", false},
		{"bob", "acme", "team-b", "billing", "invoices", "read", false},
		{"bob", "globex", "root", "billing", "invoices", "read", false},
		{"alice", "globex", "root", "billing", "invoices", "delete", true},
		{"carol", "acme", "team-a", "billing", "invoices", "delete", false},
		{"carol", "acme", "team-b", "billing", "invoices", "delete", true},
		{"carol", "acme", "team-a", "billing", "invoices", "read", true},
		{"helen", "acme", "team-a", "hr", "employees", "read", true},
		{"helen", "acme", "team-a", "billing", "invoices", "read", false},
		{"alice", "globex", "root", "hr", "employees", "read", false},
		{"unknown", "acme", "root", "billing", "invoices", "read", false},
		{"role:manager", "acme", "root", "billing", "invoices", "read", false},
		{"alice", "unknown", "root", "billing", "invoices", "read", false},
		{"alice", "acme", "unknown", "billing", "invoices", "read", false},
	} {
		name := tt.subject + "/" + tt.tenant + "/" + tt.scope + "/" + tt.service + "/" + tt.action
		t.Run(name, func(t *testing.T) {
			if got := s.Allowed(tt.subject, tt.tenant, tt.scope, tt.service, tt.resource, tt.action); got != tt.allowed {
				t.Fatalf("allowed=%v want %v", got, tt.allowed)
			}
		})
	}
}
func TestInvalidConfigurationFailsClosed(t *testing.T) {
	cases := map[string]func(*Config){
		"role cycle": func(c *Config) {
			tenant := c.Tenants["acme"]
			role := tenant.Roles["reader"]
			role.Inherits = []string{"manager"}
			tenant.Roles["reader"] = role
		},
		"scope cycle":    func(c *Config) { c.Tenants["acme"].Scopes["root"] = "team-a" },
		"unknown role":   func(c *Config) { tenant := c.Tenants["acme"]; tenant.Bindings[0].Role = "unknown" },
		"unknown parent": func(c *Config) { c.Tenants["acme"].Scopes["root"] = "unknown" },
		"bad effect":     func(c *Config) { c.Tenants["acme"].Roles["reader"].Permissions[0].Effect = "maybe" },
		"bad upstream": func(c *Config) {
			service := c.Services["billing"]
			service.Upstream = "file:///etc/passwd"
			c.Services["billing"] = service
		},
		"upstream credentials": func(c *Config) {
			service := c.Services["billing"]
			service.Upstream = "http://user:pass@example.org"
			c.Services["billing"] = service
		},
		"method action mismatch": func(c *Config) { c.Services["billing"].Routes[0].Action = "delete" },
		"ambiguous route": func(c *Config) {
			service := c.Services["billing"]
			service.Routes = append(service.Routes, Route{"GET", "/invoices/latest", "invoices", "read"})
			c.Services["billing"] = service
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixture(t)
			mutate(&c)
			if _, err := Compile(c); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
func TestDecodeRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	raw, _ := json.Marshal(fixture(t))
	if _, err := Decode(append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("accepted trailing object")
	}
	if _, err := Decode([]byte(`{"unexpected":true}`)); err == nil {
		t.Fatal("accepted unknown field")
	}
}
