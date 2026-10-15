// Billing is a deliberately small in-memory upstream to demonstrate enforcement
// at the resource boundary as well as at the gateway. It is not a billing product.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Sultanbro/tenant-access-gateway/internal/auth"
)

type Invoice struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	Scope  string `json:"scope"`
	Amount int    `json:"amount_cents"`
}

func main() {
	key := []byte(os.Getenv("INTERNAL_SIGNING_KEY"))
	if len(key) < 32 {
		log.Fatal("INTERNAL_SIGNING_KEY required")
	}
	service := os.Getenv("SERVICE_NAME")
	if service == "" {
		service = "billing"
	}
	rows := map[string]Invoice{"acme/team-a/invoice-1": {ID: "invoice-1", Tenant: "acme", Scope: "team-a", Amount: 12500}, "globex/root/invoice-2": {ID: "invoice-2", Tenant: "globex", Scope: "root", Amount: 9900}}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := auth.VerifyInternal(key, service, r.Method, r.URL.Path, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			http.Error(w, "invalid gateway context", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if service == "hr" {
			if r.Method == "GET" && r.URL.Path == "/employees" {
				_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "employee-1", "tenant": c.Tenant, "scope": c.Scope, "name": "Demo Employee"}})
			} else {
				http.Error(w, "not found", 404)
			}
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/invoices" && r.Method == "GET" {
			items := []Invoice{}
			for _, row := range rows {
				if row.Tenant == c.Tenant && row.Scope == c.Scope {
					items = append(items, row)
				}
			}
			_ = json.NewEncoder(w).Encode(items)
			return
		}
		if r.URL.Path == "/invoices" && r.Method == "POST" {
			var body struct {
				ID     string `json:"id"`
				Amount int    `json:"amount_cents"`
			}
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			d.DisallowUnknownFields()
			if d.Decode(&body) != nil || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(body.ID) || body.Amount < 0 || body.Amount > 1000000000 {
				http.Error(w, "invalid invoice", 422)
				return
			}
			if _, ok := rows[c.Tenant+"/"+c.Scope+"/"+body.ID]; ok {
				http.Error(w, "ID exists", 409)
				return
			}
			row := Invoice{body.ID, c.Tenant, c.Scope, body.Amount}
			rows[c.Tenant+"/"+c.Scope+"/"+row.ID] = row
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(row)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/invoices/")
		storageKey := c.Tenant + "/" + c.Scope + "/" + id
		row, exists := rows[storageKey]
		if !exists || row.Tenant != c.Tenant || row.Scope != c.Scope {
			http.Error(w, "not found", 404)
			return
		}
		switch r.Method {
		case "GET":
			_ = json.NewEncoder(w).Encode(row)
		case "DELETE":
			delete(rows, storageKey)
			w.WriteHeader(204)
		case "PUT", "PATCH":
			var body struct {
				Amount int `json:"amount_cents"`
			}
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			d.DisallowUnknownFields()
			if d.Decode(&body) != nil || body.Amount < 0 {
				http.Error(w, "invalid invoice", 422)
				return
			}
			row.Amount = body.Amount
			rows[storageKey] = row
			_ = json.NewEncoder(w).Encode(row)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:9090"
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
