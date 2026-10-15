package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{&key.PublicKey, "https://issuer.example", "gateway"}
	valid := Claims{Tenant: "acme", RegisteredClaims: jwt.RegisteredClaims{Subject: "alice", Issuer: v.Issuer, Audience: jwt.ClaimStrings{v.Audience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now())}}
	for _, name := range []string{"valid", "expired", "issuer", "audience", "missing expiry", "missing tenant", "missing subject", "future nbf"} {
		t.Run(name, func(t *testing.T) {
			c := valid
			switch name {
			case "expired":
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			case "issuer":
				c.Issuer = "wrong"
			case "audience":
				c.Audience = jwt.ClaimStrings{"wrong"}
			case "missing expiry":
				c.ExpiresAt = nil
			case "missing tenant":
				c.Tenant = ""
			case "missing subject":
				c.Subject = ""
			case "future nbf":
				c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Verify(token)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected validation: %v", err)
			}
		})
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodNone, jwt.SigningMethodHS256} {
		var signingKey any = []byte(strings.Repeat("x", 32))
		if method == jwt.SigningMethodNone {
			signingKey = jwt.UnsafeAllowNoneSignatureType
		}
		token, _ := jwt.NewWithClaims(method, valid).SignedString(signingKey)
		if _, err := v.Verify(token); err == nil {
			t.Fatal("accepted unexpected algorithm")
		}
	}
}
func TestInternalContextBoundToServiceAndRequest(t *testing.T) {
	key := []byte(strings.Repeat("x", 32))
	token, err := SignInternal(key, "alice", "acme", "team-a", "billing", "GET", "/invoices/1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInternal(key, "billing", "GET", "/invoices/1", token); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][3]string{{"hr", "GET", "/invoices/1"}, {"billing", "DELETE", "/invoices/1"}, {"billing", "GET", "/invoices/2"}} {
		if _, err := VerifyInternal(key, args[0], args[1], args[2], token); err == nil {
			t.Fatal("context accepted for different request")
		}
	}
}
