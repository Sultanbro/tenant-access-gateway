package auth

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Identity struct {
	Subject string
	Tenant  string
}
type Claims struct {
	Tenant string `json:"tenant"`
	jwt.RegisteredClaims
}
type Verifier struct {
	PublicKey *rsa.PublicKey
	Issuer    string
	Audience  string
}

func (v Verifier) Verify(token string) (Identity, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) { return v.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(5*time.Second))
	if err != nil || !parsed.Valid || claims.Subject == "" || claims.Tenant == "" {
		return Identity{}, errors.New("invalid bearer token")
	}
	return Identity{claims.Subject, claims.Tenant}, nil
}

// Internal claims are signed separately and bound to exactly one upstream request.
type InternalClaims struct {
	Tenant string `json:"tenant"`
	Scope  string `json:"scope"`
	Method string `json:"method"`
	Path   string `json:"path"`
	jwt.RegisteredClaims
}

func SignInternal(key []byte, subject, tenant, scope, service, method, path string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, InternalClaims{Tenant: tenant, Scope: scope, Method: method, Path: path, RegisteredClaims: jwt.RegisteredClaims{Subject: subject, Issuer: "tenant-access-gateway", Audience: jwt.ClaimStrings{service}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second))}}).SignedString(key)
}
func VerifyInternal(key []byte, service, method, path, token string) (InternalClaims, error) {
	c := InternalClaims{}
	parsed, err := jwt.ParseWithClaims(token, &c, func(_ *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("tenant-access-gateway"), jwt.WithAudience(service), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid || c.Subject == "" || c.Tenant == "" || c.Scope == "" || c.Method != method || c.Path != path {
		return c, errors.New("invalid internal context")
	}
	return c, nil
}
