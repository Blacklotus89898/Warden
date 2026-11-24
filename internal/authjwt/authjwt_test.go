package authjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _  = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now       = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwks(t *testing.T) (*httptest.Server, *int32) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method != http.MethodGet {
			t.Errorf("non-GET %s", r.Method)
		}
		pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "rsa1", "use": "sig", "n": b64(rsaKey.N.Bytes()), "e": b64(big.NewInt(int64(rsaKey.E)).Bytes())},
			{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64(pad(ecKey.X.Bytes())), "y": b64(pad(ecKey.Y.Bytes()))},
		}})
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

func sign(t *testing.T, alg, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sum[:])
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, ecKey, sum[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	default:
		sig = []byte("x")
	}
	return in + "." + b64(sig)
}

func good() map[string]any {
	return map[string]any{"preferred_username": "steve", "iss": "https://auth.lab.home/application/o/warden-console/",
		"aud": "warden-client", "exp": now.Add(5 * time.Minute).Unix()}
}

func with(k string, v any) map[string]any { c := good(); c[k] = v; return c }

func TestVerify(t *testing.T) {
	ts, _ := jwks(t)
	v := &Verifier{JWKSURL: ts.URL, Issuer: "https://auth.lab.home/application/o/warden-console/", Audience: "warden-client",
		Now: func() time.Time { return now }}
	ctx := context.Background()

	for _, alg := range []string{"RS256", "ES256"} {
		kid := map[string]string{"RS256": "rsa1", "ES256": "ec1"}[alg]
		c, err := v.Verify(ctx, sign(t, alg, kid, good()))
		if err != nil || c.Username != "steve" {
			t.Errorf("%s: %v %+v", alg, err, c)
		}
	}
	tampered := sign(t, "RS256", "rsa1", good())
	parts := strings.Split(tampered, ".")
	evil, _ := json.Marshal(with("preferred_username", "admin"))
	tampered = parts[0] + "." + b64(evil) + "." + parts[2]

	bad := map[string]string{
		"expired":        sign(t, "RS256", "rsa1", with("exp", now.Add(-5*time.Minute).Unix())),
		"no exp":         sign(t, "RS256", "rsa1", with("exp", 0)),
		"future nbf":     sign(t, "RS256", "rsa1", with("nbf", now.Add(10*time.Minute).Unix())),
		"wrong issuer":   sign(t, "RS256", "rsa1", with("iss", "https://evil/")),
		"wrong audience": sign(t, "RS256", "rsa1", with("aud", []string{"other"})),
		"alg none":       sign(t, "none", "rsa1", good()),
		"HS256":          sign(t, "HS256", "rsa1", good()),
		"alg/key swap":   sign(t, "ES256", "rsa1", good()),
		"unknown kid":    sign(t, "RS256", "nope", good()),
		"tampered":       tampered,
		"garbage":        "a.b",
		"no username":    sign(t, "RS256", "rsa1", map[string]any{"exp": now.Add(time.Minute).Unix(), "aud": "warden-client", "iss": "https://auth.lab.home/application/o/warden-console/"}),
	}
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	c, err := v.Verify(ctx, sign(t, "RS256", "rsa1", with("aud", []string{"x", "warden-client"})))
	if err != nil || c.Username != "steve" {
		t.Errorf("aud as a list: %v", err)
	}
}

func TestJWKSCachedAndRateLimited(t *testing.T) {
	ts, hits := jwks(t)
	clk := now
	v := &Verifier{JWKSURL: ts.URL, Audience: "warden-client", Now: func() time.Time { return clk }}
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(context.Background(), sign(t, "RS256", "rsa1", good()))
		_, _ = v.Verify(context.Background(), sign(t, "RS256", "unknown", good()))
	}
	if *hits != 1 {
		t.Errorf("JWKS fetched %d times; unknown kids must not refetch within a minute", *hits)
	}
	clk = clk.Add(11 * time.Minute)
	_, _ = v.Verify(context.Background(), sign(t, "RS256", "rsa1", good()))
	if *hits != 2 {
		t.Errorf("stale cache must refetch: %d", *hits)
	}
}

func TestJWKSDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer ts.Close()
	v := &Verifier{JWKSURL: ts.URL, Audience: "warden-client", Now: func() time.Time { return now }}
	if _, err := v.Verify(context.Background(), sign(t, "RS256", "rsa1", good())); err == nil {
		t.Fatal("no keys must mean no user")
	}
}

func TestNoAudienceRefusesEverything(t *testing.T) {
	ts, hits := jwks(t)
	v := &Verifier{JWKSURL: ts.URL, Now: func() time.Time { return now }}
	if _, err := v.Verify(context.Background(), sign(t, "RS256", "rsa1", good())); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a verifier without an audience must refuse, got %v", err)
	}
	if *hits != 0 {
		t.Error("and must not even fetch keys")
	}
}
