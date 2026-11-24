// Package authjwt verifies the JWT authentik's proxy outpost forwards with
// every request it allows (X-Authentik-Jwt), so the console's notion of "who
// is signed in" can't be spoofed by a client, or by a pod calling Warden's
// Service directly, that simply sets a username header.
//
// Stdlib only: RS256 and ES256 against the provider's JWKS, with expiry,
// issuer and audience checks. The JWKS is public, fetched with one fixed GET
// and cached.
package authjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verifier checks tokens against one JWKS.
type Verifier struct {
	JWKSURL  string // http://authentik.default.svc:9000/application/o/<slug>/jwks/
	Issuer   string // optional: exact "iss"
	Audience string // required: must be in "aud" (the provider's client ID)
	HTTP     *http.Client
	Now      func() time.Time
	// CacheFor is how long a fetched key set is reused (default 10m). An
	// unknown key ID refetches at most once per minute.
	CacheFor time.Duration

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
	tried   time.Time
}

// Claims are the fields Warden uses.
type Claims struct {
	Username  string   `json:"preferred_username"`
	Email     string   `json:"email"`
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	Audience  audience `json:"aud"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// ErrInvalid wraps every rejection.
var ErrInvalid = errors.New("authjwt: invalid token")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	// No audience means any app signed by the same authentik key would pass:
	// refuse everything rather than accept tokens minted for other apps.
	if v.Audience == "" {
		return nil, invalid("no audience configured (WARDEN_AUTH_AUDIENCE)")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid("not a JWS compact token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJSON(parts[0], &hdr); err != nil {
		return nil, invalid("header: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("signature encoding")
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg { // the key's type decides, never "none" or HMAC
	case "RS256":
		pk, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(pk, crypto.SHA256, sum[:], sig) != nil {
			return nil, invalid("bad RS256 signature")
		}
	case "ES256":
		pk, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return nil, invalid("bad ES256 signature")
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pk, sum[:], r, s) {
			return nil, invalid("bad ES256 signature")
		}
	default:
		return nil, invalid("algorithm %q not accepted", hdr.Alg)
	}
	var c Claims
	if err := decodeJSON(parts[1], &c); err != nil {
		return nil, invalid("claims: %v", err)
	}
	now := v.now().Unix()
	const skew = 60
	if c.Expiry == 0 || now > c.Expiry+skew {
		return nil, invalid("expired")
	}
	if c.NotBefore != 0 && now+skew < c.NotBefore {
		return nil, invalid("not yet valid")
	}
	if v.Issuer != "" && c.Issuer != v.Issuer {
		return nil, invalid("issuer %q", c.Issuer)
	}
	ok := false
	for _, a := range c.Audience {
		ok = ok || a == v.Audience
	}
	if !ok {
		return nil, invalid("audience")
	}
	if c.Username == "" {
		c.Username = c.Subject
	}
	if c.Username == "" {
		return nil, invalid("no username")
	}
	return &c, nil
}

func decodeJSON(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// key returns the public key for kid, fetching the JWKS when it is stale or
// the kid is new (rate-limited, so bad tokens can't hammer authentik).
func (v *Verifier) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ttl := v.CacheFor
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	now := v.now()
	stale := v.keys == nil || now.Sub(v.fetched) > ttl
	_, known := v.keys[kid]
	if v.keys == nil || ((stale || !known) && now.Sub(v.tried) > time.Minute) {
		v.tried = now
		keys, err := v.fetch(ctx)
		if err != nil {
			if v.keys == nil {
				return nil, fmt.Errorf("authjwt: jwks: %w", err)
			}
		} else {
			v.keys, v.fetched = keys, now
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if kid == "" && len(v.keys) == 1 {
		for _, k := range v.keys {
			return k, nil
		}
	}
	return nil, invalid("unknown key id %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	hc := v.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Crv, N, E, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	b64 := func(s string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return new(big.Int).SetBytes(b)
	}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, e := b64(k.N), b64(k.E)
			if n == nil || e == nil || !e.IsInt64() || n.BitLen() < 2048 {
				continue
			}
			out[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
		case "EC":
			x, y := b64(k.X), b64(k.Y)
			if k.Crv != "P-256" || x == nil || y == nil {
				continue
			}
			pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
			if !pk.Curve.IsOnCurve(x, y) { //nolint:staticcheck // validating untrusted key material
				continue
			}
			out[k.Kid] = pk
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable signing keys")
	}
	return out, nil
}
