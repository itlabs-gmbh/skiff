package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// refreshMargin renews a cached token this long before it expires.
const refreshMargin = 5 * time.Minute

// placeholderClaims are copied from the real token into the placeholder: the
// identity az reads locally (tenant, object id, user), never the signature.
var placeholderClaims = []string{
	"aud", "iss", "iat", "nbf", "exp", "tid", "oid", "upn", "unique_name", "name", "idtyp", "appid",
}

type token struct {
	value   string
	expires time.Time
}

// tokens mints real tokens with the Mac's az CLI and caches them per resource.
type tokens struct {
	mu    sync.Mutex
	cache map[string]token
}

func (t *tokens) get(ctx context.Context, resource string) (token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.cache[resource]; ok && time.Until(c.expires) > refreshMargin {
		return c, nil
	}
	out, err := exec.CommandContext(ctx, "az", "account", "get-access-token",
		"--resource", resource, "--output", "json").Output()
	if err != nil {
		return token{}, fmt.Errorf("az get-access-token %s: %w", resource, err)
	}
	var parsed struct {
		AccessToken string `json:"accessToken"`
		ExpiresOn   int64  `json:"expires_on"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil || parsed.AccessToken == "" {
		return token{}, fmt.Errorf("az get-access-token %s: unexpected output", resource)
	}
	tok := token{value: parsed.AccessToken, expires: time.Unix(parsed.ExpiresOn, 0)}
	if t.cache == nil {
		t.cache = map[string]token{}
	}
	t.cache[resource] = tok
	return tok, nil
}

// placeholder builds a JWT that carries the real token's identity claims but
// no valid signature: az can read tenant and user from it, Azure rejects it.
func placeholder(real string) (string, error) {
	parts := strings.Split(real, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("token payload: %w", err)
	}
	kept := map[string]any{"skiff": "placeholder"}
	for _, k := range placeholderClaims {
		if v, ok := claims[k]; ok {
			kept[k] = v
		}
	}
	body, err := json.Marshal(kept)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	header := `{"alg":"RS256","typ":"JWT","kid":"skiff-placeholder"}`
	return enc([]byte(header)) + "." + enc(body) + "." + enc([]byte("skiff-placeholder-no-signature")), nil
}
