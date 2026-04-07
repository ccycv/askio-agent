package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrUnauthorized = errors.New("unauthorized")

// ValidateHostToken validates a per-host gateway token.
//
// Token format (v1): base64url("<server_id>.<exp_unix>.<hmac_hex>")
// where hmac = HMAC_SHA256(key, "<server_id>.<exp_unix>") as hex.
//
// This keeps the gateway stateless (no per-host DB required for v1).
func ValidateHostToken(token string, key []byte, expectedServerID string, now time.Time) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrUnauthorized
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrUnauthorized
	}
	parts := strings.Split(string(b), ".")
	if len(parts) != 3 {
		return ErrUnauthorized
	}
	sid := parts[0]
	expStr := parts[1]
	sigHex := parts[2]
	if expectedServerID != "" && sid != expectedServerID {
		return ErrUnauthorized
	}
	expUnix, err := parseInt64(expStr)
	if err != nil {
		return ErrUnauthorized
	}
	if expUnix > 0 && !now.Before(time.Unix(expUnix, 0)) {
		return fmt.Errorf("%w: token expired", ErrUnauthorized)
	}

	msg := sid + "." + expStr
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sigHex)) {
		return ErrUnauthorized
	}
	return nil
}

func parseInt64(s string) (int64, error) {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int64(r-'0')
	}
	return n, nil
}

