package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func makeToken(serverID string, exp time.Time, key []byte) string {
	expUnix := exp.Unix()
	msg := fmt.Sprintf("%s.%d", serverID, expUnix)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	sig := fmt.Sprintf("%x", mac.Sum(nil))
	plain := fmt.Sprintf("%s.%d.%s", serverID, expUnix, sig)
	return base64.RawURLEncoding.EncodeToString([]byte(plain))
}

func TestValidateHostToken_OK(t *testing.T) {
	key := []byte("secret")
	now := time.Unix(1000, 0)
	tok := makeToken("srv", time.Unix(2000, 0), key)
	if err := ValidateHostToken(tok, key, "srv", now); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestValidateHostToken_BadServerID(t *testing.T) {
	key := []byte("secret")
	now := time.Unix(1000, 0)
	tok := makeToken("srv", time.Unix(2000, 0), key)
	if err := ValidateHostToken(tok, key, "other", now); err == nil {
		t.Fatalf("expected error")
	}
}

