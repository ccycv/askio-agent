package migration

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	signingPrivateFile    = "task-signing-ed25519.pem"
	encryptionPrivateFile = "secret-encryption-x25519.pem"
	hostIdentityKeyFile   = "host-identity-hmac.key"
)

type Identity struct {
	SigningKeyID           string
	SigningPrivateKey      ed25519.PrivateKey
	SigningPublicKeyPEM    string
	EncryptionKeyID        string
	EncryptionPrivateKey   *ecdh.PrivateKey
	EncryptionPublicKeyPEM string
	HostIdentityDigest     string
}

type SecurityProfile struct {
	DaemonIsRoot         bool     `json:"daemonIsRoot"`
	DaemonUser           string   `json:"daemonUser"`
	ShellMode            bool     `json:"shellMode"`
	TypedBroker          bool     `json:"typedBroker"`
	ProtectSystem        string   `json:"protectSystem"`
	ProtectHome          bool     `json:"protectHome"`
	GenericHelperEnabled bool     `json:"genericHelperEnabled"`
	PackageVersion       string   `json:"packageVersion"`
	UnitDigest           string   `json:"unitDigest"`
	BrokerDigest         string   `json:"brokerDigest"`
	AllowedRoots         []string `json:"allowedRoots"`
}

type Enrollment struct {
	SchemaVersion          string          `json:"schema_version"`
	SigningKeyID           string          `json:"signing_key_id"`
	SigningPublicKeyPEM    string          `json:"signing_public_key_pem"`
	EncryptionKeyID        string          `json:"encryption_key_id"`
	EncryptionPublicKeyPEM string          `json:"encryption_public_key_pem"`
	Nonce                  string          `json:"nonce"`
	ProofSignature         string          `json:"proof_signature"`
	HostIdentityDigest     string          `json:"host_identity_digest"`
	SecurityProfile        SecurityProfile `json:"security_profile"`
	AttestationDigest      string          `json:"attestation_digest"`
	Capabilities           []string        `json:"capabilities"`
}

func ensureDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("key directory must be absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func keyID(publicDER []byte) string {
	digest := sha256.Sum256(publicDER)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func loadOrCreateSigningKey(dir string) (ed25519.PrivateKey, string, string, error) {
	path := filepath.Join(dir, signingPrivateFile)
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, "", "", errors.New("invalid signing key PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", "", err
		}
		privateKey, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, "", "", errors.New("stored signing key is not Ed25519")
		}
		publicDER, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
		return privateKey, keyID(publicDER), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
	} else if !os.IsNotExist(err) {
		return nil, "", "", err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", "", err
	}
	if err := writeExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})); err != nil {
		return nil, "", "", err
	}
	publicDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	return privateKey, keyID(publicDER), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
}

func loadOrCreateEncryptionKey(dir string) (*ecdh.PrivateKey, string, string, error) {
	path := filepath.Join(dir, encryptionPrivateFile)
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, "", "", errors.New("invalid encryption key PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", "", err
		}
		privateKey, ok := parsed.(*ecdh.PrivateKey)
		if !ok || privateKey.Curve() != ecdh.X25519() {
			return nil, "", "", errors.New("stored encryption key is not X25519")
		}
		publicDER, _ := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
		return privateKey, keyID(publicDER), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
	} else if !os.IsNotExist(err) {
		return nil, "", "", err
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, "", "", err
	}
	if err := writeExclusive(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})); err != nil {
		return nil, "", "", err
	}
	publicDER, _ := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	return privateKey, keyID(publicDER), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})), nil
}

func loadOrCreateHostKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, hostIdentityKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, errors.New("stored host identity key has invalid length")
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeExclusive(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

func readIdentityFact(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func hostIdentityDigest(key []byte) (string, error) {
	facts := []string{}
	if value := readIdentityFact("/etc/machine-id"); value != "" {
		facts = append(facts, "machine-id="+value)
	}
	if value := readIdentityFact("/sys/class/dmi/id/product_uuid"); value != "" {
		facts = append(facts, "dmi-product-uuid="+strings.ToLower(value))
	}
	if value, err := os.Hostname(); err == nil && value != "" {
		facts = append(facts, "hostname="+strings.ToLower(value))
	}
	if len(facts) == 0 {
		return "", errors.New("no stable local host identity facts are available")
	}
	sort.Strings(facts)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.Join(facts, "\n")))
	return "sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func LoadOrCreateIdentity(dir string) (*Identity, error) {
	if err := ensureDirectory(dir); err != nil {
		return nil, err
	}
	signingPrivate, signingID, signingPublic, err := loadOrCreateSigningKey(dir)
	if err != nil {
		return nil, err
	}
	encryptionPrivate, encryptionID, encryptionPublic, err := loadOrCreateEncryptionKey(dir)
	if err != nil {
		return nil, err
	}
	hostKey, err := loadOrCreateHostKey(dir)
	if err != nil {
		return nil, err
	}
	hostDigest, err := hostIdentityDigest(hostKey)
	for index := range hostKey {
		hostKey[index] = 0
	}
	if err != nil {
		return nil, err
	}
	return &Identity{
		SigningKeyID: signingID, SigningPrivateKey: signingPrivate, SigningPublicKeyPEM: signingPublic,
		EncryptionKeyID: encryptionID, EncryptionPrivateKey: encryptionPrivate, EncryptionPublicKeyPEM: encryptionPublic,
		HostIdentityDigest: hostDigest,
	}, nil
}

func BuildEnrollment(identity *Identity, registrationToken string, profile SecurityProfile, capabilities []string) (Enrollment, error) {
	if identity == nil || len(identity.SigningPrivateKey) != ed25519.PrivateKeySize {
		return Enrollment{}, errors.New("migration signing identity is unavailable")
	}
	capabilities = append([]string{}, capabilities...)
	sort.Strings(capabilities)
	attestation := map[string]any{
		"schema_version":            "operations.migration.enrollment.v1",
		"signing_key_id":            identity.SigningKeyID,
		"signing_public_key_pem":    identity.SigningPublicKeyPEM,
		"encryption_key_id":         identity.EncryptionKeyID,
		"encryption_public_key_pem": identity.EncryptionPublicKeyPEM,
		"host_identity_digest":      identity.HostIdentityDigest,
		"security_profile":          profile,
		"capabilities":              capabilities,
	}
	attestationDigest, err := Digest(attestation)
	if err != nil {
		return Enrollment{}, err
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return Enrollment{}, err
	}
	tokenDigest := sha256.Sum256([]byte(registrationToken))
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	proof := map[string]any{}
	for key, value := range attestation {
		proof[key] = value
	}
	proof["attestation_digest"] = attestationDigest
	proof["nonce"] = nonce
	proof["registration_token_digest"] = hex.EncodeToString(tokenDigest[:])
	canonical, err := CanonicalJSON(proof)
	if err != nil {
		return Enrollment{}, err
	}
	signature := ed25519.Sign(identity.SigningPrivateKey, canonical)
	return Enrollment{
		SchemaVersion:          "operations.migration.enrollment.v1",
		SigningKeyID:           identity.SigningKeyID,
		SigningPublicKeyPEM:    identity.SigningPublicKeyPEM,
		EncryptionKeyID:        identity.EncryptionKeyID,
		EncryptionPublicKeyPEM: identity.EncryptionPublicKeyPEM,
		Nonce:                  nonce,
		ProofSignature:         base64.RawURLEncoding.EncodeToString(signature),
		HostIdentityDigest:     identity.HostIdentityDigest,
		SecurityProfile:        profile,
		AttestationDigest:      attestationDigest,
		Capabilities:           capabilities,
	}, nil
}
