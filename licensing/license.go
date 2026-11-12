// Package licensing is the single implementation of the Obsydia licence
// format (ADR-004). The signed JSON is byte-compatible with every licence
// issued since 2026: new information travels as namespaced entries in
// Features, so binaries built before this package keep verifying licences
// issued by it.
package licensing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// License is the signed part of a licence. Field order, names and tags must
// never change: the signature covers json.Marshal of this struct.
type License struct {
	TenantID       string   `json:"tenant_id"`
	Tier           string   `json:"tier"`
	NodeCount      int      `json:"node_count"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	Features       []string `json:"features"`
	Mode           string   `json:"mode,omitempty"`
	BridgeEndpoint string   `json:"bridge_endpoint,omitempty"`
}

// SignedLicense is the licence file: the licence plus a 64-byte P-256
// signature (R and S, 32 bytes each) over SHA-256 of the marshalled License.
type SignedLicense struct {
	License
	Signature []byte `json:"signature"`
}

const (
	ModeSelfhosted = "selfhosted"
	ModeHosted     = "hosted"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrMalformed        = errors.New("malformed licence")
)

// Issue signs lic with key. IssuedAt is set to now.
func Issue(key *ecdsa.PrivateKey, lic License, now time.Time) (*SignedLicense, error) {
	lic.IssuedAt = now.Unix()
	data, err := json.Marshal(lic)
	if err != nil {
		return nil, fmt.Errorf("marshal licence: %w", err)
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign licence: %w", err)
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	return &SignedLicense{License: lic, Signature: sig}, nil
}

// VerifySignature checks the signature only. Expiry is a state, not an
// error: use StateAt.
func VerifySignature(pub *ecdsa.PublicKey, sl *SignedLicense) error {
	if sl == nil || pub == nil {
		return ErrMalformed
	}
	if len(sl.Signature) != 64 {
		return fmt.Errorf("%w: signature length %d", ErrInvalidSignature, len(sl.Signature))
	}
	data, err := json.Marshal(sl.License)
	if err != nil {
		return fmt.Errorf("marshal licence: %w", err)
	}
	hash := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sl.Signature[:32])
	s := new(big.Int).SetBytes(sl.Signature[32:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// Parse reads a licence file.
func Parse(data []byte) (*SignedLicense, error) {
	var sl SignedLicense
	if err := json.Unmarshal(data, &sl); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if sl.TenantID == "" || sl.Tier == "" || sl.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: missing tenant, tier or expiry", ErrMalformed)
	}
	return &sl, nil
}

// Load parses, verifies the signature and returns the state at now. A bad
// signature returns StateInvalid and an error.
func Load(pub *ecdsa.PublicKey, data []byte, now time.Time) (*SignedLicense, State, error) {
	sl, err := Parse(data)
	if err != nil {
		return nil, StateInvalid, err
	}
	if err := VerifySignature(pub, sl); err != nil {
		return sl, StateInvalid, err
	}
	return sl, sl.StateAt(now), nil
}

// ---- keys ----

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MarshalPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func MarshalPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ParsePrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func ParsePublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return key, nil
}
