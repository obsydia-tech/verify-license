package licensing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Verbatim copies of the pre-2026-10 implementation (obsydia-connector-ce
// internal/license) used to prove compatibility in both directions.

type legacyLicense struct {
	TenantID       string   `json:"tenant_id"`
	Tier           string   `json:"tier"`
	NodeCount      int      `json:"node_count"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	Features       []string `json:"features"`
	Mode           string   `json:"mode,omitempty"`
	BridgeEndpoint string   `json:"bridge_endpoint,omitempty"`
}

type legacySignedLicense struct {
	legacyLicense
	Signature []byte `json:"signature"`
}

func legacyVerify(pub *ecdsa.PublicKey, sl *legacySignedLicense) error {
	lic := sl.legacyLicense
	data, err := json.Marshal(lic)
	if err != nil {
		return fmt.Errorf("marshal license: %w", err)
	}
	hash := sha256.Sum256(data)
	if len(sl.Signature) != 64 {
		return fmt.Errorf("invalid signature length: %d", len(sl.Signature))
	}
	r := new(big.Int).SetBytes(sl.Signature[:32])
	s := new(big.Int).SetBytes(sl.Signature[32:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func legacyIssue(key *ecdsa.PrivateKey, lic legacyLicense) (*legacySignedLicense, error) {
	lic.IssuedAt = time.Now().Unix()
	data, err := json.Marshal(lic)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	return &legacySignedLicense{legacyLicense: lic, Signature: sig}, nil
}
