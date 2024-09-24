package iam

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type KeycloakPublicKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type KeycloakPublicKeys struct {
	Keys []KeycloakPublicKey `json:"keys"`
}

type PublicKeyCache struct {
	KeycloakURL     string
	Realm           string
	PublicKey       *rsa.PublicKey
	LastFetched     time.Time
	RefreshInterval time.Duration
	mutex           sync.RWMutex
}

func NewPublicKeyCache(keycloakURL, realm string, refreshInterval time.Duration) *PublicKeyCache {
	return &PublicKeyCache{
		KeycloakURL:     keycloakURL,
		Realm:           realm,
		RefreshInterval: refreshInterval,
	}
}

func (pkc *PublicKeyCache) GetPublicKey() (*rsa.PublicKey, error) {
	pkc.mutex.RLock()
	if pkc.PublicKey != nil && time.Since(pkc.LastFetched) < pkc.RefreshInterval {
		defer pkc.mutex.RUnlock()
		return pkc.PublicKey, nil
	}
	pkc.mutex.RUnlock()

	return pkc.refreshPublicKey()
}

func (pkc *PublicKeyCache) refreshPublicKey() (*rsa.PublicKey, error) {
	pkc.mutex.Lock()
	defer pkc.mutex.Unlock()

	// Double-check if the key was refreshed while waiting for the lock
	if pkc.PublicKey != nil && time.Since(pkc.LastFetched) < pkc.RefreshInterval {
		return pkc.PublicKey, nil
	}

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", pkc.KeycloakURL, pkc.Realm)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Keycloak public key: %w", err)
	}
	defer resp.Body.Close()

	var keys KeycloakPublicKeys
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode Keycloak public keys: %w", err)
	}

	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("no public keys found")
	}

	// Use the first key (you might want to implement key rotation logic here)
	key := keys.Keys[0]

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key exponent: %w", err)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	pkc.PublicKey = publicKey
	pkc.LastFetched = time.Now()

	return pkc.PublicKey, nil
}

func (pkc *PublicKeyCache) InvalidateCache() {
	pkc.mutex.Lock()
	defer pkc.mutex.Unlock()
	pkc.PublicKey = nil
	pkc.LastFetched = time.Time{}
}
