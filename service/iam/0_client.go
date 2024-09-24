package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type KeycloakClient struct {
	ClientID       string
	ClientSecret   string
	KeycloakURL    string
	Realm          string
	HTTPClient     *http.Client
	PublicKeyCache *PublicKeyCache
}

func NewKeycloakClient(clientID, clientSecret, keycloakURL, realm string) *KeycloakClient {
	return &KeycloakClient{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		KeycloakURL:    keycloakURL,
		Realm:          realm,
		HTTPClient:     &http.Client{Timeout: 10 * time.Second},
		PublicKeyCache: NewPublicKeyCache(keycloakURL, realm, 1*time.Hour),
	}
}

func (kc *KeycloakClient) getAdminToken() (string, error) {
	data := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", kc.ClientID, kc.ClientSecret)
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kc.KeycloakURL, kc.Realm)

	resp, err := kc.HTTPClient.Post(url, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse admin token response: %w", err)
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse admin token")
	}

	return token, nil
}
