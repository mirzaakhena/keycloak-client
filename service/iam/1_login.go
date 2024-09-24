package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func (kc *KeycloakClient) Login(username, password string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", kc.ClientID)
	data.Set("client_secret", kc.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kc.KeycloakURL, kc.Realm)
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed: %s", string(body))
	}

	var tokenResponse TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}
