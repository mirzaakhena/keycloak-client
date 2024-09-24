package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (kc *KeycloakClient) GetAllUsers() ([]KeycloakUser, error) {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users", kc.KeycloakURL, kc.Realm)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get users: %s", string(body))
	}

	var users []KeycloakUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to parse users response: %w", err)
	}

	return users, nil
}
