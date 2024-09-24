package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (kc *KeycloakClient) GetUserRoles(userID string) ([]string, error) {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/role-mappings/realm", kc.KeycloakURL, kc.Realm, userID)

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
		return nil, fmt.Errorf("failed to get user roles. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	var roles []struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	return roleNames, nil
}
