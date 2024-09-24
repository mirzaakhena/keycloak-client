package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (kc *KeycloakClient) ListRealmRoles() ([]string, error) {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/roles", kc.KeycloakURL, kc.Realm)

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
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rolesData []map[string]interface{}
	if err := json.Unmarshal(body, &rolesData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var roleNames []string
	for _, role := range rolesData {
		if name, ok := role["name"].(string); ok {
			roleNames = append(roleNames, name)
		}
	}

	return roleNames, nil
}
