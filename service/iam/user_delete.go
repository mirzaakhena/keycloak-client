package iam

import (
	"fmt"
	"io"
	"net/http"
)

func (kc *KeycloakClient) DeleteUser(userId string) error {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users/%s", kc.KeycloakURL, kc.Realm, userId)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete user: %s", string(body))
	}

	return nil
}
