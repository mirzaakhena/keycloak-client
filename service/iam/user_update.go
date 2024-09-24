package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func (kc *KeycloakClient) UpdateUser(userId, firstName, lastName, email string) error {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return fmt.Errorf("failed to get admin token: %w", err)
	}

	updateData := map[string]string{
		"firstName": firstName,
		"lastName":  lastName,
		"email":     email,
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal update data: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users/%s", kc.KeycloakURL, kc.Realm, userId)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update user: %s", string(body))
	}

	return nil
}
