package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func (kc *KeycloakClient) AssignRealmRolesToUser(userID string, roleNames []string) ([]string, []string, error) {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	var successfulRoles []string
	var failedRoles []string
	var rolesToAssign []map[string]interface{}

	for _, roleName := range roleNames {
		// Get the role details
		roleURL := fmt.Sprintf("%s/admin/realms/%s/roles/%s", kc.KeycloakURL, kc.Realm, roleName)
		roleReq, err := http.NewRequest("GET", roleURL, nil)
		if err != nil {
			failedRoles = append(failedRoles, roleName)
			continue
		}
		roleReq.Header.Set("Authorization", "Bearer "+adminToken)

		roleResp, err := kc.HTTPClient.Do(roleReq)
		if err != nil {
			failedRoles = append(failedRoles, roleName)
			continue
		}

		if roleResp.StatusCode != http.StatusOK {
			failedRoles = append(failedRoles, roleName)
			roleResp.Body.Close()
			continue
		}

		var roleDetails map[string]interface{}
		if err := json.NewDecoder(roleResp.Body).Decode(&roleDetails); err != nil {
			failedRoles = append(failedRoles, roleName)
			roleResp.Body.Close()
			continue
		}
		roleResp.Body.Close()

		rolesToAssign = append(rolesToAssign, roleDetails)
		successfulRoles = append(successfulRoles, roleName)
	}

	if len(rolesToAssign) == 0 {
		return successfulRoles, failedRoles, fmt.Errorf("no valid roles to assign")
	}

	// Assign roles to the user
	assignURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/role-mappings/realm", kc.KeycloakURL, kc.Realm, userID)

	roleJSON, err := json.Marshal(rolesToAssign)
	if err != nil {
		return successfulRoles, failedRoles, fmt.Errorf("failed to marshal role data: %w", err)
	}

	req, err := http.NewRequest("POST", assignURL, bytes.NewBuffer(roleJSON))
	if err != nil {
		return successfulRoles, failedRoles, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return successfulRoles, failedRoles, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return successfulRoles, failedRoles, fmt.Errorf("failed to assign roles. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully assigned roles %v to user '%s'.", successfulRoles, userID)
	return successfulRoles, failedRoles, nil
}
