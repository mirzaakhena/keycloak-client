package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type KeycloakUser struct {
	ID              string       `json:"id"`
	Username        string       `json:"username"`
	Enabled         bool         `json:"enabled"`
	EmailVerified   bool         `json:"emailVerified"`
	FirstName       string       `json:"firstName"`
	LastName        string       `json:"lastName"`
	Email           string       `json:"email"`
	Credentials     []Credential `json:"credentials,omitempty"`
	RequiredActions []string     `json:"requiredActions,omitempty"`
}

type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

func (kc *KeycloakClient) RegisterUser(username, password, email, firstName, lastName string) error {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return fmt.Errorf("failed to get admin token: %w", err)
	}

	user := KeycloakUser{
		Username:      username,
		Enabled:       true,
		EmailVerified: false, // Set this to false
		FirstName:     firstName,
		LastName:      lastName,
		Email:         email,
		Credentials: []Credential{
			{
				Type:      "password",
				Value:     password,
				Temporary: false,
			},
		},
		RequiredActions: []string{"VERIFY_EMAIL"}, // Add this line
	}

	userJSON, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users", kc.KeycloakURL, kc.Realm)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(userJSON))
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

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create user: %s", string(body))
	}

	// Get the user ID from the response headers
	userIdUrl := resp.Header.Get("Location")
	if userIdUrl == "" {
		return fmt.Errorf("user ID not found in response")
	}

	// Extract user ID from the URL
	userId := userIdUrl[strings.LastIndex(userIdUrl, "/")+1:]

	// Send verification email
	err = kc.sendVerificationEmail(userId)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

func (kc *KeycloakClient) sendVerificationEmail(userId string) error {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/send-verify-email", kc.KeycloakURL, kc.Realm, userId)

	fmt.Printf("url send verify email: %s\n", url)

	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to send verification email. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Verification email sent successfully. Status: %d, Body: %s\n", resp.StatusCode, string(body))

	return nil
}
