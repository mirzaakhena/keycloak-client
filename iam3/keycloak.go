package iam3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type KeycloakClient struct {
	ClientID       string
	ClientSecret   string
	KeycloakURL    string
	Realm          string
	HTTPClient     *http.Client
	PublicKeyCache *PublicKeyCache
}

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

func (kc *KeycloakClient) ValidateToken(tokenString string) (*jwt.Token, error) {
	publicKey, err := kc.PublicKeyCache.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		// If there's an error, invalidate the cache in case it's due to a key rotation
		kc.PublicKeyCache.InvalidateCache()
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Validate expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return nil, fmt.Errorf("token expired")
		}
		// Validate issuer
		expectedIssuer := fmt.Sprintf("%s/realms/%s", kc.KeycloakURL, kc.Realm)
		if claims["iss"] != expectedIssuer {
			return nil, fmt.Errorf("invalid issuer")
		}
		// Add more custom validations as needed
	} else {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
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

func (kc *KeycloakClient) GetUserDetails(userID string) (map[string]interface{}, error) {
	adminToken, err := kc.getAdminToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users/%s", kc.KeycloakURL, kc.Realm, userID)

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
		return nil, fmt.Errorf("failed to get user details. Status: %d, Body: %s", resp.StatusCode, string(body))
	}

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user details: %w", err)
	}

	return user, nil
}

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
