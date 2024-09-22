package iam3

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type UserRegistrationRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type UpdateUserRequest struct {
	UserID    string `json:"userId"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

type UserDetails struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	Enabled       bool     `json:"enabled"`
	EmailVerified bool     `json:"emailVerified"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	Email         string   `json:"email"`
	Roles         []string `json:"roles"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func AuthMiddleware(kc *KeycloakClient, next http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token, err := kc.ValidateToken(bearerToken[1])
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		if err := validateRoles(claims, roles); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// Token is valid and has required roles, proceed with the request
		next.ServeHTTP(w, r)
	}
}

func validateRoles(claims jwt.MapClaims, requiredRoles []string) error {
	if len(requiredRoles) == 0 {
		return nil // No roles required, so validation passes
	}

	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("realm_access claim not found or invalid")
	}

	userRoles, ok := realmAccess["roles"].([]interface{})
	if !ok {
		return fmt.Errorf("roles claim not found or invalid")
	}

	userRolesMap := make(map[string]bool)
	for _, role := range userRoles {
		if roleStr, ok := role.(string); ok {
			userRolesMap[roleStr] = true
		}
	}

	for _, requiredRole := range requiredRoles {
		if !userRolesMap[requiredRole] {
			return fmt.Errorf("missing required role: %s", requiredRole)
		}
	}

	return nil
}

func RegisterHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var userData UserRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		err := kc.RegisterUser(userData.Username, userData.Password, userData.Email, userData.FirstName, userData.LastName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User registered successfully. Please check your email to verify your account."))
	}
}

func LoginHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var loginData LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		tokenResponse, err := kc.Login(loginData.Username, loginData.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}
}

func GetAllUsersHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		users, err := kc.GetAllUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func UpdateUserHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userId := r.PathValue("id")
		if userId == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		var updateData UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		err := kc.UpdateUser(userId, updateData.FirstName, updateData.LastName, updateData.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User updated successfully"))
	}
}

func DeleteUserHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userId := r.PathValue("id")
		if userId == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		err := kc.DeleteUser(userId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User deleted successfully"))
	}
}

func AssignRolesToUserHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userId := r.PathValue("id")
		if userId == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		var requestBody struct {
			Roles []string `json:"roles"`
		}

		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(requestBody.Roles) == 0 {
			http.Error(w, "At least one role is required", http.StatusBadRequest)
			return
		}

		successfulRoles, failedRoles, err := kc.AssignRealmRolesToUser(userId, requestBody.Roles)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to assign roles: %v", err), http.StatusInternalServerError)
			return
		}

		response := struct {
			SuccessfulRoles []string `json:"successfulRoles"`
			FailedRoles     []string `json:"failedRoles"`
		}{
			SuccessfulRoles: successfulRoles,
			FailedRoles:     failedRoles,
		}

		w.Header().Set("Content-Type", "application/json")
		if len(failedRoles) > 0 {
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(response)
	}
}

func ListRealmRolesHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		roles, err := kc.ListRealmRoles()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list realm roles: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := struct {
			Roles []string `json:"roles"`
		}{
			Roles: roles,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}

	}
}

func GetOneUserHandler(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userID := r.PathValue("id")
		if userID == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		user, err := kc.GetUserDetails(userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get user details: %v", err), http.StatusInternalServerError)
			return
		}

		roles, err := kc.GetUserRoles(userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get user roles: %v", err), http.StatusInternalServerError)
			return
		}

		userDetails := UserDetails{
			ID:            user["id"].(string),
			Username:      user["username"].(string),
			Enabled:       user["enabled"].(bool),
			EmailVerified: user["emailVerified"].(bool),
			FirstName:     user["firstName"].(string),
			LastName:      user["lastName"].(string),
			Email:         user["email"].(string),
			Roles:         roles,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userDetails)
	}
}


func BukaPintuAir(kc *KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}