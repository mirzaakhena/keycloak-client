package iam

import (
	"encoding/json"
	"fmt"
	"net/http"

	svc "warehouse/service/iam"
)

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

func GetOneUserHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
