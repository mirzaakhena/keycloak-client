package iam

import (
	"encoding/json"
	"net/http"

	svc "warehouse/service/iam"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
