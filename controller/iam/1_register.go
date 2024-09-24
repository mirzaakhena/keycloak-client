package iam

import (
	"encoding/json"
	"net/http"

	svc "warehouse/service/iam"
)

type UserRegistrationRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

func RegisterHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
