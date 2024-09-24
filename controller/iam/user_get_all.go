package iam

import (
	"encoding/json"
	"net/http"

	svc "warehouse/service/iam"
)

func GetAllUsersHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
