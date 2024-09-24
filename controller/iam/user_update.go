package iam

import (
	"encoding/json"
	"net/http"

	svc "warehouse/service/iam"
)

type UpdateUserRequest struct {
	UserID    string `json:"userId"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

func UpdateUserHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
