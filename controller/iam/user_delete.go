package iam

import (
	"net/http"

	svc "warehouse/service/iam"
)

func DeleteUserHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
