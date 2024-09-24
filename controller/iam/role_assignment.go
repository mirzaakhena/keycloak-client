package iam

import (
	"encoding/json"
	"fmt"
	"net/http"

	svc "warehouse/service/iam"
)

func AssignRolesToUserHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
