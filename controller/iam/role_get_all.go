package iam

import (
	"encoding/json"
	"fmt"
	"net/http"

	svc "warehouse/service/iam"
)

func ListRealmRolesHandler(kc *svc.KeycloakClient) http.HandlerFunc {
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
