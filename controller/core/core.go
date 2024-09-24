package core

import (
	"net/http"
	sv "warehouse/service/iam"
)

func DoSomething(kc *sv.KeycloakClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}
