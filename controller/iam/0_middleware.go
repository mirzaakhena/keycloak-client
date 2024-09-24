package iam

import (
	"fmt"
	"net/http"
	"strings"

	svc "warehouse/service/iam"

	"github.com/golang-jwt/jwt/v4"
)

func AuthMiddleware(kc *svc.KeycloakClient, next http.HandlerFunc, roles ...string) http.HandlerFunc {
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
