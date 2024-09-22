package iam3

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func Run() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	kc := NewKeycloakClient(
		os.Getenv("KEYCLOAK_CLIENT_ID"),
		os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		os.Getenv("KEYCLOAK_URL"),
		os.Getenv("KEYCLOAK_REALM"),
	)

	http.HandleFunc("POST /register", RegisterHandler(kc))
	http.HandleFunc("POST /login", LoginHandler(kc))
	http.HandleFunc("GET /users", GetAllUsersHandler(kc))
	http.HandleFunc("GET /user/{id}", GetOneUserHandler(kc))
	http.HandleFunc("PUT /user/{id}", UpdateUserHandler(kc))
	http.HandleFunc("DELETE /user/{id}", DeleteUserHandler(kc))
	http.HandleFunc("POST /user/{id}/roles", AssignRolesToUserHandler(kc))
	http.HandleFunc("GET /roles", ListRealmRolesHandler(kc))

	http.HandleFunc("GET /bukapintuair", AuthMiddleware(kc, BukaPintuAir(kc), "admin"))

	// http.HandleFunc("/admin", authMiddleware(adminOnlyHandler, "admin"))
	// http.HandleFunc("/editor", authMiddleware(editorOnlyHandler, "editor"))

	port := 8081
	log.Printf("Server is running on http://localhost:%d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
