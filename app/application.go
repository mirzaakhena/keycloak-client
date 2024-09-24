package app

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	ctCore "warehouse/controller/core"
	ctIAM "warehouse/controller/iam"
	sv "warehouse/service/iam"
)

func Run() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	kc := sv.NewKeycloakClient(
		os.Getenv("KEYCLOAK_CLIENT_ID"),
		os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		os.Getenv("KEYCLOAK_URL"),
		os.Getenv("KEYCLOAK_REALM"),
	)

	http.HandleFunc("POST /register", ctIAM.RegisterHandler(kc))
	http.HandleFunc("POST /login", ctIAM.LoginHandler(kc))
	http.HandleFunc("GET /users", ctIAM.GetAllUsersHandler(kc))
	http.HandleFunc("GET /user/{id}", ctIAM.GetOneUserHandler(kc))
	http.HandleFunc("PUT /user/{id}", ctIAM.UpdateUserHandler(kc))
	http.HandleFunc("DELETE /user/{id}", ctIAM.DeleteUserHandler(kc))
	http.HandleFunc("POST /user/{id}/roles", ctIAM.AssignRolesToUserHandler(kc))
	http.HandleFunc("GET /roles", ctIAM.ListRealmRolesHandler(kc))

	http.HandleFunc("GET /bukapintuair", ctIAM.AuthMiddleware(kc, ctCore.DoSomething(kc), "admin"))

	port := 8081
	log.Printf("Server is running on http://localhost:%d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
