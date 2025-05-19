package main

import (
	"log"
	"net/http"
	"os"

	"search-engine/internal/app"
	"search-engine/internal/database"
	"search-engine/internal/handlers"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	db, err := database.InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	app := app.NewApp(db)
	defer app.GetWorkerManager().Close()

	// Register all routes
	handlers.SetupRoutes(app)

	mainPort := os.Getenv("MAIN_PORT")
	if mainPort == "" {
		mainPort = "8080"
	}
	log.Printf("Server starting on :%s...", mainPort)
	log.Fatal(http.ListenAndServe(":"+mainPort, nil))
}
