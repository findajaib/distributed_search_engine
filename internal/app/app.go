package app

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"

	"search-engine/internal/models"
	"search-engine/internal/services"
	"search-engine/internal/utils"
)

// responseWriter wraps http.ResponseWriter to track if we've written to it
type responseWriter struct {
	http.ResponseWriter
	written bool
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.written = true
	return rw.ResponseWriter.Write(b)
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.written = true
	rw.ResponseWriter.WriteHeader(code)
}

type App struct {
	db             *sql.DB
	userService    models.UserService
	searchService  models.SearchService
	contentService models.ContentService
	sessionService models.SessionService
	workerManager  models.WorkerManager
	templates      *template.Template
}

func NewApp(db *sql.DB) *App {
	userService := services.NewSQLUserService(db)
	searchService := services.NewSQLSearchService(db)
	sessionService := services.NewMemorySessionService(userService)
	registryAddr := os.Getenv("REGISTRY_ADDRESS")
	if registryAddr == "" {
		registryAddr = "localhost:50052"
	}
	workerManager := services.NewWorkerManager(registryAddr)
	workerManager.Start()
	contentService := services.NewSQLContentService(db, workerManager)
	templates := template.Must(template.ParseGlob("templates/*.html"))

	return &App{
		db:             db,
		userService:    userService,
		searchService:  searchService,
		contentService: contentService,
		sessionService: sessionService,
		workerManager:  workerManager,
		templates:      templates,
	}
}

// Getter methods
func (a *App) GetSessionService() models.SessionService {
	return a.sessionService
}

func (a *App) GetUserService() models.UserService {
	return a.userService
}

func (a *App) GetSearchService() models.SearchService {
	return a.searchService
}

func (a *App) GetContentService() models.ContentService {
	return a.contentService
}

func (a *App) GetWorkerManager() models.WorkerManager {
	return a.workerManager
}

func (a *App) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	rw := &responseWriter{ResponseWriter: w}
	if err := a.templates.ExecuteTemplate(rw, name, data); err != nil {
		if !rw.written {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			log.Printf("Template error after writing: %v", err)
		}
	}
}

func (a *App) RenderForbidden(w http.ResponseWriter, r *http.Request) {
	a.RenderTemplate(w, "forbidden.html", nil)
}

func (a *App) SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     utils.SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(utils.SessionDuration.Seconds()),
	})
}
