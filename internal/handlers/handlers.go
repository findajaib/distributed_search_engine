package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"search-engine/internal/app"
	"search-engine/internal/models"
	"search-engine/internal/services"
)

const (
	sessionCookieName = "session_id"
	sessionDuration   = 24 * time.Hour
)

// Handlers
func HandleHome(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, _ := app.GetSessionService().GetUserFromRequest(r)
	app.RenderTemplate(w, "index.html", struct {
		User *models.User
	}{
		User: user,
	})
}

func HandleSearch(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, _ := app.GetSessionService().GetUserFromRequest(r)
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	results, err := app.GetSearchService().Search(query)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	if user != nil {
		if err := app.GetSearchService().SaveSearchHistory(user.ID, query); err != nil {
			log.Printf("Failed to save search history: %v", err)
		}
	}

	app.RenderTemplate(w, "results.html", struct {
		Query   string
		Results []models.SearchResult
		User    *models.User
	}{
		Query:   query,
		Results: results,
		User:    user,
	})
}

func HandleAPISearch(app *app.App, w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	results, err := app.GetSearchService().Search(query)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func HandleRegister(app *app.App, w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := app.GetUserService().Register(username, password, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		sessionID := app.GetSessionService().CreateSession(user.ID)
		app.SetSessionCookie(w, sessionID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	app.RenderTemplate(w, "register.html", nil)
}

func HandleLogin(app *app.App, w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := app.GetUserService().Login(username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		sessionID := app.GetSessionService().CreateSession(user.ID)
		app.SetSessionCookie(w, sessionID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	app.RenderTemplate(w, "login.html", nil)
}

func HandleLogout(app *app.App, w http.ResponseWriter, r *http.Request) {
	app.GetSessionService().DeleteSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func HandleHistory(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	history, err := app.GetSearchService().GetSearchHistory(user.ID)
	if err != nil {
		http.Error(w, "Failed to get history", http.StatusInternalServerError)
		return
	}

	app.RenderTemplate(w, "history.html", struct {
		User    *models.User
		History []models.History
	}{
		User:    user,
		History: history,
	})
}

func HandleAPIHistory(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	history, err := app.GetSearchService().GetSearchHistory(user.ID)
	if err != nil {
		http.Error(w, "Failed to get history", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func HandleAdminScrape(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	var scrapeMsg string
	if r.Method == "POST" {
		mode := r.FormValue("mode")
		url := r.FormValue("url")

		if url != "" {
			if mode == "scrape" {
				title, body, err := app.GetContentService().ScrapeReadable(url)
				if err != nil {
					scrapeMsg = "Failed to scrape: " + err.Error()
				} else {
					if err := app.GetContentService().AddContent(title, body, url); err != nil {
						scrapeMsg = "Failed to save content: " + err.Error()
					} else {
						scrapeMsg = "Scraping and saving successful!"
					}
				}
			}
		}
	}

	contents, err := app.GetContentService().GetRecentContent(10)
	if err != nil {
		http.Error(w, "Failed to get recent content", http.StatusInternalServerError)
		return
	}

	app.RenderTemplate(w, "admin_scrape.html", struct {
		User     *models.User
		Msg      string
		Contents []models.ScrapedContent
	}{
		User:     user,
		Msg:      scrapeMsg,
		Contents: contents,
	})
}

func HandleRegisterAdmin(app *app.App, w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := app.GetUserService().Register(username, password, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		sessionID := app.GetSessionService().CreateSession(user.ID)
		app.SetSessionCookie(w, sessionID)
		http.Redirect(w, r, "/admin/scrape", http.StatusSeeOther)
		return
	}

	app.RenderTemplate(w, "register_admin.html", nil)
}

func HandleAdminScrapeSingle(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	title, body, err := app.GetContentService().ScrapeReadable(url)
	if err != nil {
		http.Error(w, "Failed to scrape: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := app.GetContentService().AddContent(title, body, url); err != nil {
		http.Error(w, "Failed to save content: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func HandleAdminScrapeCrawl(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	url := r.FormValue("url")
	depth, _ := strconv.Atoi(r.FormValue("depth"))
	if depth <= 0 {
		depth = 1
	}

	summary, err := app.GetContentService().ImportFromURLs([]string{url}, depth)
	if err != nil {
		http.Error(w, "Failed to crawl: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func HandleAdminWikiImport(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	titles := strings.Split(r.FormValue("titles"), "\n")
	summary, err := app.GetContentService().ImportFromWikipedia(titles)
	if err != nil {
		http.Error(w, "Failed to import: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func HandleAdminWorkers(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	app.RenderTemplate(w, "admin_workers.html", struct {
		User    *models.User
		Workers []map[string]interface{}
	}{
		User:    user,
		Workers: app.GetWorkerManager().GetWorkers(),
	})
}

func HandleAPIAdminWorkers(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	w.Header().Set("Content-Type", "application/json")
	if err != nil || !user.IsAdmin {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"workers": []interface{}{},
			"error":   "Unauthorized",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"workers": app.GetWorkerManager().GetWorkers(),
	})
}

func HandleAdminImportData(app *app.App, w http.ResponseWriter, r *http.Request) {
	user, err := app.GetSessionService().GetUserFromRequest(r)
	if err != nil || !user.IsAdmin {
		app.RenderForbidden(w, r)
		return
	}

	type ImportDataPage struct {
		User    *models.User
		Msg     string
		Summary *models.ImportSummary
	}

	var msg string
	var summary *models.ImportSummary

	if r.Method == "POST" {
		file, _, err := r.FormFile("csvfile")
		if err != nil {
			http.Error(w, "Failed to get file: "+err.Error(), http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			http.Error(w, "Failed to read file: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Start async import, but do not set msg to job ID
		go func(data []byte) {
			_, _ = app.GetContentService().ImportFromCSV(bytes.NewReader(data)) // Optionally, you could store the result somewhere for later display
		}(data)

		// Show spinner only (no toast/message)
		app.RenderTemplate(w, "admin_import_data.html", ImportDataPage{
			User:    user,
			Msg:     "", // No message, just spinner
			Summary: nil,
		})
		return
	}

	app.RenderTemplate(w, "admin_import_data.html", ImportDataPage{
		User:    user,
		Msg:     msg,
		Summary: summary,
	})
}

// New handler to check import job status
func HandleAdminImportStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job_id")
	services.ImportJobsMu.RLock()
	status, exists := services.ImportJobs[jobID]
	services.ImportJobsMu.RUnlock()
	if !exists {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// Helper functions
func RenderTemplate(app *app.App, w http.ResponseWriter, name string, data interface{}) {
	app.RenderTemplate(w, name, data)
}

func RenderForbidden(app *app.App, w http.ResponseWriter, r *http.Request) {
	app.RenderTemplate(w, "forbidden.html", nil)
}

func SetSessionCookie(app *app.App, w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(sessionDuration.Seconds()),
	})
}
