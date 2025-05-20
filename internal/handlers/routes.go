package handlers

import (
	"net/http"

	"search-engine/internal/app"
)

// SetupRoutes configures all the routes for the application
func SetupRoutes(app *app.App) {
	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Public routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		HandleHome(app, w, r)
	})
	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		HandleSearch(app, w, r)
	})
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		HandleRegister(app, w, r)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		HandleLogin(app, w, r)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		HandleLogout(app, w, r)
	})

	// Protected routes
	http.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		HandleHistory(app, w, r)
	})

	// API routes
	http.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		HandleAPISearch(app, w, r)
	})
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		HandleAPIHistory(app, w, r)
	})

	// Admin routes
	http.HandleFunc("/admin/register", func(w http.ResponseWriter, r *http.Request) {
		HandleRegisterAdmin(app, w, r)
	})
	http.HandleFunc("/admin/scrape", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminScrape(app, w, r)
	})
	http.HandleFunc("/admin/scrape/single", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminScrapeSingle(app, w, r)
	})
	http.HandleFunc("/admin/scrape/crawl", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminScrapeCrawl(app, w, r)
	})
	http.HandleFunc("/admin/wiki/import", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminWikiImport(app, w, r)
	})
	http.HandleFunc("/admin/workers", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminWorkers(app, w, r)
	})
	http.HandleFunc("/admin/import-data", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminImportData(app, w, r)
	})
	http.HandleFunc("/admin/import-status", func(w http.ResponseWriter, r *http.Request) {
		HandleAdminImportStatus(w, r)
	})

	// Admin API routes
	http.HandleFunc("/api/admin/workers", func(w http.ResponseWriter, r *http.Request) {
		HandleAPIAdminWorkers(app, w, r)
	})
}
