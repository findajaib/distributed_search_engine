package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"context"
	"fmt"
	pb "search-engine/importworker"

	"github.com/go-shiori/go-readability"
	"github.com/gocolly/colly/v2"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

var db *sql.DB

// Helper to extract the first URL from a string
var urlRegex = regexp.MustCompile(`https?://[^\s"'<>]+`)

// List of worker node addresses
var workerAddresses = []string{
	"localhost:50051",
	// Add more worker addresses as needed
}

// WorkerManager manages worker connections and job distribution
type WorkerManager struct {
	mu       sync.RWMutex
	registry string
	workers  map[string]*workerClient
}

type workerClient struct {
	conn      *grpc.ClientConn
	client    pb.ImportWorkerClient
	jobCount  int32
	address   string
	isHealthy bool
	lastSeen  time.Time
}

func NewWorkerManager(registryAddr string) *WorkerManager {
	return &WorkerManager{
		registry: registryAddr,
		workers:  make(map[string]*workerClient),
	}
}

func (wm *WorkerManager) Start() {
	// Start worker discovery loop
	go wm.discoverWorkers()
}

func (wm *WorkerManager) discoverWorkers() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		conn, err := grpc.Dial(wm.registry, grpc.WithInsecure())
		if err != nil {
			log.Printf("Failed to connect to registry: %v", err)
			continue
		}
		client := pb.NewRegistryClient(conn)
		resp, err := client.GetWorkers(context.Background(), &pb.GetWorkersRequest{})
		conn.Close()
		if err != nil {
			log.Printf("Failed to get workers: %v", err)
			continue
		}

		wm.mu.Lock()
		// Remove workers that are no longer in the registry
		for id := range wm.workers {
			found := false
			for _, w := range resp.Workers {
				if w.WorkerId == id {
					found = true
					break
				}
			}
			if !found {
				wm.workers[id].conn.Close()
				delete(wm.workers, id)
			}
		}

		// Add new workers
		for _, w := range resp.Workers {
			if _, exists := wm.workers[w.WorkerId]; !exists {
				conn, err := grpc.Dial(w.Address, grpc.WithInsecure())
				if err != nil {
					log.Printf("Failed to connect to worker %s: %v", w.WorkerId, err)
					continue
				}
				wm.workers[w.WorkerId] = &workerClient{
					conn:      conn,
					client:    pb.NewImportWorkerClient(conn),
					jobCount:  w.JobCount,
					address:   w.Address,
					isHealthy: true,
					lastSeen:  time.Now(),
				}
			} else {
				// Update existing worker info
				wm.workers[w.WorkerId].jobCount = w.JobCount
				wm.workers[w.WorkerId].lastSeen = time.Now()
			}
		}
		wm.mu.Unlock()
	}
}

func (wm *WorkerManager) DistributeJob(job *pb.ImportJob) ([]*pb.ImportResult, error) {
	wm.mu.RLock()
	if len(wm.workers) == 0 {
		wm.mu.RUnlock()
		return nil, fmt.Errorf("no workers available")
	}

	// Find worker with least jobs
	var selectedWorker *workerClient
	var minJobs int32 = 1<<31 - 1
	for _, w := range wm.workers {
		if w.jobCount < minJobs {
			minJobs = w.jobCount
			selectedWorker = w
		}
	}
	wm.mu.RUnlock()

	if selectedWorker == nil {
		return nil, fmt.Errorf("no workers available")
	}

	// Execute job
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	result, err := selectedWorker.client.Import(ctx, job)
	if err != nil {
		return nil, err
	}

	// Update job count
	wm.mu.Lock()
	selectedWorker.jobCount++
	wm.mu.Unlock()

	return []*pb.ImportResult{result}, nil
}

func (wm *WorkerManager) Close() {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	for _, w := range wm.workers {
		w.conn.Close()
	}
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "search_engine.db")
	if err != nil {
		return err
	}
	// Create users table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin INTEGER DEFAULT 0
	)`)
	if err != nil {
		return err
	}
	// Create content table (add source_url if not exists)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS content (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_url TEXT
	)`)
	if err != nil {
		return err
	}
	// Try to add source_url column if it doesn't exist (for migration)
	_, _ = db.Exec(`ALTER TABLE content ADD COLUMN source_url TEXT`)
	// Create search_history table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS search_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		query TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	return err
}

// Document represents a searchable document
type Document struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Link    string `json:"link"`
}

// SearchResult represents a search result
type SearchResult struct {
	Document Document `json:"document"`
	Score    float64  `json:"score"`
}

// User represents a registered user
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	IsAdmin  int    `json:"is_admin"`
}

// History represents a search history entry
type History struct {
	Query     string    `json:"query"`
	Timestamp time.Time `json:"timestamp"`
}

// Session represents a user session
type Session struct {
	UserID    string
	ExpiresAt time.Time
}

// In-memory stores
var (
	documents []Document
	users     = make(map[string]User)
	sessions  = make(map[string]Session)
)

func main() {
	if err := initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize worker manager
	wm := NewWorkerManager("localhost:50052")
	wm.Start()
	defer wm.Close()

	// Create a context with worker manager
	ctx := context.WithValue(context.Background(), "workerManager", wm)

	// Initialize sample documents
	documents = []Document{
		{ID: "1", Title: "Go Programming", Content: "Go is a statically typed, compiled programming language designed at Google."},
		{ID: "2", Title: "Web Development", Content: "Web development is the work involved in developing a website for the Internet."},
		{ID: "3", Title: "Search Engines", Content: "A search engine is a software system designed to carry out web searches."},
	}

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/search", handleSearch)
	http.HandleFunc("/api/search", handleAPISearch)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/history", handleHistory)
	http.HandleFunc("/api/history", handleAPIHistory)
	http.HandleFunc("/admin/scrape", handleAdminScrape)
	http.HandleFunc("/register-admin", handleRegisterAdmin)
	http.HandleFunc("/admin/scrape-single", handleAdminScrapeSingle)
	http.HandleFunc("/admin/scrape-crawl", handleAdminScrapeCrawl)
	http.HandleFunc("/admin/wiki-import", handleAdminWikiImport)
	http.HandleFunc("/admin/workers", handleAdminWorkers)
	http.HandleFunc("/api/admin/workers", func(w http.ResponseWriter, r *http.Request) {
		handleAPIAdminWorkers(w, r.WithContext(ctx))
	})
	http.HandleFunc("/admin/import-data", func(w http.ResponseWriter, r *http.Request) {
		handleAdminImportData(w, r.WithContext(ctx))
	})

	log.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	tmpl.Execute(w, struct {
		User *User
	}{
		User: user,
	})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	results := searchDocuments(query)

	// Save search to history if user is logged in
	if user != nil {
		_, err := db.Exec("INSERT INTO search_history (user_id, query) VALUES (?, ?)", user.ID, query)
		if err != nil {
			log.Println("Failed to save search history:", err)
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/results.html"))
	tmpl.Execute(w, struct {
		Query   string
		Results []SearchResult
		User    *User
	}{
		Query:   query,
		Results: results,
		User:    user,
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check if username already exists in DB
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&exists)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if exists > 0 {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		// Insert new user
		res, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		userID, _ := res.LastInsertId()

		// Create session
		sessionID := createSession(int(userID))
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 24 hours
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/register.html"))
	tmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Find user in DB
		var id int
		var passwordHash string
		err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&id, &passwordHash)
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Check password
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Create session
		sessionID := createSession(id)
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 24 hours
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT query, timestamp FROM search_history WHERE user_id = ? ORDER BY timestamp DESC", user.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	history := []History{}
	for rows.Next() {
		var h History
		if err := rows.Scan(&h.Query, &h.Timestamp); err == nil {
			history = append(history, h)
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/history.html"))
	tmpl.Execute(w, struct {
		User    *User
		History []History
	}{
		User:    user,
		History: history,
	})
}

func handleAPISearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	results := searchDocuments(query)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := db.Query("SELECT query, timestamp FROM search_history WHERE user_id = ? ORDER BY timestamp DESC", user.ID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	history := []History{}
	for rows.Next() {
		var h History
		if err := rows.Scan(&h.Query, &h.Timestamp); err == nil {
			history = append(history, h)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func renderForbidden(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/forbidden.html"))
	tmpl.Execute(w, nil)
}

func handleAdminScrape(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}

	var scrapeMsg string
	if r.Method == "POST" {
		mode := r.FormValue("mode")
		url := r.FormValue("url")
		selector := r.FormValue("selector")
		if url != "" {
			if mode == "scrape" {
				title, body, err := scrapeReadable(url)
				if err != nil {
					scrapeMsg = "Failed to scrape: " + err.Error()
				} else {
					_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", title, body)
					if err != nil {
						scrapeMsg = "Failed to save content: " + err.Error()
					} else {
						scrapeMsg = "Scraping and saving successful!"
					}
				}
			} else if mode == "crawl" && selector != "" {
				c := colly.NewCollector(colly.AllowedDomains(getDomain(url)))
				found := 0
				c.OnHTML(selector, func(e *colly.HTMLElement) {
					link := e.Request.AbsoluteURL(e.Attr("href"))
					if link != "" {
						title, body, err := scrapeReadable(link)
						if err == nil && title != "" && body != "" {
							_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", title, body)
							if err == nil {
								found++
							}
						}
					}
				})
				err := c.Visit(url)
				if err != nil {
					scrapeMsg = "Crawling failed: " + err.Error()
				} else {
					scrapeMsg = "Crawling and scraping complete! " + strconv.Itoa(found) + " articles added."
				}
			} else {
				scrapeMsg = "Please provide a valid selector for crawling."
			}
		}
	}

	// Fetch last 10 scraped content
	rows, err := db.Query("SELECT title, body, created_at FROM content ORDER BY created_at DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ScrapedContent struct {
		Title     string
		Body      string
		CreatedAt string
	}
	var contents []ScrapedContent
	for rows.Next() {
		var c ScrapedContent
		rows.Scan(&c.Title, &c.Body, &c.CreatedAt)
		contents = append(contents, c)
	}
	tmpl := template.Must(template.ParseFiles("templates/admin_scrape.html"))
	tmpl.Execute(w, struct {
		User     *User
		Msg      string
		Contents []ScrapedContent
	}{
		User:     user,
		Msg:      scrapeMsg,
		Contents: contents,
	})
}

// Scrape a URL for main readable content using go-readability
func scrapeReadable(rawurl string) (string, string, error) {
	resp, err := http.Get(rawurl)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return "", "", err
	}
	article, err := readability.FromReader(strings.NewReader(string(body)), parsedURL)
	if err != nil {
		return "", "", err
	}
	title := article.Title
	content := article.TextContent
	return title, content, nil
}

// Helper to get domain from URL for Colly
func getDomain(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Host
}

// Helper to truncate content to about 180 chars (2 lines)
func truncateContent(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	// Try to cut at a word boundary
	truncated := s[:max]
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > 0 {
		truncated = truncated[:lastSpace]
	}
	return truncated + "..."
}

// Helper to extract the first URL from a string
func extractFirstURL(s string) string {
	match := urlRegex.FindString(s)
	return match
}

func searchDocuments(query string) []SearchResult {
	query = strings.ToLower(query)
	var results []SearchResult

	log.Printf("[DEBUG] Searching for query: %s", query)
	rows, err := db.Query("SELECT id, title, body, source_url FROM content WHERE LOWER(title) LIKE ? OR LOWER(body) LIKE ? ORDER BY created_at DESC LIMIT 50", "%"+query+"%", "%"+query+"%")
	if err != nil {
		log.Printf("[ERROR] DB search error: %v", err)
		return results
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id int
		var title, body, sourceURL string
		if err := rows.Scan(&id, &title, &body, &sourceURL); err == nil {
			log.Printf("[DEBUG] Found document - ID: %d, Title: %s", id, title)
			link := sourceURL
			doc := Document{
				ID:      strconv.Itoa(id),
				Title:   title,
				Content: truncateContent(body, 180),
				Link:    link,
			}
			score := calculateScore(doc, query)
			if score > 0 {
				log.Printf("[DEBUG] Document scored: %f for query: %s", score, query)
				results = append(results, SearchResult{
					Document: doc,
					Score:    score,
				})
				count++
			}
		}
	}
	log.Printf("[DEBUG] Search complete - found %d matching documents", count)
	return results
}

func calculateScore(doc Document, query string) float64 {
	titleScore := 0.0
	contentScore := 0.0

	if strings.Contains(strings.ToLower(doc.Title), query) {
		titleScore = 1.0
	}

	if strings.Contains(strings.ToLower(doc.Content), query) {
		contentScore = 0.5
	}

	return titleScore + contentScore
}

// Helper functions

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func createSession(userID int) string {
	sessionID := generateID()
	sessions[sessionID] = Session{
		UserID:    strconv.Itoa(userID),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return sessionID
}

func getUserFromSession(r *http.Request) *User {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	session, exists := sessions[cookie.Value]
	if !exists || time.Now().After(session.ExpiresAt) {
		delete(sessions, cookie.Value)
		return nil
	}

	userID, err := strconv.Atoi(session.UserID)
	if err != nil {
		return nil
	}
	var user User
	err = db.QueryRow("SELECT id, username, is_admin FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.IsAdmin)
	if err != nil {
		return nil
	}
	return &user
}

func handleRegisterAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check if username already exists in DB
		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&exists)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if exists > 0 {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		// Insert new admin user
		res, err := db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		userID, _ := res.LastInsertId()

		// Create session
		sessionID := createSession(int(userID))
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 24 hours
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/register_admin.html"))
	tmpl.Execute(w, nil)
}

func handleAdminScrapeSingle(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}
	var msg string
	if r.Method == "POST" {
		url := r.FormValue("url")
		if url != "" {
			title, body, err := scrapeReadable(url)
			if err != nil {
				msg = "Failed to scrape: " + err.Error()
			} else {
				_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", title, body)
				if err != nil {
					msg = "Failed to save content: " + err.Error()
				} else {
					msg = "Scraping and saving successful!"
				}
			}
		}
	}
	// Fetch last 10 scraped content
	rows, err := db.Query("SELECT title, body, created_at FROM content ORDER BY created_at DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type ScrapedContent struct {
		Title     string
		Body      string
		CreatedAt string
	}
	var contents []ScrapedContent
	for rows.Next() {
		var c ScrapedContent
		rows.Scan(&c.Title, &c.Body, &c.CreatedAt)
		contents = append(contents, c)
	}
	tmpl := template.Must(template.ParseFiles("templates/admin_scrape_single.html"))
	tmpl.Execute(w, struct {
		User     *User
		Msg      string
		Contents []ScrapedContent
	}{
		User:     user,
		Msg:      msg,
		Contents: contents,
	})
}

func handleAdminScrapeCrawl(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}
	var msg string
	if r.Method == "POST" {
		url := r.FormValue("url")
		selector := r.FormValue("selector")
		if url != "" && selector != "" {
			c := colly.NewCollector(colly.AllowedDomains(getDomain(url)))
			found := 0
			c.OnHTML(selector, func(e *colly.HTMLElement) {
				link := e.Request.AbsoluteURL(e.Attr("href"))
				if link != "" {
					title, body, err := scrapeReadable(link)
					if err == nil && title != "" && body != "" {
						_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", title, body)
						if err == nil {
							found++
						}
					}
				}
			})
			err := c.Visit(url)
			if err != nil {
				msg = "Crawling failed: " + err.Error()
			} else {
				msg = "Crawling and scraping complete! " + strconv.Itoa(found) + " articles added."
			}
		}
	}
	// Fetch last 10 scraped content
	rows, err := db.Query("SELECT title, body, created_at FROM content ORDER BY created_at DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type ScrapedContent struct {
		Title     string
		Body      string
		CreatedAt string
	}
	var contents []ScrapedContent
	for rows.Next() {
		var c ScrapedContent
		rows.Scan(&c.Title, &c.Body, &c.CreatedAt)
		contents = append(contents, c)
	}
	tmpl := template.Must(template.ParseFiles("templates/admin_scrape_crawl.html"))
	tmpl.Execute(w, struct {
		User     *User
		Msg      string
		Contents []ScrapedContent
	}{
		User:     user,
		Msg:      msg,
		Contents: contents,
	})
}

func handleAdminWikiImport(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}
	var wikiMsg string
	if r.Method == "POST" {
		titlesRaw := r.FormValue("wiki_titles")
		titles := []string{}
		for _, line := range strings.Split(titlesRaw, "\n") {
			for _, t := range strings.Split(line, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					titles = append(titles, t)
				}
			}
		}
		added := 0
		for _, title := range titles {
			artTitle, artContent, err := fetchWikipediaArticle(title)
			if err == nil && artContent != "" {
				_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", artTitle, artContent)
				if err == nil {
					added++
				}
			}
		}
		wikiMsg = "Imported " + strconv.Itoa(added) + " Wikipedia articles."
	}
	// Fetch last 10 scraped content
	rows, err := db.Query("SELECT title, body, created_at FROM content ORDER BY created_at DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type ScrapedContent struct {
		Title     string
		Body      string
		CreatedAt string
	}
	var contents []ScrapedContent
	for rows.Next() {
		var c ScrapedContent
		rows.Scan(&c.Title, &c.Body, &c.CreatedAt)
		contents = append(contents, c)
	}
	tmpl := template.Must(template.ParseFiles("templates/admin_wiki_import.html"))
	tmpl.Execute(w, struct {
		User     *User
		WikiMsg  string
		Contents []ScrapedContent
	}{
		User:     user,
		WikiMsg:  wikiMsg,
		Contents: contents,
	})
}

// Fetch Wikipedia article by title using the Wikipedia API
func fetchWikipediaArticle(title string) (string, string, error) {
	apiURL := "https://en.wikipedia.org/w/api.php?action=query&prop=extracts&explaintext&format=json&titles=" + url.QueryEscape(title)
	resp, err := http.Get(apiURL)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	var result struct {
		Query struct {
			Pages map[string]struct {
				Title   string `json:"title"`
				Extract string `json:"extract"`
			} `json:"pages"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}
	for _, page := range result.Query.Pages {
		return page.Title, page.Extract, nil
	}
	return "", "", nil
}

// Update handleAdminImportData to use WorkerManager
func handleAdminImportData(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}

	var msg string
	var importSummary struct {
		Successes []string
		Failures  []string
	}

	if r.Method == "POST" {
		// 1. Check for CSV file upload
		if file, header, err := r.FormFile("csvfile"); err == nil && header.Filename != "" {
			defer file.Close()
			reader := csv.NewReader(file)
			wm := r.Context().Value("workerManager").(*WorkerManager)
			if wm == nil {
				msg = "Worker manager not available"
			} else {
				for {
					record, err := reader.Read()
					if err == io.EOF {
						break
					}
					if err != nil {
						importSummary.Failures = append(importSummary.Failures, "CSV read error: "+err.Error())
						continue
					}
					if len(record) < 3 {
						importSummary.Failures = append(importSummary.Failures, "Invalid CSV row: "+strings.Join(record, ", "))
						continue
					}
					title, body, sourceURL := record[0], record[1], record[2]
					log.Printf("[DEBUG] Processing CSV record: title=%s, sourceURL=%s", title, sourceURL)
					// Create a job to save the record to the database
					job := &pb.ImportJob{
						Urls:       []string{sourceURL},
						Keywords:   []string{title, body}, // Store title and body in keywords
						Depth:      1,
						SourceType: "direct", // Use direct import
					}
					// Dispatch the job to the worker manager
					results, err := wm.DistributeJob(job)
					if err != nil {
						log.Printf("[DEBUG] Failed to distribute job for %s: %v", title, err)
						importSummary.Failures = append(importSummary.Failures, title+": "+err.Error())
					} else {
						log.Printf("[DEBUG] Job distributed for %s, results: %+v", title, results)
						for _, res := range results {
							importSummary.Successes = append(importSummary.Successes, res.Successes...)
							importSummary.Failures = append(importSummary.Failures, res.Failures...)
						}
					}
				}
				msg = "CSV import successfuly finshed."
			}
		} else {
			// Handle URLs/crawl/Wikipedia import
			urls := r.FormValue("urls")
			keywords := r.FormValue("keywords")
			depth, _ := strconv.Atoi(r.FormValue("depth"))
			sourceType := r.FormValue("source_type")
			wikiTitles := r.FormValue("wiki_titles")

			wm := r.Context().Value("workerManager").(*WorkerManager)
			if wm == nil {
				msg = "Worker manager not available"
			} else {
				if urls != "" {
					urlList := strings.Split(urls, "\n")
					keywordList := strings.Split(keywords, ",")
					job := &pb.ImportJob{
						Urls:       urlList,
						Keywords:   keywordList,
						Depth:      int32(depth),
						SourceType: sourceType,
					}
					results, err := wm.DistributeJob(job)
					if err != nil {
						msg = "Failed to distribute job: " + err.Error()
					} else {
						for _, res := range results {
							importSummary.Successes = append(importSummary.Successes, res.Successes...)
							importSummary.Failures = append(importSummary.Failures, res.Failures...)
						}
						msg = "URL import dispatched to workers."
					}
				} else if wikiTitles != "" {
					titles := strings.Split(wikiTitles, "\n")
					for _, title := range titles {
						title = strings.TrimSpace(title)
						if title != "" {
							artTitle, artContent, err := fetchWikipediaArticle(title)
							if err == nil && artContent != "" {
								_, err := db.Exec("INSERT INTO content (title, body) VALUES (?, ?)", artTitle, artContent)
								if err == nil {
									importSummary.Successes = append(importSummary.Successes, title)
								} else {
									importSummary.Failures = append(importSummary.Failures, title+": "+err.Error())
								}
							} else {
								importSummary.Failures = append(importSummary.Failures, title+": Failed to fetch article")
							}
						}
					}
					msg = "Wikipedia import completed."
				}
			}
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/admin_import_data.html"))
	tmpl.Execute(w, struct {
		User    *User
		Msg     string
		Summary struct {
			Successes []string
			Failures  []string
		}
	}{
		User:    user,
		Msg:     msg,
		Summary: importSummary,
	})
}

func handleAdminWorkers(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	log.Printf("[DEBUG] handleAdminWorkers: user=%+v", user)
	if user == nil || user.IsAdmin != 1 {
		log.Printf("[DEBUG] handleAdminWorkers: forbidden, user=%+v", user)
		renderForbidden(w, r)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/admin_workers.html"))
	err := tmpl.ExecuteTemplate(w, "admin_workers.html", struct {
		User *User
	}{
		User: user,
	})
	if err != nil {
		log.Printf("admin_workers template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func handleAPIAdminWorkers(w http.ResponseWriter, r *http.Request) {
	user := getUserFromSession(r)
	if user == nil || user.IsAdmin != 1 {
		renderForbidden(w, r)
		return
	}

	wm := r.Context().Value("workerManager").(*WorkerManager)
	if wm == nil {
		http.Error(w, "Worker manager not available", http.StatusInternalServerError)
		return
	}

	// Get worker information
	wm.mu.RLock()
	workers := make([]map[string]interface{}, 0)
	for id, worker := range wm.workers {
		workers = append(workers, map[string]interface{}{
			"worker_id":  id,
			"address":    worker.address,
			"is_healthy": worker.isHealthy,
			"job_count":  worker.jobCount,
			"last_seen":  worker.lastSeen.Format(time.RFC3339),
		})
	}
	wm.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"workers": workers,
	})
}
