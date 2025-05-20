package services

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "search-engine/importworker"
	"search-engine/internal/models"
	"search-engine/internal/utils"

	"github.com/go-shiori/go-readability"
	"github.com/gocolly/colly/v2"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

// SQLUserService implementation
type SQLUserService struct {
	db *sql.DB
}

func NewSQLUserService(db *sql.DB) models.UserService {
	return &SQLUserService{db: db}
}

func (s *SQLUserService) Register(username, password string, isAdmin bool) (*models.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	var isAdminInt int
	if isAdmin {
		isAdminInt = 1
	}

	res, err := s.db.Exec(
		"INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
		username, string(hashedPassword), isAdminInt,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	userID, _ := res.LastInsertId()
	return &models.User{
		ID:       int(userID),
		Username: username,
		IsAdmin:  isAdmin,
	}, nil
}

func (s *SQLUserService) Login(username, password string) (*models.User, error) {
	var user models.User
	var passwordHash string
	var isAdminInt int

	err := s.db.QueryRow(
		"SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &isAdminInt)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	user.IsAdmin = isAdminInt == 1

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	return &user, nil
}

func (s *SQLUserService) GetUserByID(id int) (*models.User, error) {
	var user models.User
	var isAdminInt int

	err := s.db.QueryRow(
		"SELECT id, username, is_admin FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &isAdminInt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	user.IsAdmin = isAdminInt == 1
	return &user, nil
}

// SQLSearchService implementation
type SQLSearchService struct {
	db *sql.DB
}

func NewSQLSearchService(db *sql.DB) models.SearchService {
	return &SQLSearchService{db: db}
}

func (s *SQLSearchService) Search(query string) ([]models.SearchResult, error) {
	query = strings.ToLower(query)
	var results []models.SearchResult

	rows, err := s.db.Query(
		"SELECT id, title, body, source_url FROM content WHERE LOWER(title) LIKE ? OR LOWER(body) LIKE ? ORDER BY created_at DESC LIMIT 50",
		"%"+query+"%", "%"+query+"%",
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var title, body, sourceURL string
		if err := rows.Scan(&id, &title, &body, &sourceURL); err != nil {
			continue
		}

		link := sourceURL
		doc := models.Document{
			ID:      strconv.Itoa(id),
			Title:   title,
			Content: utils.TruncateContent(body, 180),
			Link:    link,
		}
		score := utils.CalculateScore(doc, query)
		if score > 0 {
			results = append(results, models.SearchResult{
				Document: doc,
				Score:    score,
			})
		}
	}

	return results, nil
}

func (s *SQLSearchService) SaveSearchHistory(userID int, query string) error {
	_, err := s.db.Exec(
		"INSERT INTO search_history (user_id, query) VALUES (?, ?)",
		userID, query,
	)
	if err != nil {
		return fmt.Errorf("failed to save search history: %w", err)
	}
	return nil
}

func (s *SQLSearchService) GetSearchHistory(userID int) ([]models.History, error) {
	rows, err := s.db.Query(
		"SELECT query, timestamp FROM search_history WHERE user_id = ? ORDER BY timestamp DESC",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var history []models.History
	for rows.Next() {
		var h models.History
		if err := rows.Scan(&h.Query, &h.Timestamp); err == nil {
			history = append(history, h)
		}
	}

	return history, nil
}

// SQLContentService implementation
type SQLContentService struct {
	db          *sql.DB
	workerMgr   models.WorkerManager
	urlRegex    *regexp.Regexp
	httpClient  *http.Client
	collyConfig func(*colly.Collector)
}

func NewSQLContentService(db *sql.DB, workerMgr models.WorkerManager) models.ContentService {
	return &SQLContentService{
		db:         db,
		workerMgr:  workerMgr,
		urlRegex:   regexp.MustCompile(`https?://[^\s"'<>]+`),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		collyConfig: func(c *colly.Collector) {
			c.Limit(&colly.LimitRule{
				DomainGlob:  "*",
				Parallelism: 2,
				Delay:       1 * time.Second,
			})
		},
	}
}

func (s *SQLContentService) AddContent(title, body, sourceURL string) error {
	_, err := s.db.Exec(
		"INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
		title, body, sourceURL,
	)
	if err != nil {
		return fmt.Errorf("failed to save content: %w", err)
	}
	return nil
}

func (s *SQLContentService) GetRecentContent(limit int) ([]models.ScrapedContent, error) {
	rows, err := s.db.Query(
		"SELECT title, body, created_at FROM content ORDER BY created_at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var contents []models.ScrapedContent
	for rows.Next() {
		var c models.ScrapedContent
		if err := rows.Scan(&c.Title, &c.Body, &c.CreatedAt); err == nil {
			contents = append(contents, c)
		}
	}

	return contents, nil
}

func (s *SQLContentService) ImportFromCSV(file io.Reader) (models.ImportSummary, error) {
	log.Println("[DEBUG] ImportFromCSV: started")
	var summary models.ImportSummary
	if s.workerMgr == nil {
		log.Println("[DEBUG] ImportFromCSV: worker manager is not initialized")
		return summary, fmt.Errorf("worker manager is not initialized")
	}
	reader := csv.NewReader(file)
	_, err := reader.Read() // skip header
	if err != nil {
		log.Printf("[DEBUG] ImportFromCSV: failed to read header: %v", err)
		return summary, fmt.Errorf("failed to read CSV header: %w", err)
	}
	rowNum := 0
	for {
		log.Printf("[DEBUG] ImportFromCSV: reading row %d", rowNum)
		record, err := reader.Read()
		if err == io.EOF {
			log.Printf("[DEBUG] ImportFromCSV: reached EOF at row %d", rowNum)
			break
		}
		if err != nil {
			log.Printf("[DEBUG] ImportFromCSV: CSV read error at row %d: %v", rowNum, err)
			summary.Failures = append(summary.Failures, "CSV read error: "+err.Error())
			continue
		}
		if len(record) < 3 {
			log.Printf("[DEBUG] ImportFromCSV: Invalid CSV row at row %d: %v", rowNum, record)
			summary.Failures = append(summary.Failures, "Invalid CSV row: "+strings.Join(record, ", "))
			continue
		}

		title, body, sourceURL := record[0], record[1], record[2]
		log.Printf("[DEBUG] ImportFromCSV: Distributing job for row %d: title=%s, body=%s, sourceURL=%s", rowNum, title, body, sourceURL)
		job := &pb.ImportJob{
			Urls:       []string{sourceURL},
			Keywords:   []string{title, body},
			Depth:      1,
			SourceType: "direct",
		}

		results, err := s.workerMgr.DistributeJob(job)
		log.Printf("[DEBUG] ImportFromCSV: DistributeJob returned for row %d (err=%v, results=%+v)", rowNum, err, results)
		if err != nil {
			summary.Failures = append(summary.Failures, title+": "+err.Error())
			continue
		}

		for _, res := range results {
			summary.Successes = append(summary.Successes, res.Successes...)
			summary.Failures = append(summary.Failures, res.Failures...)
		}
		rowNum++
	}
	log.Println("[DEBUG] ImportFromCSV: completed")
	return summary, nil
}

func (s *SQLContentService) ImportFromURLs(urls []string, depth int) (models.ImportSummary, error) {
	var summary models.ImportSummary
	job := &pb.ImportJob{
		Urls:     urls,
		Depth:    int32(depth),
		Keywords: []string{},
	}

	results, err := s.workerMgr.DistributeJob(job)
	if err != nil {
		return summary, fmt.Errorf("failed to distribute job: %w", err)
	}

	for _, res := range results {
		summary.Successes = append(summary.Successes, res.Successes...)
		summary.Failures = append(summary.Failures, res.Failures...)
	}

	return summary, nil
}

func (s *SQLContentService) ImportFromWikipedia(titles []string) (models.ImportSummary, error) {
	var summary models.ImportSummary

	for _, title := range titles {
		title = strings.TrimSpace(title)
		if title == "" {
			continue
		}

		artTitle, artContent, err := s.fetchWikipediaArticle(title)
		if err != nil {
			summary.Failures = append(summary.Failures, title+": Failed to fetch article")
			continue
		}

		if err := s.AddContent(artTitle, artContent, "https://en.wikipedia.org/wiki/"+url.PathEscape(title)); err != nil {
			summary.Failures = append(summary.Failures, title+": "+err.Error())
			continue
		}

		summary.Successes = append(summary.Successes, title)
	}

	return summary, nil
}

func (s *SQLContentService) fetchWikipediaArticle(title string) (string, string, error) {
	apiURL := "https://en.wikipedia.org/w/api.php?action=query&prop=extracts&explaintext&format=json&titles=" + url.QueryEscape(title)
	resp, err := s.httpClient.Get(apiURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch Wikipedia API: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Query struct {
			Pages map[string]struct {
				Title   string `json:"title"`
				Extract string `json:"extract"`
			} `json:"pages"`
		} `json:"query"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("failed to decode Wikipedia response: %w", err)
	}

	for _, page := range result.Query.Pages {
		return page.Title, page.Extract, nil
	}

	return "", "", fmt.Errorf("no content found for title: %s", title)
}

func (s *SQLContentService) ScrapeReadable(rawurl string) (string, string, error) {
	resp, err := s.httpClient.Get(rawurl)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse URL: %w", err)
	}

	article, err := readability.FromReader(strings.NewReader(string(body)), parsedURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse readable content: %w", err)
	}

	return article.Title, article.TextContent, nil
}

// MemorySessionService implementation
type MemorySessionService struct {
	sessions    map[string]models.Session
	mu          sync.RWMutex
	userService models.UserService
}

func NewMemorySessionService(userService models.UserService) models.SessionService {
	return &MemorySessionService{
		sessions:    make(map[string]models.Session),
		userService: userService,
	}
}

func (s *MemorySessionService) CreateSession(userID int) string {
	sessionID := utils.GenerateID()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sessionID] = models.Session{
		UserID:    strconv.Itoa(userID),
		ExpiresAt: time.Now().Add(utils.SessionDuration),
	}

	return sessionID
}

func (s *MemorySessionService) GetUserFromRequest(r *http.Request) (*models.User, error) {
	cookie, err := r.Cookie(utils.SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	s.mu.RLock()
	session, exists := s.sessions[cookie.Value]
	s.mu.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		return nil, fmt.Errorf("invalid or expired session")
	}

	userID, err := strconv.Atoi(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in session: %w", err)
	}

	return s.userService.GetUserByID(userID)
}

func (s *MemorySessionService) DeleteSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(utils.SessionCookieName)
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     utils.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// WorkerManager implementation
type workerClient struct {
	address   string
	client    pb.ImportWorkerClient
	conn      *grpc.ClientConn
	jobCount  int32
	isHealthy bool
	lastSeen  time.Time
}

type workerManagerImpl struct {
	mu       sync.RWMutex
	registry string
	workers  map[string]*workerClient
}

func NewWorkerManager(registryAddr string) models.WorkerManager {
	return &workerManagerImpl{
		registry: registryAddr,
		workers:  make(map[string]*workerClient),
	}
}

func (wm *workerManagerImpl) Start() {
	go wm.discoverWorkers()
}

func (wm *workerManagerImpl) Close() {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	for _, w := range wm.workers {
		w.conn.Close()
	}
}

func (wm *workerManagerImpl) discoverWorkers() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("[INFO] discoverWorkers: Starting worker discovery cycle")
		conn, err := grpc.Dial(wm.registry, grpc.WithInsecure())
		if err != nil {
			log.Printf("[ERROR] discoverWorkers: Failed to connect to registry: %v", err)
			continue
		}

		client := pb.NewRegistryClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.GetWorkers(ctx, &pb.GetWorkersRequest{})
		cancel()
		conn.Close()

		if err != nil {
			log.Printf("[ERROR] discoverWorkers: Failed to fetch workers from registry: %v", err)
			continue
		}

		log.Println("[INFO] discoverWorkers: Acquiring write lock to update worker list")
		wm.mu.Lock()

		// Keep existing connections for workers that are still present
		newWorkers := make(map[string]*workerClient)
		for _, w := range resp.Workers {
			if existing, exists := wm.workers[w.WorkerId]; exists {
				// Update existing worker info
				existing.jobCount = w.JobCount
				existing.isHealthy = true
				existing.lastSeen = time.Now()
				newWorkers[w.WorkerId] = existing
				log.Printf("[INFO] discoverWorkers: Updated existing worker %s at %s", w.WorkerId, w.Address)
			} else {
				// Create new connection for new worker
				workerConn, err := grpc.Dial(w.Address, grpc.WithInsecure())
				if err != nil {
					log.Printf("[ERROR] discoverWorkers: Failed to connect to worker %s at %s: %v", w.WorkerId, w.Address, err)
					continue
				}

				importWorkerClient := pb.NewImportWorkerClient(workerConn)
				log.Printf("[INFO] discoverWorkers: Connected to new worker %s at %s", w.WorkerId, w.Address)
				newWorkers[w.WorkerId] = &workerClient{
					address:   w.Address,
					client:    importWorkerClient,
					conn:      workerConn,
					jobCount:  w.JobCount,
					isHealthy: true,
					lastSeen:  time.Now(),
				}
			}
		}

		// Close connections for removed workers
		for id, w := range wm.workers {
			if _, exists := newWorkers[id]; !exists {
				log.Printf("[INFO] discoverWorkers: Closing connection to removed worker at %s", w.address)
				w.conn.Close()
			}
		}

		wm.workers = newWorkers
		wm.mu.Unlock()
		log.Println("[INFO] discoverWorkers: Released write lock after updating worker list")
	}
}

func (wm *workerManagerImpl) DistributeJob(job *pb.ImportJob) ([]*pb.ImportResult, error) {
	log.Println("[INFO] DistributeJob: Acquiring read lock")
	wm.mu.RLock()
	if len(wm.workers) == 0 {
		log.Println("[ERROR] DistributeJob: No workers available")
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

	if selectedWorker == nil {
		log.Println("[ERROR] DistributeJob: No selected worker")
		wm.mu.RUnlock()
		return nil, fmt.Errorf("no workers available")
	}
	wm.mu.RUnlock()
	log.Println("[INFO] DistributeJob: Releasing read lock")

	log.Printf("[INFO] DistributeJob: Sending job to worker at %s", selectedWorker.address)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	log.Printf("[DEBUG] DistributeJob: Calling Import on worker %s", selectedWorker.address)
	result, err := selectedWorker.client.Import(ctx, job)
	log.Printf("[DEBUG] DistributeJob: Import call returned (err=%v, result=%+v)", err, result)

	log.Println("[DEBUG] DistributeJob: After Import call, before error check")
	if err != nil {
		log.Printf("[ERROR] DistributeJob: Worker import failed for %s: %v", selectedWorker.address, err)
		// Signal worker removal without nested locks
		go func() {
			log.Println("[INFO] DistributeJob: Acquiring write lock for worker removal")
			wm.mu.Lock()
			defer func() {
				log.Println("[INFO] DistributeJob: Releasing write lock after worker removal")
				wm.mu.Unlock()
			}()
			for id, w := range wm.workers {
				if w == selectedWorker {
					log.Printf("[INFO] DistributeJob: Removing unhealthy worker %s at %s", id, w.address)
					w.conn.Close()
					delete(wm.workers, id)
					break
				}
			}
		}()
		return nil, fmt.Errorf("worker import failed: %w", err)
	}
	log.Println("[DEBUG] DistributeJob: After error check, before write lock")
	log.Println("[INFO] DistributeJob: Acquiring write lock to update job count")
	wm.mu.Lock()
	selectedWorker.jobCount++
	wm.mu.Unlock()
	log.Println("[INFO] DistributeJob: Released write lock after updating job count")
	log.Println("[DEBUG] DistributeJob: Before return statement")
	log.Printf("[INFO] DistributeJob: Job completed by worker at %s", selectedWorker.address)
	return []*pb.ImportResult{result}, nil
}

func (wm *workerManagerImpl) GetWorkers() []map[string]interface{} {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	workers := make([]map[string]interface{}, 0, len(wm.workers))
	for id, worker := range wm.workers {
		workers = append(workers, map[string]interface{}{
			"worker_id":  id,
			"address":    worker.address,
			"is_healthy": worker.isHealthy,
			"job_count":  worker.jobCount,
			"last_seen":  worker.lastSeen.Format(time.RFC3339),
		})
	}

	return workers
}
