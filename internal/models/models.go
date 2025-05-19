package models

import (
	"io"
	"net/http"
	pb "search-engine/importworker"
	"time"
)

// Domain types
type (
	Document struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Content string `json:"content"`
		Link    string `json:"link"`
	}

	SearchResult struct {
		Document Document `json:"document"`
		Score    float64  `json:"score"`
	}

	User struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
	}

	History struct {
		Query     string    `json:"query"`
		Timestamp time.Time `json:"timestamp"`
	}

	Session struct {
		UserID    string
		ExpiresAt time.Time
	}

	ScrapedContent struct {
		Title     string
		Body      string
		CreatedAt string
	}

	ImportSummary struct {
		Successes []string
		Failures  []string
	}
)

// Service interfaces for dependency injection
type (
	UserService interface {
		Register(username, password string, isAdmin bool) (*User, error)
		Login(username, password string) (*User, error)
		GetUserByID(id int) (*User, error)
	}

	SearchService interface {
		Search(query string) ([]SearchResult, error)
		SaveSearchHistory(userID int, query string) error
		GetSearchHistory(userID int) ([]History, error)
	}

	ContentService interface {
		AddContent(title, body, sourceURL string) error
		GetRecentContent(limit int) ([]ScrapedContent, error)
		ImportFromCSV(file io.Reader) (ImportSummary, error)
		ImportFromURLs(urls []string, depth int) (ImportSummary, error)
		ImportFromWikipedia(titles []string) (ImportSummary, error)
		ScrapeReadable(url string) (string, string, error)
	}

	SessionService interface {
		CreateSession(userID int) string
		GetUserFromRequest(r *http.Request) (*User, error)
		DeleteSession(w http.ResponseWriter, r *http.Request)
	}

	WorkerManager interface {
		Start()
		Close()
		DistributeJob(job *pb.ImportJob) ([]*pb.ImportResult, error)
		GetWorkers() []map[string]interface{}
	}
)
