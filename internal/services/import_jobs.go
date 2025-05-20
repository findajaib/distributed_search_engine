package services

import (
	"search-engine/internal/models"
	"sync"
)

type ImportJobStatus struct {
	Status  string // "pending", "running", "done", "failed"
	Summary *models.ImportSummary
	Error   string
}

var (
	ImportJobs   = make(map[string]*ImportJobStatus)
	ImportJobsMu sync.RWMutex
)
