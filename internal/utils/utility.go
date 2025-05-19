package utils

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"search-engine/internal/models"
)

const (
	SessionCookieName = "session_id"
	SessionDuration   = 24 * time.Hour
)

func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func TruncateContent(s string, max int) string {
	if len(s) <= max {
		return s
	}

	// Find the last space before max
	lastSpace := max
	for i := max; i >= 0; i-- {
		if i < len(s) && s[i] == ' ' {
			lastSpace = i
			break
		}
	}

	return s[:lastSpace] + "..."
}

func CalculateScore(doc models.Document, query string) float64 {
	query = strings.ToLower(query)
	title := strings.ToLower(doc.Title)
	content := strings.ToLower(doc.Content)

	score := 0.0
	if strings.Contains(title, query) {
		score += 2.0
	}
	if strings.Contains(content, query) {
		score += 1.0
	}
	return score
}

// ... existing code ...
