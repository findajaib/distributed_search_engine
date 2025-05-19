package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Database initialization
func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "search_engine.db")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin INTEGER DEFAULT 0
	)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create users table: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS content (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_url TEXT
	)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create content table: %w", err)
	}

	_, _ = db.Exec(`ALTER TABLE content ADD COLUMN source_url TEXT`)

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS search_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		query TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create search_history table: %w", err)
	}

	return db, nil
}
