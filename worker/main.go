package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "search-engine/importworker"
	"search-engine/pkg/scraper"

	_ "modernc.org/sqlite"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	port     = flag.Int("port", 50051, "The server port")
	dbPath   = flag.String("db", "search_engine.db", "Path to SQLite database")
	registry = flag.String("registry", "localhost:50052", "Registry server address")
)

type server struct {
	pb.UnimplementedImportWorkerServer
	db         *sql.DB
	jobCounter *jobCounter
	workerID   string
}

type registryClient struct {
	addr     string
	conn     *grpc.ClientConn
	client   pb.RegistryClient
	workerID string
}

type jobCounter struct {
	mu       sync.RWMutex
	count    int32
	lastSeen time.Time
}

func (jc *jobCounter) increment() {
	jc.mu.Lock()
	defer jc.mu.Unlock()
	jc.count++
	jc.lastSeen = time.Now()
}

func (jc *jobCounter) decrement() {
	jc.mu.Lock()
	defer jc.mu.Unlock()
	if jc.count > 0 {
		jc.count--
	}
	jc.lastSeen = time.Now()
}

func (jc *jobCounter) getCount() int32 {
	jc.mu.RLock()
	defer jc.mu.RUnlock()
	return jc.count
}

func (s *server) Import(ctx context.Context, job *pb.ImportJob) (*pb.ImportResult, error) {
	s.jobCounter.increment()
	defer s.jobCounter.decrement()

	// Update registry with new job count
	if err := s.updateRegistryJobCount(); err != nil {
		log.Printf("[WARN] Failed to update registry job count: %v", err)
	}

	var successes, failures []string

	// Defensive: Check DB health before import
	if err := s.db.PingContext(ctx); err != nil {
		log.Printf("[ERROR] Database health check failed before import: %v", err)
		return &pb.ImportResult{Successes: successes, Failures: []string{"Database health check failed: " + err.Error()}}, err
	}

	retryLimit := 5
	retryDelay := 200 * time.Millisecond

	for _, item := range job.Urls {
		select {
		case <-ctx.Done():
			log.Printf("[ERROR] Import cancelled by context: %v", ctx.Err())
			return &pb.ImportResult{Successes: successes, Failures: failures}, ctx.Err()
		default:
		}
		switch job.SourceType {
		case "direct":
			if len(job.Urls) > 0 {
				sourceURL := job.Urls[0]
				log.Printf("[DEBUG] Direct import - Title: %s, Body length: %d, Source URL: %s",
					job.Keywords[0], len(job.Keywords[1]), sourceURL)
				// Defensive: Check for empty title/body
				if job.Keywords[0] == "" || job.Keywords[1] == "" {
					failures = append(failures, sourceURL+": Empty title or body")
					log.Printf("[ERROR] Skipping import: Empty title or body for %s", sourceURL)
					continue
				}
				// Check for exact duplicate (source_url, title, body)
				var exists int
				var err error
				err = s.db.QueryRowContext(ctx, "SELECT 1 FROM content WHERE source_url = ? AND title = ? AND body = ? LIMIT 1", sourceURL, job.Keywords[0], job.Keywords[1]).Scan(&exists)
				if err == nil {
					log.Printf("[INFO] Skipping duplicate record: %s, %s, %s", sourceURL, job.Keywords[0], job.Keywords[1])
					successes = append(successes, sourceURL+" (skipped duplicate)")
					continue
				}
				if err != sql.ErrNoRows {
					log.Printf("[ERROR] Failed to check for duplicate: %v", err)
					failures = append(failures, fmt.Sprintf("%s: %v", sourceURL, err))
					continue
				}
				for attempt := 1; attempt <= retryLimit; attempt++ {
					_, err = s.db.ExecContext(ctx, "INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
						job.Keywords[0],
						job.Keywords[1],
						sourceURL)
					if err == nil {
						successes = append(successes, sourceURL)
						break
					}
					if strings.Contains(err.Error(), "database is locked") {
						log.Printf("[WARN] SQLITE_BUSY on insert, retrying (%d/%d)...", attempt, retryLimit)
						time.Sleep(retryDelay)
						continue
					}
					log.Printf("[ERROR] Failed to insert into database: %v", err)
					failures = append(failures, fmt.Sprintf("%s: %v", sourceURL, err))
					break
				}
				if err != nil {
					// Defensive: Check DB health after error
					if pingErr := s.db.PingContext(ctx); pingErr != nil {
						log.Printf("[CRITICAL] Database health check failed after insert error: %v", pingErr)
					}
				}
			}
		case "scrape":
			result, err := scraper.ScrapeReadable(item)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			if len(job.Keywords) > 0 && !scraper.ContainsKeywords(result.Title+" "+result.Content, job.Keywords) {
				continue
			}
			_, err = s.db.ExecContext(ctx, "INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
				result.Title, result.Content, result.URL)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			successes = append(successes, result.Title)
		case "crawl":
			results, err := scraper.CrawlWebsite(item, int(job.Depth), job.Keywords)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			for _, result := range results {
				_, err := s.db.ExecContext(ctx, "INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
					result.Title, result.Content, result.URL)
				if err != nil {
					failures = append(failures, fmt.Sprintf("%s: %v", result.URL, err))
					continue
				}
				successes = append(successes, result.Title)
			}
		case "wikipedia":
			result, err := scraper.FetchWikipediaArticle(item)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			if result == nil {
				failures = append(failures, fmt.Sprintf("%s: article not found", item))
				continue
			}
			if len(job.Keywords) > 0 && !scraper.ContainsKeywords(result.Title+" "+result.Content, job.Keywords) {
				continue
			}
			_, err = s.db.ExecContext(ctx, "INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
				result.Title, result.Content, result.URL)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			successes = append(successes, result.Title)
		}
	}

	// Defensive: Check DB health after import
	if err := s.db.PingContext(ctx); err != nil {
		log.Printf("[ERROR] Database health check failed after import: %v", err)
		failures = append(failures, "Database health check failed after import: "+err.Error())
	}

	log.Printf("[DEBUG] Import completed. Successes: %d, Failures: %d", len(successes), len(failures))
	return &pb.ImportResult{
		Successes: successes,
		Failures:  failures,
	}, nil
}

func (s *server) updateRegistryJobCount() error {
	conn, err := grpc.Dial(*registry, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to registry: %w", err)
	}
	defer conn.Close()

	client := pb.NewRegistryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.UpdateWorkerStatus(ctx, &pb.UpdateWorkerStatusRequest{
		WorkerId:  s.workerID,
		IsHealthy: true,
		JobCount:  s.jobCounter.getCount(),
	})
	return err
}

func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for better concurrency
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		return nil, err
	}

	// Create content table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS content (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_url TEXT
	)`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func registerWithRegistry(addr string, workerAddr string) (*registryClient, error) {
	maxRetries := 5
	retryDelay := 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			log.Printf("[WARN] Failed to connect to registry (attempt %d/%d): %v", i+1, maxRetries, err)
			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				continue
			}
			return nil, fmt.Errorf("failed to connect to registry after %d attempts: %w", maxRetries, err)
		}

		client := pb.NewRegistryClient(conn)
		workerID := fmt.Sprintf("worker-%d", time.Now().UnixNano())

		// Register worker with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = client.RegisterWorker(ctx, &pb.RegisterWorkerRequest{
			WorkerId: workerID,
			Address:  workerAddr,
		})
		cancel()

		if err != nil {
			conn.Close()
			log.Printf("[WARN] Failed to register worker (attempt %d/%d): %v", i+1, maxRetries, err)
			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				continue
			}
			return nil, fmt.Errorf("failed to register worker after %d attempts: %w", maxRetries, err)
		}

		log.Printf("[INFO] Successfully registered worker %s at %s", workerID, workerAddr)
		return &registryClient{
			addr:     addr,
			conn:     conn,
			client:   client,
			workerID: workerID,
		}, nil
	}

	return nil, fmt.Errorf("failed to register worker after %d attempts", maxRetries)
}

func startHeartbeat(reg *registryClient) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := reg.client.UpdateWorkerStatus(ctx, &pb.UpdateWorkerStatusRequest{
				WorkerId:  reg.workerID,
				IsHealthy: true,
				JobCount:  0, // We'll track this properly later
			})
			cancel()

			if err != nil {
				log.Printf("[ERROR] Failed to send heartbeat: %v", err)
				// Try to reconnect to registry
				if newReg, err := registerWithRegistry(reg.addr, reg.workerID); err == nil {
					reg.conn.Close()
					reg.conn = newReg.conn
					reg.client = newReg.client
					log.Printf("[INFO] Successfully reconnected to registry")
				}
			}
		}
	}()
}

func main() {
	flag.Parse()

	// Initialize database
	db, err := initDB(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create job counter
	jobCounter := &jobCounter{
		count:    0,
		lastSeen: time.Now(),
	}

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()

	// Register with registry
	workerAddr := fmt.Sprintf("localhost:%d", *port)
	registry, err := registerWithRegistry(*registry, workerAddr)
	if err != nil {
		log.Printf("[WARN] Failed to register with registry: %v", err)
	} else {
		defer registry.conn.Close()
		// Register gRPC server with correct workerID
		pb.RegisterImportWorkerServer(s, &server{
			db:         db,
			jobCounter: jobCounter,
			workerID:   registry.workerID,
		})
		startHeartbeat(registry)
	}

	// Add health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, healthServer)

	// Add reflection service
	reflection.Register(s)

	// Handle graceful shutdown
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Graceful shutdown
	log.Println("Shutting down...")
	if registry != nil {
		// Unregister worker
		_, err := registry.client.UnregisterWorker(context.Background(), &pb.UnregisterWorkerRequest{
			WorkerId: registry.workerID,
		})
		if err != nil {
			log.Printf("Warning: Failed to unregister worker: %v", err)
		}
	}
	s.GracefulStop()
	wg.Wait()
}
