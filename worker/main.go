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
	db *sql.DB
}

type registryClient struct {
	addr     string
	conn     *grpc.ClientConn
	client   pb.RegistryClient
	workerID string
}

func (s *server) Import(ctx context.Context, job *pb.ImportJob) (*pb.ImportResult, error) {
	var successes, failures []string

	for _, item := range job.Urls {
		switch job.SourceType {
		case "direct":
			// For direct database imports, the first URL contains the source URL
			if len(job.Urls) > 0 {
				sourceURL := job.Urls[0]
				log.Printf("[DEBUG] Direct import - Title: %s, Body length: %d, Source URL: %s",
					job.Keywords[0], len(job.Keywords[1]), sourceURL)
				// Insert directly into database
				result, err := s.db.Exec("INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
					job.Keywords[0], // Use first keyword as title
					job.Keywords[1], // Use second keyword as body
					sourceURL)
				if err != nil {
					log.Printf("[ERROR] Failed to insert into database: %v", err)
					failures = append(failures, fmt.Sprintf("%s: %v", sourceURL, err))
				} else {
					lastID, _ := result.LastInsertId()
					log.Printf("[DEBUG] Successfully inserted record with ID: %d", lastID)
					successes = append(successes, sourceURL)
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
			// Save to local DB
			_, err = s.db.Exec("INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
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
				_, err := s.db.Exec("INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
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
			_, err = s.db.Exec("INSERT INTO content (title, body, source_url) VALUES (?, ?, ?)",
				result.Title, result.Content, result.URL)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item, err))
				continue
			}
			successes = append(successes, result.Title)
		}
	}

	return &pb.ImportResult{
		Successes: successes,
		Failures:  failures,
	}, nil
}

func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
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
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := pb.NewRegistryClient(conn)
	workerID := fmt.Sprintf("worker-%d", time.Now().UnixNano())

	// Register worker
	_, err = client.RegisterWorker(context.Background(), &pb.RegisterWorkerRequest{
		WorkerId: workerID,
		Address:  workerAddr,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &registryClient{
		addr:     addr,
		conn:     conn,
		client:   client,
		workerID: workerID,
	}, nil
}

func startHeartbeat(reg *registryClient) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			_, err := reg.client.UpdateWorkerStatus(context.Background(), &pb.UpdateWorkerStatusRequest{
				WorkerId:  reg.workerID,
				IsHealthy: true,
				JobCount:  0, // Optionally, track actual job count
			})
			if err != nil {
				log.Printf("Failed to send heartbeat: %v", err)
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

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterImportWorkerServer(s, &server{db: db})

	// Add health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, healthServer)

	// Add reflection service
	reflection.Register(s)

	// Register with registry
	workerAddr := fmt.Sprintf("localhost:%d", *port)
	registry, err := registerWithRegistry(*registry, workerAddr)
	if err != nil {
		log.Printf("Warning: Failed to register with registry: %v", err)
	} else {
		defer registry.conn.Close()
		startHeartbeat(registry)
	}

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
