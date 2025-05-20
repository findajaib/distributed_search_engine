package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pb "search-engine/importworker"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	port = flag.Int("port", 50052, "The registry server port")
)

type registryServer struct {
	pb.UnimplementedRegistryServer
	mu      sync.RWMutex
	workers map[string]*workerInfo
}

type workerInfo struct {
	address    string
	lastSeen   time.Time
	isHealthy  bool
	jobCount   int32
	lastUpdate time.Time
	conn       *grpc.ClientConn
	client     healthpb.HealthClient
}

func newRegistryServer() *registryServer {
	return &registryServer{
		workers: make(map[string]*workerInfo),
	}
}

func (s *registryServer) RegisterWorker(ctx context.Context, req *pb.RegisterWorkerRequest) (*pb.RegisterWorkerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if worker already exists
	if existing, exists := s.workers[req.WorkerId]; exists {
		log.Printf("[INFO] Worker %s already registered, updating information", req.WorkerId)
		existing.address = req.Address
		existing.lastSeen = time.Now()
		existing.isHealthy = true
		existing.lastUpdate = time.Now()
		return &pb.RegisterWorkerResponse{}, nil
	}

	// Create connection to worker for health checks
	conn, err := grpc.Dial(req.Address, grpc.WithInsecure())
	if err != nil {
		log.Printf("[ERROR] Failed to connect to worker %s at %s: %v", req.WorkerId, req.Address, err)
		return nil, fmt.Errorf("failed to connect to worker: %w", err)
	}

	s.workers[req.WorkerId] = &workerInfo{
		address:    req.Address,
		lastSeen:   time.Now(),
		isHealthy:  true,
		jobCount:   0,
		lastUpdate: time.Now(),
		conn:       conn,
		client:     healthpb.NewHealthClient(conn),
	}

	log.Printf("[INFO] Worker registered: %s at %s", req.WorkerId, req.Address)
	return &pb.RegisterWorkerResponse{}, nil
}

func (s *registryServer) UnregisterWorker(ctx context.Context, req *pb.UnregisterWorkerRequest) (*pb.UnregisterWorkerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if worker, exists := s.workers[req.WorkerId]; exists {
		if worker.conn != nil {
			worker.conn.Close()
		}
		delete(s.workers, req.WorkerId)
		log.Printf("[INFO] Worker unregistered: %s", req.WorkerId)
	}

	return &pb.UnregisterWorkerResponse{}, nil
}

func (s *registryServer) GetWorkers(ctx context.Context, req *pb.GetWorkersRequest) (*pb.GetWorkersResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var workers []*pb.WorkerInfo
	for id, info := range s.workers {
		if info.isHealthy {
			workers = append(workers, &pb.WorkerInfo{
				WorkerId: id,
				Address:  info.address,
				JobCount: info.jobCount,
			})
		}
	}

	return &pb.GetWorkersResponse{
		Workers: workers,
	}, nil
}

func (s *registryServer) UpdateWorkerStatus(ctx context.Context, req *pb.UpdateWorkerStatusRequest) (*pb.UpdateWorkerStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if info, exists := s.workers[req.WorkerId]; exists {
		info.lastSeen = time.Now()
		info.isHealthy = req.IsHealthy
		info.jobCount = req.JobCount
		info.lastUpdate = time.Now()
		log.Printf("[DEBUG] Updated worker status: %s (healthy: %v, jobs: %d)", req.WorkerId, req.IsHealthy, req.JobCount)
	}

	return &pb.UpdateWorkerStatusResponse{}, nil
}

func (s *registryServer) startHealthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.checkWorkersHealth()
		}
	}()
}

func (s *registryServer) checkWorkersHealth() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, info := range s.workers {
		// Check if worker hasn't been seen in the last 2 minutes
		if now.Sub(info.lastSeen) > 2*time.Minute {
			log.Printf("[WARN] Worker %s marked unhealthy: no heartbeat for %v", id, now.Sub(info.lastSeen))
			info.isHealthy = false
			continue
		}

		// Check worker's health using gRPC health check
		if info.client != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := info.client.Check(ctx, &healthpb.HealthCheckRequest{})
			cancel()

			if err != nil {
				log.Printf("[WARN] Worker %s health check failed: %v", id, err)
				info.isHealthy = false
				continue
			}

			if resp.Status != healthpb.HealthCheckResponse_SERVING {
				log.Printf("[WARN] Worker %s not serving: %v", id, resp.Status)
				info.isHealthy = false
				continue
			}

			info.isHealthy = true
			log.Printf("[DEBUG] Worker %s health check passed", id)
		}
	}
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	registry := newRegistryServer()
	pb.RegisterRegistryServer(s, registry)

	// Add health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, healthServer)

	// Add reflection service
	reflection.Register(s)

	// Start health check loop
	registry.startHealthCheck()

	log.Printf("[INFO] Registry server listening on :%d", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
