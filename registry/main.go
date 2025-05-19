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
}

func newRegistryServer() *registryServer {
	return &registryServer{
		workers: make(map[string]*workerInfo),
	}
}

func (s *registryServer) RegisterWorker(ctx context.Context, req *pb.RegisterWorkerRequest) (*pb.RegisterWorkerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workers[req.WorkerId] = &workerInfo{
		address:    req.Address,
		lastSeen:   time.Now(),
		isHealthy:  true,
		jobCount:   0,
		lastUpdate: time.Now(),
	}

	log.Printf("Worker registered: %s at %s", req.WorkerId, req.Address)
	return &pb.RegisterWorkerResponse{}, nil
}

func (s *registryServer) UnregisterWorker(ctx context.Context, req *pb.UnregisterWorkerRequest) (*pb.UnregisterWorkerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.workers[req.WorkerId]; exists {
		delete(s.workers, req.WorkerId)
		log.Printf("Worker unregistered: %s", req.WorkerId)
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
	}

	return &pb.UpdateWorkerStatusResponse{}, nil
}

func (s *registryServer) startHealthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.mu.Lock()
			now := time.Now()
			for id, info := range s.workers {
				// Mark worker as unhealthy if not seen in last 2 minutes
				if now.Sub(info.lastSeen) > 2*time.Minute {
					info.isHealthy = false
					log.Printf("Worker marked unhealthy: %s", id)
				}
			}
			s.mu.Unlock()
		}
	}()
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

	log.Printf("Registry server listening on :%d", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
