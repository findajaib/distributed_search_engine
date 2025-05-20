# Search Engine Project

## New Features (2024)


- **Robust Worker Heartbeat:**
  - Worker nodes now send regular heartbeats to the registry, ensuring they remain visible and available as long as they are running.

- **Unified Database:**
  - All services (main server and workers) use a single SQLite database file (`search_engine.db`) for consistent data access and search results.

- **Frontend Defensive Coding:**
  - The search results renderer now safely handles empty or null results, preventing UI errors and infinite spinners.
  - The HTML templates have been updated to ensure the results container exists on all relevant pages.

- **Improved Error Handling:**
  - Both backend and frontend now handle empty search results and errors gracefully, always providing a user-friendly response.

## Prerequisites
- Go (1.18+ recommended)
- [protoc](https://grpc.io/docs/protoc-installation/) (Protocol Buffers compiler)
- PowerShell (for .ps1 scripts) or Windows Command Prompt (for .bat scripts)

## Setup

1. **Clone the repository:**
   ```sh
   git clone <your-repo-url>
   cd search_engine
   ```

2. **Install Go dependencies:**
   ```sh
   go mod tidy
   ```

3. **Generate gRPC/Protobuf files:**
   ```sh
   protoc --go_out=. --go-grpc_out=. importworker/import.proto
   ```

4. **Run the application:**
   ```sh
   ./run.bat
   ```
   The script provides an interactive menu:
   - Press 1 to build all components
   - Press 2 to start all servers
     - When starting servers, you'll be prompted to specify the number of worker nodes
     - If no number is specified, it defaults to 1 worker

5. **Access the app:**
   - Open your browser and go to: [http://localhost:8080](http://localhost:8080)

## Scripts
- `.ps1` (PowerShell) and `.bat` (batch) files are tracked and can be used to automate build/run tasks.
- Example:
  ```sh
  ./run.bat
  # or
  ./run.ps1
  ```

## Notes
- Search is available without login.
- Register or login to access dashboard, history, and (if admin) data import.
- Database files (`*.db`) and generated files (`*.pb.go`) are ignored by git.

---

Feel free to update this README with more details about your project, endpoints, or usage instructions!

# Project Structure

```
.
├── cmd/
│   └── server/           # Entry point for the main web server
│       └── main.go
├── internal/
│   ├── app/              # App wiring, dependency injection, and app-wide helpers
│   │   └── app.go
│   ├── handlers/         # HTTP route handlers
│   │   ├── handlers.go
│   │   └── routes.go
│   ├── models/           # Data models and interfaces
│   │   └── models.go
│   ├── services/         # Business logic, worker manager, and service implementations
│   │   ├── services.go
│   │   └── import_jobs.go
│   ├── utils/            # Utility functions (e.g., ID generation, session helpers)
│   │   └── utility.go
│   └── database/         # Database connection and setup
│       └── database.go
├── registry/
│   └── main.go           # Worker registry service (gRPC)
├── worker/
│   └── main.go           # Worker node (gRPC)
├── templates/            # HTML templates for the web UI
│   └── *.html
├── static/               # Static assets (CSS, JS, images)
├── logs/                 # Log files for main, worker, and registry
├── go.mod, go.sum        # Go module files
├── README.md             # Project documentation
└── run.bat               # Batch script to build/run services and workers
```

## Folder/File Descriptions

- **cmd/server/main.go**: Entry point for the main web server.
- **internal/app/app.go**: Sets up the application, dependency injection, and app-wide helpers.
- **internal/handlers/**: Contains HTTP route handlers and route registration.
- **internal/models/models.go**: Data models and service interfaces.
- **internal/services/services.go**: Business logic, service implementations, and worker manager.
- **internal/services/import_jobs.go**: Tracks asynchronous import job status.
- **internal/utils/utility.go**: Utility functions (ID generation, session helpers, etc).
- **internal/database/database.go**: Database connection and setup helpers.
- **registry/main.go**: gRPC registry service for worker registration and health.
- **worker/main.go**: gRPC worker node that processes import jobs.
- **templates/**: HTML templates for the web UI.
- **static/**: Static assets (CSS, JS, images).
- **logs/**: Log files for main, worker, and registry services.
- **run.bat**: Batch script to build and run the main server, registry, and workers. 