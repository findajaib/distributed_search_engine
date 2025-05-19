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
   # If you have a script
   ./generate.ps1
   # Or manually
   protoc --go_out=. --go-grpc_out=. importworker/import.proto
   ```

4. **Build the project:**
   ```sh
   ./build.ps1
   # or
   ./build.bat
   # or manually
   go build ./...
   ```

5. **Run the services:**
   - **Main server:**
     ```sh
     go run cmd/main/main.go
     ```
   - **Registry server:**
     ```sh
     go run cmd/registry/main.go
     ```
   - **Worker server:**
     ```sh
     go run cmd/worker/main.go
     ```
   - Or use your batch/PowerShell scripts to start all services.

6. **Access the app:**
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