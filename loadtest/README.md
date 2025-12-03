## Local load test and profiling

This suite runs a small k6 scenario and keeps the load generator constrained to **1 vCPU and 512MiB** by default. By default, it targets a local mock server so no real backend calls are made (zero cost).

### Prereqs
- Start the mock gateway (default target) to avoid hitting real services:
  ```bash
  go run loadtest/mock_server.go
  ```
- If you intentionally want to hit the real gateway, start the service (e.g. `ENABLE_PPROF=true go run ./...` or `ENABLE_PPROF=true docker compose up --build`) **and override** `MOCK_MODE=false BASE_URL=http://127.0.0.1:8000`.
- Tokens: when using the mock, no real tokens are needed; when pointing at the real gateway, export `PUBLIC_TOKEN`, optionally `ADMIN_TOKEN` and `INTEGRITY_TOKEN` (required if `MOCK_MODE=false`).
- Docker available to pull/run the k6 image.

### Run the load test
```bash
# Defaults: mock target on 127.0.0.1:18000, 1 vCPU, 512MiB, 2m duration, rate 10/s public + 2/s admin.
loadtest/run_local.sh
```

Target the real gateway (opt-in):
```bash
MOCK_MODE=false \
BASE_URL=http://127.0.0.1:8000 \
PUBLIC_TOKEN=ey... \
ADMIN_TOKEN=ey... \
loadtest/run_local.sh
```

If you need a different host name (e.g., Docker Desktop on macOS/Windows), set `HOST_ADDR=host.docker.internal` when running the script.

### Fixed-iterations run (20k requests)
To run a finite load of 20,000 requests and see how long it completes under the resource cap:
```bash
go run loadtest/mock_server.go &  # optional: mock target

SCRIPT=eac_report_20k.js \
ITERATIONS=20000 \
VUS=200 \
loadtest/run_local.sh
```

Adjust `VUS` to change parallelism and `MAX_DURATION` (env) to cap total time. Keep `MOCK_MODE=true` (default) to avoid real calls, or set `MOCK_MODE=false BASE_URL=http://127.0.0.1:8000 PUBLIC_TOKEN=...` to hit the live gateway.

Useful overrides:
- `BASE_PATH` if the gateway is mounted under a prefix (e.g. `/anti-cheat`).
- `DURATION`, `RATE_PUBLIC`, `RATE_ADMIN`, `VUS`, `MAX_VUS` to tune pressure.
- `CPUS`, `MEMORY` to change resource limits for the load generator.

The script mounts `loadtest/eac_report_load.js` into a `grafana/k6` container and uses `--network host` so the gateway on `localhost:8000` is reachable.

### Profiling while load runs
Expose pprof by starting the service with `ENABLE_PPROF=true`. Profiles are served on the metrics port (default `:8080`).

CPU profile for 30s:
```bash
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30
```

Heap profile snapshot:
```bash
go tool pprof http://localhost:8080/debug/pprof/heap
```

To visualize, add `-http=:0` to either command and open the reported URL. Metrics remain available at `http://localhost:8080/metrics`.
