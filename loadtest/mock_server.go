package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type response struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

func main() {
	addr := getEnv("ADDR", ":18000")
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{
			Status: "ok",
			Path:   r.URL.Path,
		})
	}

	mux.HandleFunc("/v1/public/anti-cheat/eac/report", handler)
	mux.HandleFunc("/v1/public/anti-cheat/eac/integrity/report", handler)
	mux.HandleFunc("/v1/admin/anti-cheat/eac/report", handler)

	log.Printf("Mock gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func getEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	return def
}
