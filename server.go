package main

import (
	"encoding/json"
	"net/http"
)

// Setup version endpoint for deployment validation.
func newRouter() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", handleVersion)
	return mux
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
