package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (config *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		config.fileserverHits.Add(1)
		next.ServeHTTP(responseWriter, request)
	})
}

func appFileServerHandler() http.Handler {
	return http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
}

func healthHandler(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
	responseWriter.WriteHeader(200)
	responseWriter.Write([]byte("OK"))
}

func (config *apiConfig) hitsHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	responseWriter.WriteHeader(200)
	responseWriter.Write(fmt.Appendf(nil, "Hits: %v", config.fileserverHits.Load()))
}

func (config *apiConfig) resetHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	config.fileserverHits.Store(0)
	responseWriter.WriteHeader(200)
}

func main() {
	var config apiConfig

	mux := http.NewServeMux()

	mux.Handle("/app/", config.middlewareMetricsInc(appFileServerHandler()))

	mux.HandleFunc("GET /api/healthz", healthHandler)

	mux.HandleFunc("GET /api/metrics", config.hitsHandler)
	mux.HandleFunc("POST /api/reset", config.resetHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err := server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
