package main

import (
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
}

func respondWithError(responseWriter http.ResponseWriter, code int, message string) {
	type responseBody struct {
		Err string `json:"error"`
	}

	respBody := responseBody{}

	respBody.Err = message
	data, _ := json.Marshal(respBody)

	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(code)
	responseWriter.Write(data)
}

func respondWithJSON(responseWriter http.ResponseWriter, code int, payload interface{}) {
	data, _ := json.Marshal(payload)

	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(code)
	responseWriter.Write(data)
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

func validateChirpHandler(responseWriter http.ResponseWriter, request *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	type responseBody struct {
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}
	respBody := responseBody{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(responseWriter, 400, "Chirp is too long")
		return
	}

	bodyWords := strings.Split(params.Body, " ")
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	cleanBodySlice := []string{}

	for _, word := range bodyWords {
		if slices.Contains(profaneWords, strings.ToLower(word)) {
			cleanBodySlice = append(cleanBodySlice, "****")
			continue
		}

		cleanBodySlice = append(cleanBodySlice, word)
	}

	respBody.CleanedBody = strings.Join(cleanBodySlice, " ")

	respondWithJSON(responseWriter, 200, respBody)
}

func (config *apiConfig) hitsHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	responseWriter.WriteHeader(200)
	responseWriter.Write(fmt.Appendf(nil, `
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>
	`, config.fileserverHits.Load()))
}

func (config *apiConfig) resetHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	config.fileserverHits.Store(0)
	responseWriter.WriteHeader(200)
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")

	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Fatal("Error connecting to database")
	}

	var config apiConfig

	config.dbQueries = database.New(db)

	mux := http.NewServeMux()

	mux.Handle("/app/", config.middlewareMetricsInc(appFileServerHandler()))

	mux.HandleFunc("GET /api/healthz", healthHandler)

	mux.HandleFunc("GET /admin/metrics", config.hitsHandler)
	mux.HandleFunc("POST /admin/reset", config.resetHandler)

	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err = server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
