package main

import (
	"chirpy/internal/auth"
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
	"time"

	"github.com/google/uuid"

	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
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

func (config *apiConfig) resetHandler(responseWriter http.ResponseWriter, request *http.Request) {
	if config.platform == "dev" {
		responseWriter.WriteHeader(403)
		return
	}

	config.fileserverHits.Store(0)

	err := config.dbQueries.Reset(request.Context())

	if err != nil {
		responseWriter.WriteHeader(500)
		return
	}

	responseWriter.WriteHeader(200)
}

func (config *apiConfig) userHandler(responseWriter http.ResponseWriter, request *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}
	respBody := responseBody{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	createdUser, err := config.dbQueries.CreateUser(request.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})

	if err != nil {
		respondWithError(responseWriter, 400, err.Error())
		return
	}

	respBody.ID = createdUser.ID
	respBody.CreatedAt = createdUser.CreatedAt
	respBody.UpdatedAt = createdUser.UpdatedAt
	respBody.Email = createdUser.Email

	respondWithJSON(responseWriter, 201, respBody)
}

func (config *apiConfig) loginHandler(responseWriter http.ResponseWriter, request *http.Request) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}
	respBody := responseBody{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	user, err := config.dbQueries.GetUserByEmail(request.Context(), params.Email)

	if err != nil {
		respondWithError(responseWriter, 401, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, params.Password)

	if err != nil {
		respondWithError(responseWriter, 401, "Incorrect email or password")
		return
	}

	var tokenExpiry time.Duration

	if params.ExpiresInSeconds == 0 {
		tokenExpiry = 1 * time.Hour
	} else {
		tokenExpiry = time.Duration(params.ExpiresInSeconds) * time.Second
	}

	token, err := auth.MakeJWT(user.ID, config.jwtSecret, tokenExpiry)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	respBody.ID = user.ID
	respBody.CreatedAt = user.CreatedAt
	respBody.UpdatedAt = user.UpdatedAt
	respBody.Email = user.Email
	respBody.Token = token

	respondWithJSON(responseWriter, 200, respBody)
}

func (config *apiConfig) chirpHandler(responseWriter http.ResponseWriter, request *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	token, err := auth.GetBearerToken(request.Header)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	userID, err := auth.ValidateJWT(token, config.jwtSecret)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	decoder := json.NewDecoder(request.Body)
	params := parameters{}

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

	cleanedBody := strings.Join(cleanBodySlice, " ")

	chirp, err := config.dbQueries.CreateChirp(request.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	})

	if err != nil {
		respondWithError(responseWriter, 400, err.Error())
		return
	}

	respondWithJSON(responseWriter, 201, responseBody(chirp))
}

func (config *apiConfig) getChirpsHandler(responseWriter http.ResponseWriter, request *http.Request) {
	type chirpJson struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	responseBody := []chirpJson{}

	chirps, err := config.dbQueries.GetChirps(request.Context())

	if err != nil {
		respondWithError(responseWriter, 400, err.Error())
		return
	}

	for _, chirp := range chirps {
		responseBody = append(responseBody, chirpJson(chirp))
	}

	respondWithJSON(responseWriter, 200, responseBody)
}

func (config *apiConfig) getChirpByIDHandler(responseWriter http.ResponseWriter, request *http.Request) {
	param := request.PathValue("chirpID")

	if param == "" {
		respondWithError(responseWriter, 404, "chirpID is required")
		return
	}

	type responseBody struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	chirpID, err := uuid.Parse(param)

	if err != nil {
		respondWithError(responseWriter, 404, "invalid chirpID")
		return
	}

	chirp, err := config.dbQueries.GetChirpByID(request.Context(), chirpID)

	if err != nil {
		respondWithError(responseWriter, 404, err.Error())
		return
	}

	respondWithJSON(responseWriter, 200, responseBody(chirp))
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

	config.platform = os.Getenv("PLATFORM")

	config.jwtSecret = os.Getenv("JWT_SECRET")

	mux := http.NewServeMux()

	mux.Handle("/app/", config.middlewareMetricsInc(appFileServerHandler()))

	mux.HandleFunc("GET /api/healthz", healthHandler)

	mux.HandleFunc("GET /admin/metrics", config.hitsHandler)
	mux.HandleFunc("POST /admin/reset", config.resetHandler)

	mux.HandleFunc("POST /api/chirps", config.chirpHandler)
	mux.HandleFunc("GET /api/chirps", config.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", config.getChirpByIDHandler)

	mux.HandleFunc("POST /api/users", config.userHandler)
	mux.HandleFunc("POST /api/login", config.loginHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err = server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
