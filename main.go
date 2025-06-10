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

func (config *apiConfig) validateAccessToken(header http.Header) (uuid.UUID, error) {
	token, err := auth.GetBearerToken(header)

	if err != nil {
		return uuid.UUID{}, err
	}

	userID, err := auth.ValidateJWT(token, config.jwtSecret)

	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type responseBody struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
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

	token, err := auth.MakeJWT(user.ID, config.jwtSecret)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	err = config.dbQueries.CreateRefreshToken(request.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	respBody.ID = user.ID
	respBody.CreatedAt = user.CreatedAt
	respBody.UpdatedAt = user.UpdatedAt
	respBody.Email = user.Email
	respBody.Token = token
	respBody.RefreshToken = refreshToken

	respondWithJSON(responseWriter, 200, respBody)
}

func (config *apiConfig) updateUserHandler(responseWriter http.ResponseWriter, request *http.Request) {
	userID, err := config.validateAccessToken(request.Header)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

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

	if err := decoder.Decode(&params); err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}
}

func (config *apiConfig) refreshHandler(responseWriter http.ResponseWriter, request *http.Request) {
	refreshToken, err := auth.GetBearerToken(request.Header)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	refreshTokenRecord, err := config.dbQueries.GetRefreshToken(request.Context(), refreshToken)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	if refreshTokenRecord.RevokedAt.Valid {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	if time.Now().Compare(refreshTokenRecord.ExpiresAt) >= 0 {
		respondWithError(responseWriter, 401, "Expired token. Please log in to perform this action")
		return
	}

	token, err := auth.MakeJWT(refreshTokenRecord.UserID, config.jwtSecret)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	type responseBody struct {
		Token string `json:"token"`
	}

	payload := responseBody{
		Token: token,
	}

	respondWithJSON(responseWriter, 200, payload)
}

func (config *apiConfig) revokeHandler(responseWriter http.ResponseWriter, request *http.Request) {
	refreshToken, err := auth.GetBearerToken(request.Header)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	_, err = config.dbQueries.GetRefreshToken(request.Context(), refreshToken)

	if err != nil {
		respondWithError(responseWriter, 401, "Please log in to perform this action")
		return
	}

	err = config.dbQueries.RevokeRefreshToken(request.Context(), refreshToken)

	if err != nil {
		respondWithError(responseWriter, 500, "Something went wrong")
		return
	}

	responseWriter.WriteHeader(204)
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

	userID, err := config.validateAccessToken(request.Header)

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

	mux.HandleFunc("POST /api/refresh", config.refreshHandler)
	mux.HandleFunc("POST /api/revoke", config.revokeHandler)

	mux.HandleFunc("PUT /api/users", config.revokeHandler)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	err = server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
