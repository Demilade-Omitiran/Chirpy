package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 11)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(hash, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return err
	}

	return nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "chirpy",
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte(tokenSecret))

	if err != nil {
		return "", err
	}

	return signedString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.UUID{}, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)

	if !ok {
		return uuid.UUID{}, fmt.Errorf("invalid token")
	}

	userIDString, err := claims.GetSubject()

	if err != nil {
		return uuid.UUID{}, err
	}

	userID, err := uuid.Parse(userIDString)

	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	token, err := getAuthToken(headers, "Bearer")

	if err != nil {
		return "", err
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	rand.Read(key)

	encodedStr := hex.EncodeToString(key)

	return encodedStr, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	token, err := getAuthToken(headers, "ApiKey")

	if err != nil {
		return "", err
	}

	return token, nil
}

func getAuthToken(headers http.Header, firstAuthWord string) (string, error) {
	authHeader := strings.TrimSpace(headers.Get("Authorization"))

	splitAuthHeader := strings.Split(authHeader, " ")

	if len(splitAuthHeader) != 2 || splitAuthHeader[0] != firstAuthWord {
		return "", fmt.Errorf("invalid auth header")
	}

	return splitAuthHeader[1], nil
}
