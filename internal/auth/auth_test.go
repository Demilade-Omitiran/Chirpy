package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTFunctions(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "someToken"
	expiresIn := 2 * time.Minute

	token, err := MakeJWT(userID, tokenSecret, expiresIn)

	if err != nil {
		t.Error(err.Error())
		return
	}

	retrievedUserID, err := ValidateJWT(token, tokenSecret)

	if err != nil {
		t.Error(err.Error())
		return
	}

	if retrievedUserID != userID {
		t.Errorf("wrong userID")
		return
	}

	_, err = ValidateJWT(token, "tokenSecret")

	if err == nil {
		t.Error("wrong token secret working for some reason")
		return
	}
}
