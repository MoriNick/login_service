package session

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"time"
)

type Session struct {
	Id             string
	UserId         string
	LastUpdateAt   time.Time
	LastActivityAt time.Time
}

func newSession(userId string) *Session {
	return &Session{
		Id:             generateSessionId(),
		UserId:         userId,
		LastUpdateAt:   time.Now(),
		LastActivityAt: time.Now(),
	}
}

func generateSessionId() string {
	id := make([]byte, 32)

	_, err := rand.Read(id)
	if err != nil {
		log.Fatal("Session: failed to generate session id")
	}

	return base64.RawURLEncoding.EncodeToString(id)
}
