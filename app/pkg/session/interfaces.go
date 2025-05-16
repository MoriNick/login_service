package session

import (
	"context"
	"time"
)

//go:generate mockgen -package session -source=interfaces.go -destination=store_mock.go
type SessionStore interface {
	ReadBySessionId(ctx context.Context, sessionId string) (*Session, error)
	ReadByUserId(ctx context.Context, userId string) (*Session, error)
	Write(ctx context.Context, session *Session) error
	Update(ctx context.Context, session *Session) error
	Destroy(ctx context.Context, sessionId string) error
	GC(ctx context.Context, absoluteExpiration time.Duration) error
}
