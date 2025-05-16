package user

import (
	"context"
	"log/slog"
	"login/internals/models"
	"login/pkg/session"
	"net/http"
)

//go:generate mockgen -source ./interfaces.go -destination ./mock/mocks.go
type UserService interface {
	Registration(ctx context.Context, email, nickname, password string) (string, error)
	Login(ctx context.Context, param, password string) (string, error)
	GetUser(ctx context.Context, id string) (*models.User, error)
	GetAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error)
	UpdatePassword(ctx context.Context, id, oldPassword, newPassword string) (*models.User, error)
	UpdateNickname(ctx context.Context, id, newNickname string) (*models.User, error)
	UpdateEmail(ctx context.Context, id, newEmail string) (*models.User, error)
	DeleteUserService(ctx context.Context, id string) error
}

type SessionManager interface {
	CreateAndSaveSession(ctx context.Context, userId string) (*session.Session, error)
	LoadSession(ctx context.Context, userId string) (*session.Session, error)
	DestroySession(ctx context.Context, sessionId string) error
	GetSessionCookie(r *http.Request) *http.Cookie
	SetUpdatedSessionCookie(w http.ResponseWriter, sessionId string)
	SetDeadSessionCookie(w http.ResponseWriter)
	GetSessionFromContext(r *http.Request) *session.Session
	AuthMiddleware(log *slog.Logger) func(http.Handler) http.Handler
}
