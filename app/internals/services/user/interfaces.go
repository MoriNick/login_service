package user

import (
	"context"
	"login/internals/models"
)

//go:generate mockgen -source=interfaces.go -destination=mock/user_repository.go
type UserRepository interface {
	CreateUser(ctx context.Context, email, nickname, password string) (string, error)
	SelectUserById(ctx context.Context, id string) (*models.User, error)
	SelectAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error)
	SelectUserByEmail(ctx context.Context, email string) (*models.User, error)
	SelectUserByNickname(ctx context.Context, nickname string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
}
