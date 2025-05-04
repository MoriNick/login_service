package user

import (
	"context"
	"login/internals/models"
)

//go:generate mockgen -source ./interfaces.go -destination ./mock/user_service.go
type UserService interface {
	Registration(ctx context.Context, email, nickname, password string) (string, string, string, error)
	Login(ctx context.Context, param, password string) (string, string, string, error)
	GetUser(ctx context.Context, id string) (*models.User, error)
	GetAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error)
	UpdatePassword(ctx context.Context, id, oldPassword, newPassword string) (*models.User, error)
	UpdateNickname(ctx context.Context, id, newNickname string) (*models.User, error)
	UpdateEmail(ctx context.Context, id, newEmail string) (*models.User, error)
	DeleteUserService(ctx context.Context, id string) error
}
