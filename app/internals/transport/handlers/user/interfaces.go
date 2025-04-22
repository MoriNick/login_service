package user

import "login/internals/models"

//go:generate mockgen -source ./interfaces.go -destination ./mock/user_service.go
type UserService interface {
	Registration(email, nickname, password string) (string, string, string, error)
	Login(param, password string) (string, string, string, error)
	GetUser(id string) (*models.User, error)
	GetAllUsers(limit, offset uint64) ([]models.User, error)
	RefreshPassword(email, newPassword string) (string, error)
	UpdatePassword(id string, oldPassword, newPassword string) (*models.User, error)
	UpdateNickname(id string, newNickname string) (*models.User, error)
	UpdateEmail(id string, newEmail string) (*models.User, error)
	DeleteUserService(id string) error
}
