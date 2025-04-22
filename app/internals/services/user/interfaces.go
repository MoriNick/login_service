package user

import "login/internals/models"

//go:generate mockgen -source=interfaces.go -destination=mock/user_repository.go
type UserRepository interface {
	CreateUser(email, nickname, password string) (string, error)
	SelectUserById(id string) (*models.User, error)
	SelectAllUsers(limit, offset uint64) ([]models.User, error)
	SelectUserByEmail(email string) (*models.User, error)
	SelectUserByNickname(nickname string) (*models.User, error)
	UpdateUser(user *models.User) error
	DeleteUser(id string) error
}
