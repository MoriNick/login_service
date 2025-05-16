package user

import (
	"context"
	"log/slog"

	"login/internals/models"

	"golang.org/x/crypto/argon2"
)

var argonSalt = []byte("TH-WEhvHmrtd4tfVkuNUDjP2XeHw4hfX25X3bwhKeOU")

var (
	errEmailExist        = newServiceClientError("email already exist")
	errNicknameExist     = newServiceClientError("nickname already exist")
	errUserNotFound      = newServiceClientError("user not found")
	errIncorrectPassword = newServiceClientError("incorrect password")
	errIncorrectEmail    = newServiceClientError("incorrect email")
)

type UserService struct {
	log  *slog.Logger
	repo UserRepository
}

func NewService(repo UserRepository, log *slog.Logger) *UserService {
	return &UserService{log, repo}
}

func (us *UserService) Registration(ctx context.Context, email, nickname, password string) (string, error) {
	candidate, err := us.repo.SelectUserByEmail(ctx, email)
	if err != nil {
		return "", newServiceInternalError("SelectUserByEmail", err)
	} else if candidate != nil {
		return "", errEmailExist
	}

	candidate, err = us.repo.SelectUserByNickname(ctx, nickname)
	if err != nil {
		return "", newServiceInternalError("SelectUserByNickname", err)
	} else if candidate != nil {
		return "", errNicknameExist
	}

	hash := argon2.Key([]byte(password), argonSalt, 3, 32*1024, 2, 32)

	id, err := us.repo.CreateUser(ctx, email, nickname, string(hash))
	if err != nil {
		return "", newServiceInternalError("CreateUser", err)
	}

	return id, nil
}

func (us *UserService) Login(ctx context.Context, param, password string) (string, error) {
	user, err := us.repo.SelectUserByEmail(ctx, param)
	if err != nil {
		return "", newServiceInternalError("SelectUserByEmail", err)
	}

	if user == nil {
		user, err = us.repo.SelectUserByNickname(ctx, param)
		if err != nil {
			return "", newServiceInternalError("SelectUserByNickname", err)
		} else if user == nil {
			return "", errUserNotFound
		}
	}

	hash := argon2.Key([]byte(password), argonSalt, 3, 32*1024, 2, 32)
	if user.Password != string(hash) {
		return "", errIncorrectPassword
	}

	return user.Id, nil
}

func (us *UserService) GetUser(ctx context.Context, id string) (*models.User, error) {
	user, err := us.repo.SelectUserById(ctx, id)
	if err != nil {
		return nil, newServiceInternalError("SelectUserById", err)
	} else if user == nil {
		return nil, errUserNotFound
	}

	return user, nil
}

func (us *UserService) GetAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error) {
	users, err := us.repo.SelectAllUsers(ctx, limit, offset)
	if err != nil {
		return nil, newServiceInternalError("SelectAllUsers", err)
	}

	return users, nil
}

func (us *UserService) UpdatePassword(ctx context.Context, id string, oldPassword, newPassword string) (*models.User, error) {
	user, err := us.repo.SelectUserById(ctx, id)
	if err != nil {
		return nil, newServiceInternalError("SelectUserById", err)
	} else if user == nil {
		return nil, errUserNotFound
	}

	hash := argon2.Key([]byte(oldPassword), argonSalt, 3, 32*1024, 2, 32)
	if user.Password != string(hash) {
		return nil, errIncorrectPassword
	}

	hash = argon2.Key([]byte(newPassword), argonSalt, 3, 32*1024, 2, 32)

	user.Password = string(hash)
	if err := us.repo.UpdateUser(ctx, user); err != nil {
		return nil, newServiceInternalError("UpdateUser", err)
	}

	return user, nil
}

func (us *UserService) UpdateNickname(ctx context.Context, id string, newNickname string) (*models.User, error) {
	user, err := us.repo.SelectUserById(ctx, id)
	if err != nil {
		return nil, newServiceInternalError("SelectUserById", err)
	} else if user == nil {
		return nil, errUserNotFound
	}

	collision, err := us.repo.SelectUserByNickname(ctx, newNickname)
	if err != nil {
		return nil, newServiceInternalError("SelectUserByNickname", err)
	} else if collision != nil {
		return nil, errNicknameExist
	}

	user.Nickname = newNickname
	if err := us.repo.UpdateUser(ctx, user); err != nil {
		return nil, newServiceInternalError("UpdateUser", err)
	}

	return user, nil
}

func (us *UserService) UpdateEmail(ctx context.Context, id string, newEmail string) (*models.User, error) {
	user, err := us.repo.SelectUserById(ctx, id)
	if err != nil {
		return nil, newServiceInternalError("SelectUserById", err)
	} else if user == nil {
		return nil, errUserNotFound
	}

	collision, err := us.repo.SelectUserByEmail(ctx, newEmail)
	if err != nil {
		return nil, newServiceInternalError("SelectUserByEmail", err)
	} else if collision != nil {
		return nil, errEmailExist
	}

	user.Email = newEmail
	if err := us.repo.UpdateUser(ctx, user); err != nil {
		return nil, newServiceInternalError("UpdateUser", err)
	}

	return user, nil
}

func (us *UserService) DeleteUserService(ctx context.Context, id string) error {
	if err := us.repo.DeleteUser(ctx, id); err != nil {
		return newServiceInternalError("DeleteUser", err)
	}

	return nil
}
