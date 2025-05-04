package user

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"login/internals/models"
	"login/pkg/tokens"

	"golang.org/x/crypto/bcrypt"
)

var salt = bcrypt.DefaultCost

var (
	errInternal          = errors.New("Internal error")
	errEmailExist        = errors.New("Email already exist")
	errNicknameExist     = errors.New("Nickname already exist")
	errUserNotFound      = errors.New("User not found")
	errIncorrectPassword = errors.New("Incorrect password")
	errIncorrectEmail    = errors.New("Incorrect email")
)

type UserService struct {
	log *slog.Logger
	UserRepository
}

func NewService(repo UserRepository, log *slog.Logger) *UserService {
	return &UserService{log, repo}
}

func (us *UserService) Registration(ctx context.Context, email, nickname, password string) (string, string, string, error) {
	candidate, err := us.SelectUserByEmail(ctx, email)
	if err != nil {
		return "", "", "", &ServiceError{Name: "SelectUserByEmail", ClientMessage: errInternal.Error(), Err: err}
	} else if candidate != nil {
		return "", "", "", &ServiceError{Name: "ClientError", ClientMessage: errEmailExist.Error(), Err: nil}
	}

	candidate, err = us.SelectUserByNickname(ctx, nickname)
	if err != nil {
		return "", "", "", &ServiceError{Name: "SelectUserByNickname", ClientMessage: errInternal.Error(), Err: err}
	} else if candidate != nil {
		return "", "", "", &ServiceError{Name: "ClientError", ClientMessage: errNicknameExist.Error(), Err: nil}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), salt)
	if err != nil {
		return "", "", "", &ServiceError{Name: "GenerateFromPassword", ClientMessage: errInternal.Error(), Err: err}
	}

	id, err := us.CreateUser(ctx, email, nickname, string(hash))
	if err != nil {
		return "", "", "", &ServiceError{Name: "CreateUser", ClientMessage: errInternal.Error(), Err: err}
	}

	token, err := tokens.GenerateTokens(id)
	if err != nil {
		return "", "", "", &ServiceError{Name: "GenerateTokens", ClientMessage: errInternal.Error(), Err: err}
	}

	return id, token.GetAccess(), token.GetRefresh(), nil
}

func (us *UserService) Login(ctx context.Context, param, password string) (string, string, string, error) {
	user, err := us.SelectUserByEmail(ctx, param)
	if err != nil {
		return "", "", "", &ServiceError{Name: "SelectUserByEmail", ClientMessage: errInternal.Error(), Err: err}
	} else if user == nil {
		user, err = us.SelectUserByNickname(ctx, param)
		if err != nil {
			return "", "", "", &ServiceError{Name: "SelectUserByNickname", ClientMessage: errInternal.Error(), Err: err}
		} else if user == nil {
			return "", "", "", &ServiceError{Name: "ClientError", ClientMessage: errUserNotFound.Error(), Err: nil}
		}
	}

	if cost, _ := bcrypt.Cost([]byte(user.Password)); cost != salt {
		return "", "", "", &ServiceError{Name: "Cost", ClientMessage: errInternal.Error(), Err: fmt.Errorf("incorrect cost for check password")}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", "", "", &ServiceError{Name: "ClientError", ClientMessage: errIncorrectPassword.Error(), Err: nil}
	}

	token, err := tokens.GenerateTokens(user.Id)
	if err != nil {
		return "", "", "", &ServiceError{Name: "GenerateTokens", ClientMessage: errInternal.Error(), Err: err}
	}

	return user.Id, token.GetAccess(), token.GetRefresh(), nil
}

func (us *UserService) GetUser(ctx context.Context, id string) (*models.User, error) {
	user, err := us.SelectUserById(ctx, id)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserById", ClientMessage: errInternal.Error(), Err: err}
	} else if user == nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errUserNotFound.Error(), Err: nil}
	}

	user.Password = ""

	return user, nil
}

func (us *UserService) GetAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error) {
	users, err := us.SelectAllUsers(ctx, limit, offset)
	if err != nil {
		return nil, &ServiceError{Name: "SelectAllUsers", ClientMessage: errInternal.Error(), Err: err}
	}

	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

func (us *UserService) UpdatePassword(ctx context.Context, id string, oldPassword, newPassword string) (*models.User, error) {
	user, err := us.SelectUserById(ctx, id)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserById", ClientMessage: errInternal.Error(), Err: err}
	} else if user == nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errUserNotFound.Error(), Err: nil}
	}

	if cost, _ := bcrypt.Cost([]byte(user.Password)); cost != salt {
		return nil, &ServiceError{Name: "Cost", ClientMessage: errInternal.Error(), Err: fmt.Errorf("incorrect cost for check password")}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errIncorrectPassword.Error(), Err: nil}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), salt)
	if err != nil {
		return nil, &ServiceError{Name: "GenerateFromPassword", ClientMessage: errInternal.Error(), Err: err}
	}

	user.Password = string(hash)
	if err := us.UpdateUser(ctx, user); err != nil {
		return nil, &ServiceError{Name: "UpdateUser", ClientMessage: errInternal.Error(), Err: err}
	}

	return user, nil
}

func (us *UserService) UpdateNickname(ctx context.Context, id string, newNickname string) (*models.User, error) {
	user, err := us.SelectUserById(ctx, id)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserById", ClientMessage: errInternal.Error(), Err: err}
	} else if user == nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errUserNotFound.Error(), Err: nil}
	}

	collision, err := us.SelectUserByNickname(ctx, newNickname)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserByNickname", ClientMessage: errInternal.Error(), Err: err}
	} else if collision != nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errNicknameExist.Error(), Err: nil}
	}

	user.Nickname = newNickname
	if err := us.UpdateUser(ctx, user); err != nil {
		return nil, &ServiceError{Name: "UpdateUser", ClientMessage: errInternal.Error(), Err: err}
	}

	return user, nil
}

func (us *UserService) UpdateEmail(ctx context.Context, id string, newEmail string) (*models.User, error) {
	user, err := us.SelectUserById(ctx, id)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserById", ClientMessage: errInternal.Error(), Err: err}
	} else if user == nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errUserNotFound.Error(), Err: nil}
	}

	collision, err := us.SelectUserByEmail(ctx, newEmail)
	if err != nil {
		return nil, &ServiceError{Name: "SelectUserByEmail", ClientMessage: errInternal.Error(), Err: err}
	} else if collision != nil {
		return nil, &ServiceError{Name: "ClientError", ClientMessage: errEmailExist.Error(), Err: nil}
	}

	user.Email = newEmail
	if err := us.UpdateUser(ctx, user); err != nil {
		return nil, &ServiceError{Name: "UpdateUser", ClientMessage: errInternal.Error(), Err: err}
	}

	return user, nil
}

func (us *UserService) DeleteUserService(ctx context.Context, id string) error {
	if err := us.DeleteUser(ctx, id); err != nil {
		return &ServiceError{Name: "DeleteUser", ClientMessage: errInternal.Error(), Err: err}
	}

	return nil
}
