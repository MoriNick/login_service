package user

import (
	"errors"

	"login/internals/models"
	"login/pkg/logger"
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

var (
	errStatusBadRequest = errors.New("400")
	errStatusInternal   = errors.New("500")
)

type UserService struct {
	log *logger.Logger
	UserRepository
}

func NewService(repo UserRepository, log *logger.Logger) *UserService {
	return &UserService{log, repo}
}

func (us *UserService) Registration(email, nickname, password string) (string, string, string, error) {
	candidate, err := us.SelectUserByEmail(email)
	if err != nil {
		us.log.Error("SelectUserByEmail", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	} else if candidate != nil {
		return "", "", "", errors.Join(errStatusBadRequest, errEmailExist)
	}

	candidate, err = us.SelectUserByNickname(nickname)
	if err != nil {
		us.log.Error("SelectUserByNickname", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	} else if candidate != nil {
		return "", "", "", errors.Join(errStatusBadRequest, errNicknameExist)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), salt)
	if err != nil {
		us.log.Error("GenerateFromPassword", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	}

	id, err := us.CreateUser(email, nickname, string(hash))
	if err != nil {
		us.log.Error("CreateUser", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	}

	token, err := tokens.GenerateTokens(id)
	if err != nil {
		us.log.Error("GenerateTokens", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	}

	return id, token.GetAccess(), token.GetRefresh(), nil
}

func (us *UserService) Login(param, password string) (string, string, string, error) {
	user, err := us.SelectUserByEmail(param)
	if err != nil {
		us.log.Error("SelectUserByEmail", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		user, err = us.SelectUserByNickname(param)
		if err != nil {
			us.log.Error("SelectUserByNickname", us.log.String("error:", err.Error()))
			return "", "", "", errors.Join(errStatusInternal, errInternal)
		} else if user == nil {
			return "", "", "", errors.Join(errStatusBadRequest, errUserNotFound)
		}
	}

	if cost, _ := bcrypt.Cost([]byte(user.Password)); cost != salt {
		us.log.Error("Check password", us.log.String("error:", "incorrect cost"))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", "", "", errors.Join(errStatusBadRequest, errIncorrectPassword)
	}

	token, err := tokens.GenerateTokens(user.Id)
	if err != nil {
		us.log.Error("GenerateTokens", us.log.String("error:", err.Error()))
		return "", "", "", errors.Join(errStatusInternal, errInternal)
	}

	return user.Id, token.GetAccess(), token.GetRefresh(), nil
}

func (us *UserService) GetUser(id string) (*models.User, error) {
	user, err := us.SelectUserById(id)
	if err != nil {
		us.log.Error("SelectUserById", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		return nil, errors.Join(errStatusBadRequest, errUserNotFound)
	}

	user.Password = ""

	return user, nil
}

func (us *UserService) GetAllUsers(limit, offset uint64) ([]models.User, error) {
	users, err := us.SelectAllUsers(limit, offset)
	if err != nil {
		us.log.Error("SelectAllUsers", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

func (us *UserService) RefreshPassword(email, newPassword string) (string, error) {
	user, err := us.SelectUserByEmail(email)
	if err != nil {
		us.log.Error("SelectUserByEmail", us.log.String("error:", err.Error()))
		return "", errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		return "", errors.Join(errStatusBadRequest, errIncorrectEmail)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), salt)
	if err != nil {
		us.log.Error("GenerateFromPassword", us.log.String("error:", err.Error()))
		return "", errors.Join(errStatusInternal, errInternal)
	}

	user.Password = string(hash)
	if err := us.UpdateUser(user); err != nil {
		us.log.Error("UpdateUser", us.log.String("error:", err.Error()))
		return "", errors.Join(errStatusInternal, errInternal)
	}

	return user.Id, nil
}

func (us *UserService) UpdatePassword(id string, oldPassword, newPassword string) (*models.User, error) {
	user, err := us.SelectUserById(id)
	if err != nil {
		us.log.Error("SelectUserById", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		return nil, errors.Join(errStatusBadRequest, errUserNotFound)
	}

	if cost, _ := bcrypt.Cost([]byte(user.Password)); cost != salt {
		us.log.Error("Check password", us.log.String("error:", "incorrect cost"))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return nil, errors.Join(errStatusBadRequest, errIncorrectPassword)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), salt)
	if err != nil {
		us.log.Error("GenerateFromPassword", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	user.Password = string(hash)
	if err := us.UpdateUser(user); err != nil {
		us.log.Error("UpdateUser", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	return user, nil
}

func (us *UserService) UpdateNickname(id string, newNickname string) (*models.User, error) {
	user, err := us.SelectUserById(id)
	if err != nil {
		us.log.Error("SelectUserById", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		return nil, errors.Join(errStatusBadRequest, errUserNotFound)
	}

	collision, err := us.SelectUserByNickname(newNickname)
	if err != nil {
		us.log.Error("SelectUserByNickname", us.log.String("error", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if collision != nil {
		return nil, errors.Join(errStatusBadRequest, errNicknameExist)
	}

	user.Nickname = newNickname
	if err := us.UpdateUser(user); err != nil {
		us.log.Error("UpdateUser", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	return user, nil
}

func (us *UserService) UpdateEmail(id string, newEmail string) (*models.User, error) {
	user, err := us.SelectUserById(id)
	if err != nil {
		us.log.Error("Select UserById", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if user == nil {
		return nil, errors.Join(errStatusBadRequest, errUserNotFound)
	}

	collision, err := us.SelectUserByEmail(newEmail)
	if err != nil {
		us.log.Error("SelectUserByEmail", us.log.String("error", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	} else if collision != nil {
		return nil, errors.Join(errStatusBadRequest, errEmailExist)
	}

	user.Email = newEmail
	if err := us.UpdateUser(user); err != nil {
		us.log.Error("UpdateUser", us.log.String("error:", err.Error()))
		return nil, errors.Join(errStatusInternal, errInternal)
	}

	return user, nil
}

func (us *UserService) DeleteUserService(id string) error {
	if err := us.DeleteUser(id); err != nil {
		us.log.Error("DeleteUser", us.log.String("error:", err.Error()))
		return errors.Join(errStatusInternal, errInternal)
	}

	return nil
}
