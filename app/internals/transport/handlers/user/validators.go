package user

import (
	"errors"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var (
	errInvalidEmail     = errors.New("Invalid email")
	errInvalidNickname  = errors.New("Invalid nickname")
	errInvalidPassword  = errors.New("Invalid password")
	errInvalidParameter = errors.New("Invalid email/nickname")
	errInvalidUserId    = errors.New("Invalid user id")
)

var validate *validator.Validate

func InitValidator() error {
	nicknameRegexp, err := regexp.Compile("^[a-zA-Z][a-zA-Z0-9]{3,14}$")
	if err != nil {
		return err
	}

	validate = validator.New(validator.WithRequiredStructEnabled())
	_ = validate.RegisterValidation("nickname", func(fl validator.FieldLevel) bool {
		return nicknameRegexp.MatchString(fl.Field().String())
	})
	_ = validate.RegisterValidation("password", func(fl validator.FieldLevel) bool {
		return len(fl.Field().String()) > 7
	})

	return nil
}

func validateUserId(id string) error {
	if err := validate.Var(id, "uuid4"); err != nil {
		return errInvalidUserId
	}
	return nil
}

func validateEmail(email string) error {
	if err := validate.Var(email, "email"); err != nil {
		return errInvalidEmail
	}
	return nil
}

func validateNickname(nickname string) error {
	if err := validate.Var(nickname, "nickname"); err != nil {
		return errInvalidNickname
	}
	return nil
}

func validatePassword(password string) error {
	if err := validate.Var(password, "password"); err != nil {
		return errInvalidPassword
	}
	return nil
}

func validateRegistration(re *registrationEntity) error {
	if err := validateEmail(re.Email); err != nil {
		return err
	}
	if err := validateNickname(re.Nickname); err != nil {
		return err
	}
	if err := validatePassword(re.Password); err != nil {
		return err
	}
	return nil
}

func validateLogin(le *loginEntity) error {
	if err := validateEmail(le.Param); err != nil {
		if err = validateNickname(le.Param); err != nil {
			return errInvalidParameter
		}
	}
	if err := validatePassword(le.Password); err != nil {
		return err
	}
	return nil
}

func validateRefreshPassword(rp *refreshPassword) error {
	if err := validateEmail(rp.Email); err != nil {
		return err
	}
	if err := validatePassword(rp.NewPassword); err != nil {
		return err
	}
	return nil
}
