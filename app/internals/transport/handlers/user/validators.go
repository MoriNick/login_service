package user

import (
	"encoding/hex"
	"errors"
	"regexp"
)

var (
	errInvalidEmail     = errors.New("Invalid email")
	errInvalidNickname  = errors.New("Invalid nickname")
	errInvalidPassword  = errors.New("Invalid password")
	errInvalidParameter = errors.New("Invalid email/nickname")
	errInvalidUserId    = errors.New("Invalid user id")
)

func validateUserId(id string) error {
	if len(id) != 36 {
		return errInvalidUserId
	}

	src := id[0:8] + id[9:13] + id[14:18] + id[19:23] + id[24:]
	_, err := hex.DecodeString(src)
	if err != nil {
		return errInvalidUserId
	}

	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return errInvalidUserId
	}

	return nil
}

func validateEmail(email string) error {
	if len(email) > 100 {
		return errInvalidEmail
	}

	pattern := `^[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+$`
	isValid, _ := regexp.MatchString(pattern, email)

	if !isValid {
		return errInvalidEmail
	}
	return nil
}

func validateNickname(nickname string) error {
	pattern := `^[a-zA-Z][a-zA-Z0-9]{3,14}$`
	isValid, _ := regexp.MatchString(pattern, nickname)

	if !isValid {
		return errInvalidNickname
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
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
