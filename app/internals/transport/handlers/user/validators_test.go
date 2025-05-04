package user

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateUserId(t *testing.T) {
	//declared in handlers_test.go
	onceInitValidator.Do(onceInitValidatorFunc)

	cases := []struct {
		name   string
		id     string
		expErr error
	}{
		{
			name:   "less_len",
			id:     "i-i-i",
			expErr: errInvalidUserId,
		},
		{
			name:   "greater_len",
			id:     "sss-sss-sss-sss-sss-sss-sss-sss-sss-sss",
			expErr: errInvalidUserId,
		},
		{
			name:   "incorrect_by_dash",
			id:     "4fd047eb-1925-4d27-95f34bcda6ae2-01b",
			expErr: errInvalidUserId,
		},
		{
			name:   "incorrect_by_decoding",
			id:     "cccad75d-a69e-4622-8b5a-8c253d3af74s",
			expErr: errInvalidUserId,
		},
		{
			name:   "correct_id",
			id:     "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			expErr: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			err := validateUserId(tCase.id)
			require.Equal(t, tCase.expErr, err)
		})
	}
}

func TestValidateEmail(t *testing.T) {
	//declared in handlers_test.go
	onceInitValidator.Do(onceInitValidatorFunc)

	cases := []struct {
		name   string
		email  string
		expErr error
	}{
		{name: "empty_email", email: "", expErr: errInvalidEmail},
		{name: "email_aaa", email: "aaa", expErr: errInvalidEmail},
		{name: "email_aaa@", email: "aaa@", expErr: errInvalidEmail},
		{name: "email_aaa@.", email: "aaa@.", expErr: errInvalidEmail},
		{name: "email_aa@a.", email: "aa@a.", expErr: errInvalidEmail},
		{name: "email_aaa@@", email: "aaa@@", expErr: errInvalidEmail},
		{name: "email_aaa@@mail.ru", email: "aaa@@mail.ru", expErr: errInvalidEmail},
		{name: "email_aaa@aa@mail.ru", email: "aaa@aa@mail.ru", expErr: errInvalidEmail},
		{name: "email_@mail.ru", email: "@mail.ru", expErr: errInvalidEmail},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			err := validateEmail(tCase.email)
			require.Error(t, err)
			require.EqualError(t, tCase.expErr, err.Error())
		})
	}
}

func TestValidateNickname(t *testing.T) {
	//declared in handlers_test.go
	onceInitValidator.Do(onceInitValidatorFunc)

	cases := []struct {
		name     string
		nickname string
		expErr   error
	}{
		{name: "empty_nickname", nickname: "", expErr: errInvalidNickname},
		{name: "long_nickname", nickname: "aaaaaaaaaaaaaaaaaaaaaaa", expErr: errInvalidNickname},
		{name: "first_number", nickname: "2user", expErr: errInvalidNickname},
		{name: "english_only_1", nickname: "ыыыыы", expErr: errInvalidNickname},
		{name: "english_only_2", nickname: "ыыыыы22", expErr: errInvalidNickname},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			err := validateNickname(tCase.nickname)
			require.Error(t, err)
			require.EqualError(t, tCase.expErr, err.Error())
		})
	}
}

func TestValidatePassword(t *testing.T) {
	//declared in handlers_test.go
	onceInitValidator.Do(onceInitValidatorFunc)

	cases := []struct {
		name     string
		password string
		expErr   error
	}{
		{name: "empty_password", password: "", expErr: errInvalidPassword},
		{name: "short_password", password: "aaaaa", expErr: errInvalidPassword},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			err := validatePassword(tCase.password)
			require.Error(t, err)
			require.Error(t, tCase.expErr, err.Error())
		})
	}
}
