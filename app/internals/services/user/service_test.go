package user

import (
	"context"
	"errors"
	"log/slog"
	"login/internals/models"
	repo "login/internals/services/user/mock"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/argon2"
)

type discardHandler struct{}

func (dh discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (dh discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (dh discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return dh }
func (dh discardHandler) WithGroup(name string) slog.Handler        { return dh }

func getStubLogger() *slog.Logger {
	l := slog.New(discardHandler{})
	return l
}

// Check all errors in service.Registration()
func TestRegistration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	mockSelectOut := &models.User{Id: "id", Email: "email", Nickname: "Nicky", Password: "sss"}

	type selectEmailType struct {
		candidate *models.User
		err       error
	}

	type selectNicknameType struct {
		candidate *models.User
		err       error
	}

	type createUserType struct {
		id  string
		err error
	}

	cases := []struct {
		name           string
		email          string
		nickname       string
		password       string
		selectEmail    *selectEmailType
		selectNickname *selectNicknameType
		createUser     *createUserType
		expErr         error
	}{
		{
			name:        "select_by_email_exist",
			email:       "email",
			selectEmail: &selectEmailType{candidate: mockSelectOut},
			expErr:      errEmailExist,
		},
		{
			name:        "select_by_email_error",
			email:       "email",
			selectEmail: &selectEmailType{err: errors.New("database error")},
			expErr:      &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:           "select_by_nickname_exist",
			email:          "email",
			nickname:       "nick",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{candidate: mockSelectOut},
			expErr:         errNicknameExist,
		},
		{
			name:           "select_by_nickname_error",
			email:          "email",
			nickname:       "nick",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{err: errors.New("database error")},
			expErr:         &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:           "create_user_error",
			email:          "email",
			nickname:       "nick",
			password:       "pass",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{nil, nil},
			createUser:     &createUserType{err: errors.New("database error")},
			expErr:         &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserByEmail(ctx, tCase.email).
				Return(tCase.selectEmail.candidate, tCase.selectEmail.err).
				Times(1)
			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(ctx, tCase.nickname).
					Return(tCase.selectNickname.candidate, tCase.selectNickname.err).
					Times(1)
			}
			if tCase.createUser != nil {
				mockRepo.EXPECT().
					CreateUser(ctx, tCase.email, tCase.nickname, gomock.AssignableToTypeOf(tCase.password)).
					Return(tCase.createUser.id, tCase.createUser.err).
					Times(1)
			}

			_, err := service.Registration(ctx, tCase.email, tCase.nickname, tCase.password)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.Login()
func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	type selectEmailType struct {
		candidate *models.User
		err       error
	}

	type selectNicknameType struct {
		candidate *models.User
		err       error
	}

	cases := []struct {
		name           string
		param          string
		password       string
		selectEmail    *selectEmailType
		selectNickname *selectNicknameType
		expErr         error
	}{
		{
			name:           "user_not_exist",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{nil, nil},
			expErr:         errUserNotFound,
		},
		{
			name:     "incorrect_password",
			param:    "email",
			password: "password",
			selectEmail: &selectEmailType{
				candidate: &models.User{
					Id:       "id",
					Email:    "email",
					Nickname: "nick",
					Password: string(argon2.Key([]byte("word"), argonSalt, 3, 32*1024, 2, 32)),
				},
			},
			expErr: errIncorrectPassword,
		},
		{
			name:        "select_email_error",
			selectEmail: &selectEmailType{err: errors.New("database error")},
			expErr:      &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:           "select_nickname_error",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{err: errors.New("database error")},
			expErr:         &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserByEmail(ctx, tCase.param).
				Return(tCase.selectEmail.candidate, tCase.selectEmail.err).
				Times(1)
			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(ctx, tCase.param).
					Return(tCase.selectNickname.candidate, tCase.selectNickname.err).
					Times(1)
			}

			_, err := service.Login(ctx, tCase.param, tCase.password)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.GetUser()
func TestGetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	type selectIdType struct {
		candidate *models.User
		err       error
	}

	cases := []struct {
		name     string
		id       string
		selectId *selectIdType
		expErr   error
	}{
		{
			name:     "user_not_exist",
			selectId: &selectIdType{nil, nil},
			expErr:   errUserNotFound,
		},
		{
			name:     "inernal_error",
			selectId: &selectIdType{err: errors.New("database error")},
			expErr:   &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(ctx, tCase.id).
				Return(tCase.selectId.candidate, tCase.selectId.err).
				Times(1)

			_, err := service.GetUser(ctx, tCase.id)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.UpdatePassword()
func TestUpdatePassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	type selectIdType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		id          string
		oldPassword string
		newPassword string
		selectId    *selectIdType
		updateError error
		expErr      error
	}{
		{
			name:     "select_user_return_error",
			selectId: &selectIdType{err: errors.New("database error")},
			expErr:   &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:     "user_not_found",
			selectId: &selectIdType{nil, nil},
			expErr:   errUserNotFound,
		},
		{
			name:        "incorrect_password",
			id:          "id",
			oldPassword: "old",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Password: string(argon2.Key([]byte("password"), argonSalt, 3, 32*1024, 2, 32)),
				},
			},
			expErr: errIncorrectPassword,
		},
		{
			name:        "update_user_return_error",
			id:          "id",
			oldPassword: "old",
			newPassword: "new",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Password: string(argon2.Key([]byte("old"), argonSalt, 3, 32*1024, 2, 32)),
				},
			},
			updateError: errors.New("database error"),
			expErr:      &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(ctx, tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)
			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(ctx, tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdatePassword(ctx, tCase.id, tCase.oldPassword, tCase.newPassword)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.UpdateNickname()
func TestUpdateNickname(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	type selectIdType struct {
		user *models.User
		err  error
	}

	type selectNicknameType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name           string
		id             string
		newNickname    string
		selectId       *selectIdType
		selectNickname *selectNicknameType
		updateError    error
		expErr         error
	}{
		{
			name:     "select_by_id_return_error",
			id:       "id",
			selectId: &selectIdType{err: errors.New("database error")},
			expErr:   &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:     "user_not_found",
			id:       "id",
			selectId: &selectIdType{nil, nil},
			expErr:   errUserNotFound,
		},
		{
			name:        "select_by_nickname_return_error",
			id:          "id",
			newNickname: "new_nickname",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Nickname: "old_nickname",
				},
			},
			selectNickname: &selectNicknameType{nil, errors.New("database error")},
			expErr:         &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:        "nickname_collision",
			id:          "id",
			newNickname: "new_nickname",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Nickname: "old_nickname",
				},
			},
			selectNickname: &selectNicknameType{
				user: &models.User{
					Id:       "another_id",
					Nickname: "new_nickname",
				},
			},
			expErr: errNicknameExist,
		},
		{
			name:        "update_user_return_error",
			id:          "id",
			newNickname: "new_nickname",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Nickname: "old_nickname",
				},
			},
			selectNickname: &selectNicknameType{nil, nil},
			updateError:    errors.New("database error"),
			expErr:         &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(ctx, tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)

			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(ctx, tCase.newNickname).
					Return(tCase.selectNickname.user, tCase.selectNickname.err).
					Times(1)
			}

			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(ctx, tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdateNickname(ctx, tCase.id, tCase.newNickname)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.UpdateEmail()
func TestUpdateEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)
	ctx := context.Background()

	type selectIdType struct {
		user *models.User
		err  error
	}

	type selectEmailType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		id          string
		newEmail    string
		selectId    *selectIdType
		selectEmail *selectEmailType
		updateError error
		expErr      error
	}{
		{
			name:     "select_by_id_return_error",
			id:       "id",
			selectId: &selectIdType{err: errors.New("database error")},
			expErr:   &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:     "user_not_found",
			id:       "id",
			selectId: &selectIdType{nil, nil},
			expErr:   errUserNotFound,
		},
		{
			name:     "select_by_email_return_error",
			id:       "id",
			newEmail: "new_email",
			selectId: &selectIdType{
				user: &models.User{
					Id:    "id",
					Email: "old_email",
				},
			},
			selectEmail: &selectEmailType{nil, errors.New("database error")},
			expErr:      &ServiceError{ClientMessage: "internal error"},
		},
		{
			name:     "email_collision",
			id:       "id",
			newEmail: "new_email",
			selectId: &selectIdType{
				user: &models.User{
					Id:    "id",
					Email: "old_email",
				},
			},
			selectEmail: &selectEmailType{
				user: &models.User{
					Id:    "another_id",
					Email: "new_email",
				},
			},
			expErr: errEmailExist,
		},
		{
			name:     "update_user_return_error",
			id:       "id",
			newEmail: "new_email",
			selectId: &selectIdType{
				user: &models.User{
					Id:    "id",
					Email: "old_email",
				},
			},
			selectEmail: &selectEmailType{nil, nil},
			updateError: errors.New("database error"),
			expErr:      &ServiceError{ClientMessage: "internal error"},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(ctx, tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)

			if tCase.selectEmail != nil {
				mockRepo.EXPECT().
					SelectUserByEmail(ctx, tCase.newEmail).
					Return(tCase.selectEmail.user, tCase.selectEmail.err).
					Times(1)
			}

			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(ctx, tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdateEmail(ctx, tCase.id, tCase.newEmail)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}
