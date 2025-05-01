package user

import (
	"context"
	"errors"
	"log/slog"
	"login/internals/models"
	repo "login/internals/services/user/mock"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
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
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)

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
			expErr:      errors.Join(errStatusBadRequest, errEmailExist),
		},
		{
			name:        "select_by_email_error",
			email:       "email",
			selectEmail: &selectEmailType{err: errors.New("database error")},
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
		{
			name:           "select_by_nickname_exist",
			email:          "email",
			nickname:       "nick",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{candidate: mockSelectOut},
			expErr:         errors.Join(errStatusBadRequest, errNicknameExist),
		},
		{
			name:           "select_by_nickname_error",
			email:          "email",
			nickname:       "nick",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{err: errors.New("database error")},
			expErr:         errors.Join(errStatusInternal, errInternal),
		},
		{
			name:           "create_user_error",
			email:          "email",
			nickname:       "nick",
			password:       "pass",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{nil, nil},
			createUser:     &createUserType{err: errors.New("database error")},
			expErr:         errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserByEmail(tCase.email).
				Return(tCase.selectEmail.candidate, tCase.selectEmail.err).
				Times(1)
			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(tCase.nickname).
					Return(tCase.selectNickname.candidate, tCase.selectNickname.err).
					Times(1)
			}
			if tCase.createUser != nil {
				mockRepo.EXPECT().
					CreateUser(tCase.email, tCase.nickname, gomock.AssignableToTypeOf(tCase.password)).
					Return(tCase.createUser.id, tCase.createUser.err).
					Times(1)
			}

			_, _, _, err := service.Registration(tCase.email, tCase.nickname, tCase.password)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.Login()
func TestLogin(t *testing.T) {
	hashPassword := func(pass string, salt int) string {
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), salt)
		return string(hash)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)

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
			expErr:         errors.Join(errStatusBadRequest, errUserNotFound),
		},
		{
			name:     "incorrect_salt",
			param:    "email",
			password: "password",
			selectEmail: &selectEmailType{
				candidate: &models.User{
					Id:       "id",
					Email:    "email",
					Nickname: "nick",
					Password: hashPassword("password", bcrypt.MinCost),
				},
			},
			expErr: errors.Join(errStatusInternal, errInternal),
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
					Password: hashPassword("passsword", bcrypt.DefaultCost),
				},
			},
			expErr: errors.Join(errStatusBadRequest, errIncorrectPassword),
		},
		{
			name:        "select_email_error",
			selectEmail: &selectEmailType{err: errors.New("database error")},
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
		{
			name:           "select_nickname_error",
			selectEmail:    &selectEmailType{nil, nil},
			selectNickname: &selectNicknameType{err: errors.New("database error")},
			expErr:         errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserByEmail(tCase.param).
				Return(tCase.selectEmail.candidate, tCase.selectEmail.err).
				Times(1)
			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(tCase.param).
					Return(tCase.selectNickname.candidate, tCase.selectNickname.err).
					Times(1)
			}

			_, _, _, err := service.Login(tCase.param, tCase.password)
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
			expErr:   errors.Join(errStatusBadRequest, errUserNotFound),
		},
		{
			name:     "inernal_error",
			selectId: &selectIdType{err: errors.New("database error")},
			expErr:   errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(tCase.id).
				Return(tCase.selectId.candidate, tCase.selectId.err).
				Times(1)

			_, err := service.GetUser(tCase.id)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.RefreshPassword()
func TestRefreshPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)

	type selectEmailType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		email       string
		password    string
		selectEmail *selectEmailType
		updateError error
		expErr      error
	}{
		{
			name:        "email_not_exist",
			selectEmail: &selectEmailType{nil, nil},
			expErr:      errors.Join(errStatusBadRequest, errIncorrectEmail),
		},
		{
			name:        "select_user_return_error",
			selectEmail: &selectEmailType{err: errors.New("database error")},
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
		{
			name:        "update_user_return_error",
			selectEmail: &selectEmailType{user: &models.User{}},
			updateError: errors.New("database error"),
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserByEmail(tCase.email).
				Return(tCase.selectEmail.user, tCase.selectEmail.err).
				Times(1)
			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(tCase.selectEmail.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.RefreshPassword(tCase.email, tCase.password)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}

// Check all errors in service.UpdatePassword()
func TestUpdatePassword(t *testing.T) {
	hashPassword := func(pass string, salt int) string {
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), salt)
		return string(hash)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repo.NewMockUserRepository(ctrl)
	log := getStubLogger()
	service := NewService(mockRepo, log)

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
			expErr:   errors.Join(errStatusInternal, errInternal),
		},
		{
			name:     "user_not_found",
			selectId: &selectIdType{nil, nil},
			expErr:   errors.Join(errStatusBadRequest, errUserNotFound),
		},
		{
			name:        "incorrect_cost_to_hash_password",
			id:          "id",
			oldPassword: "old",
			newPassword: "new",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Password: hashPassword("old", bcrypt.MinCost),
				},
			},
			expErr: errors.Join(errStatusInternal, errInternal),
		},
		{
			name:        "incorrect_password",
			id:          "id",
			oldPassword: "old",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Password: hashPassword("another_old", bcrypt.DefaultCost),
				},
			},
			expErr: errors.Join(errStatusBadRequest, errIncorrectPassword),
		},
		{
			name:        "update_user_return_error",
			id:          "id",
			oldPassword: "old",
			newPassword: "new",
			selectId: &selectIdType{
				user: &models.User{
					Id:       "id",
					Password: hashPassword("old", bcrypt.DefaultCost),
				},
			},
			updateError: errors.New("database error"),
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)
			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdatePassword(tCase.id, tCase.oldPassword, tCase.newPassword)
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
			expErr:   errors.Join(errStatusInternal, errInternal),
		},
		{
			name:     "user_not_found",
			id:       "id",
			selectId: &selectIdType{nil, nil},
			expErr:   errors.Join(errStatusBadRequest, errUserNotFound),
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
			expErr:         errors.Join(errStatusInternal, errInternal),
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
			expErr: errors.Join(errStatusBadRequest, errNicknameExist),
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
			expErr:         errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)

			if tCase.selectNickname != nil {
				mockRepo.EXPECT().
					SelectUserByNickname(tCase.newNickname).
					Return(tCase.selectNickname.user, tCase.selectNickname.err).
					Times(1)
			}

			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdateNickname(tCase.id, tCase.newNickname)
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
			expErr:   errors.Join(errStatusInternal, errInternal),
		},
		{
			name:     "user_not_found",
			id:       "id",
			selectId: &selectIdType{nil, nil},
			expErr:   errors.Join(errStatusBadRequest, errUserNotFound),
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
			expErr:      errors.Join(errStatusInternal, errInternal),
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
			expErr: errors.Join(errStatusBadRequest, errEmailExist),
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
			expErr:      errors.Join(errStatusInternal, errInternal),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockRepo.EXPECT().
				SelectUserById(tCase.id).
				Return(tCase.selectId.user, tCase.selectId.err).
				Times(1)

			if tCase.selectEmail != nil {
				mockRepo.EXPECT().
					SelectUserByEmail(tCase.newEmail).
					Return(tCase.selectEmail.user, tCase.selectEmail.err).
					Times(1)
			}

			if tCase.updateError != nil {
				mockRepo.EXPECT().
					UpdateUser(tCase.selectId.user).
					Return(tCase.updateError).
					Times(1)
			}

			_, err := service.UpdateEmail(tCase.id, tCase.newEmail)
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}
