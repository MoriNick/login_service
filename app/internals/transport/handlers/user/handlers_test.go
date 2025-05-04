package user

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"login/internals/models"
	us "login/internals/services/user"
	mock "login/internals/transport/handlers/user/mock"
	"login/pkg/tokens"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var onceInitValidator sync.Once

func onceInitValidatorFunc() {
	_ = InitValidator()
}

type discardHandler struct{}

func (dh discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (dh discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (dh discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return dh }
func (dh discardHandler) WithGroup(name string) slog.Handler        { return dh }

func getStubLogger() *slog.Logger {
	return slog.New(discardHandler{})
}

func generateTestTokens(id string) [2]string {
	tks, _ := tokens.GenerateTokens(id)
	return [2]string{tks.GetAccess(), tks.GetRefresh()}
}

func prepareTestRequestBody(st interface{}) io.Reader {
	jsonBytes, _ := json.Marshal(st)
	return strings.NewReader(string(jsonBytes))
}

func prepareExpResponseBody(st interface{}) string {
	jsonBytes, _ := json.Marshal(st)
	return string(jsonBytes) + "\n"
}

// Check all errors in handlers.Registration()
func TestRegistration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	log := getStubLogger()
	slog.SetDefault(log)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	var strType string

	type serviceReturnType struct {
		id      string
		access  string
		refresh string
		err     error
	}

	cases := []struct {
		name          string
		body          io.Reader
		serviceReturn *serviceReturnType
		expStatus     int
		expBody       string
	}{
		{
			name:      "empty_body",
			body:      strings.NewReader(""),
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"Internal error"}),
		},
		{
			name:      "invalid_email",
			body:      prepareTestRequestBody(&registrationEntity{Email: "aaa"}),
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidEmail.Error()}),
		},
		{
			name: "service_return_error",
			body: prepareTestRequestBody(
				&registrationEntity{
					Email:    "email@mail.ru",
					Nickname: "user1",
					Password: "12345678",
				},
			),
			serviceReturn: &serviceReturnType{
				"", "", "",
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"email already exist"}),
		},
		{
			name: "without_errors",
			body: prepareTestRequestBody(
				&registrationEntity{
					Email:    "email@mail.ru",
					Nickname: "user1",
					Password: "12345678",
				},
			),
			serviceReturn: &serviceReturnType{"id", "access", "refresh", nil},
			expStatus:     http.StatusOK,
			expBody:       prepareExpResponseBody(&responseUserId{"id"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceReturn != nil {
				serviceMock.EXPECT().
					Registration(
						gomock.Any(),
						gomock.AssignableToTypeOf(strType),
						gomock.AssignableToTypeOf(strType),
						gomock.AssignableToTypeOf(strType),
					).
					Return(
						tCase.serviceReturn.id,
						tCase.serviceReturn.access,
						tCase.serviceReturn.refresh,
						tCase.serviceReturn.err,
					).
					Times(1)
			}

			req := httptest.NewRequest("POST", "http://localhost/api/user/registration", tCase.body)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
			if w.Code == http.StatusOK {
				cookies := w.Result().Cookies()
				require.Equal(t, tCase.serviceReturn.access, cookies[0].Value)
				require.Equal(t, tCase.serviceReturn.refresh, cookies[1].Value)
			}
		})
	}
}

// Check all errors in handlers.Login()
func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	log := getStubLogger()
	slog.SetDefault(log)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	type serviceResultType struct {
		id      string
		access  string
		refresh string
		err     error
	}

	cases := []struct {
		name          string
		body          io.Reader
		serviceResult *serviceResultType
		expStatus     int
		expBody       string
	}{
		{
			name:      "empty_body",
			body:      strings.NewReader(""),
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"Internal error"}),
		},
		{
			name:      "validation_(invalid_email/nickname)",
			body:      prepareTestRequestBody(&loginEntity{Param: "aaa"}),
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidParameter.Error()}),
		},
		{
			name: "service_return_error",
			body: prepareTestRequestBody(&loginEntity{Param: "email@mail.ru", Password: "12345678"}),
			serviceResult: &serviceResultType{
				"", "", "",
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"email already exist"}),
		},
		{
			name:          "without_errors",
			body:          prepareTestRequestBody(&loginEntity{Param: "user1", Password: "12345678"}),
			serviceResult: &serviceResultType{"id", "access", "refresh", nil},
			expStatus:     http.StatusOK,
			expBody:       prepareExpResponseBody(&responseUserId{"id"}),
		},
	}

	var strType string

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceResult != nil {
				serviceMock.EXPECT().
					Login(
						gomock.Any(),
						gomock.AssignableToTypeOf(strType),
						gomock.AssignableToTypeOf(strType),
					).
					Return(
						tCase.serviceResult.id,
						tCase.serviceResult.access,
						tCase.serviceResult.refresh,
						tCase.serviceResult.err,
					).
					Times(1)
			}

			req := httptest.NewRequest("POST", "http://localhost/api/user/login", tCase.body)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
			if w.Code == http.StatusOK {
				cookies := w.Result().Cookies()
				require.Equal(t, tCase.serviceResult.access, cookies[0].Value)
				require.Equal(t, tCase.serviceResult.refresh, cookies[1].Value)
			}
		})
	}
}

// Check all errors in handlers.GetUser()
func TestGetUser(t *testing.T) {
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	log := getStubLogger()
	slog.SetDefault(log)
	serviceMock := mock.NewMockUserService(ctrl)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	type serviceResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name          string
		userId        string
		tokens        [2]string
		serviceResult *serviceResultType
		expStatus     int
		expBody       string
	}{
		{
			name:      "invalid_user_id",
			userId:    "id",
			tokens:    generateTestTokens("id"),
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:   "service_return_error",
			userId: "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens: generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "user not found"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"user not found"}),
		},
		{
			name:   "without_errors",
			userId: "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens: generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			serviceResult: &serviceResultType{
				&models.User{
					Id:       "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
					Email:    "email@mail.ru",
					Nickname: "Nicky",
				},
				nil,
			},
			expStatus: http.StatusOK,
			expBody: prepareExpResponseBody(&responseUser{
				Id:       "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
				Email:    "email@mail.ru",
				Nickname: "Nicky",
			}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceResult != nil {
				serviceMock.EXPECT().
					GetUser(
						gomock.Any(),
						tCase.userId,
					).
					Return(tCase.serviceResult.user, tCase.serviceResult.err).
					Times(1)
			}

			req := httptest.NewRequest("GET", "http://localhost/api/user/"+tCase.userId, nil)
			req.SetPathValue("id", tCase.userId)
			req.AddCookie(
				&http.Cookie{Name: "access_token", Value: tCase.tokens[0], HttpOnly: true},
			)
			req.AddCookie(
				&http.Cookie{Name: "refresh_token", Value: tCase.tokens[1], HttpOnly: true},
			)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.GetAllUsers()
func TestGetAllUsers(t *testing.T) {
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	log := getStubLogger()
	slog.SetDefault(log)
	serviceMock := mock.NewMockUserService(ctrl)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	var uintType uint64

	type serviceResultType struct {
		users []models.User
		err   error
	}

	cases := []struct {
		name          string
		limit         string
		offset        string
		serviceResult *serviceResultType
		expCode       int
		expBody       string
	}{
		{
			name:    "empty_parameters",
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"Empty limit or offset"}),
		},
		{
			name:    "empty_offset",
			limit:   "10",
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"Empty limit or offset"}),
		},
		{
			name:    "empty_limit",
			offset:  "10",
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"Empty limit or offset"}),
		},
		{
			name:    "incorrect_limit",
			limit:   "-10",
			offset:  "10",
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"Incorrect limit parameter"}),
		},
		{
			name:    "incorrect_offset",
			limit:   "10",
			offset:  "-10",
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"Incorrect offset parameter"}),
		},
		{
			name:   "service_return_error",
			limit:  "3",
			offset: "0",
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "internal error", Err: errors.New("internalsss")},
			},
			expCode: http.StatusInternalServerError,
			expBody: prepareExpResponseBody(&responseError{"internal error"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceResult != nil {
				serviceMock.EXPECT().
					GetAllUsers(
						gomock.Any(),
						gomock.AssignableToTypeOf(uintType),
						gomock.AssignableToTypeOf(uintType),
					).
					Return(tCase.serviceResult.users, tCase.serviceResult.err).
					Times(1)
			}
			tokens := generateTestTokens("id")
			req := httptest.NewRequest(
				"GET",
				"http://localhost/api/user/all?limit="+tCase.limit+"&offset="+tCase.offset,
				nil,
			)
			req.AddCookie(&http.Cookie{Name: "access_token", Value: tokens[0], HttpOnly: true})
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: tokens[1], HttpOnly: true})
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expCode, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.UpdateUser()
func TestUpdateUser(t *testing.T) {
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	log := getStubLogger()
	slog.SetDefault(log)
	serviceMock := mock.NewMockUserService(ctrl)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	var stringType string

	type serviceResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name          string
		id            string
		tokens        [2]string
		updateType    string
		reqBody       io.Reader
		serviceResult *serviceResultType
		expCode       int
		expBody       string
	}{
		{
			name:       "invalid_id",
			id:         "idd",
			tokens:     generateTestTokens("idd"),
			updateType: "invalid",
			expCode:    http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:       "different_id's",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("idd"),
			updateType: "invalid",
			expCode:    http.StatusForbidden,
			expBody:    prepareExpResponseBody(&responseError{"Access denied"}),
		},
		{
			name:       "incorrect_type",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "invalid",
			expCode:    http.StatusNotFound,
			expBody:    prepareExpResponseBody(&responseError{"Page not found"}),
		},
		{
			name:       "incorrect_body_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "password",
			reqBody:    strings.NewReader(""),
			expCode:    http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"Internal error"}),
		},
		{
			name:       "invalid_new_password_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "password",
			reqBody:    prepareTestRequestBody(&updatePassword{NewPassword: "ss"}),
			expCode:    http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidPassword.Error()}),
		},
		{
			name:       "serivce_return_error_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "password",
			reqBody:    prepareTestRequestBody(&updatePassword{NewPassword: "len_password_>_8"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "incorrect old password"},
			},
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"incorrect old password"}),
		},
		{
			name:       "incorrect_body_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "nickname",
			reqBody:    strings.NewReader(""),
			expCode:    http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"Internal error"}),
		},
		{
			name:       "invalid_nickname_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "nickname",
			reqBody:    prepareTestRequestBody(&updateNickname{"00"}),
			expCode:    http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidNickname.Error()}),
		},
		{
			name:       "service_return_error_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "nickname",
			reqBody:    prepareTestRequestBody(&updateNickname{"Nicky"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "nickname already exist"},
			},
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"nickname already exist"}),
		},
		{
			name:       "incorrect_body_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "email",
			reqBody:    strings.NewReader(""),
			expCode:    http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"Internal error"}),
		},
		{
			name:       "invalid_email_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "email",
			reqBody:    prepareTestRequestBody(&updateEmail{"email"}),
			expCode:    http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidEmail.Error()}),
		},
		{
			name:       "service_return_error_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:     generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			updateType: "email",
			reqBody:    prepareTestRequestBody(&updateEmail{"email@mail.ru"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{"email already exist"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceResult != nil {
				if tCase.updateType == "password" {
					serviceMock.EXPECT().
						UpdatePassword(
							gomock.Any(),
							tCase.id,
							gomock.AssignableToTypeOf(stringType),
							gomock.AssignableToTypeOf(stringType),
						).
						Return(
							tCase.serviceResult.user,
							tCase.serviceResult.err,
						).
						Times(1)
				} else if tCase.updateType == "nickname" {
					serviceMock.EXPECT().
						UpdateNickname(
							gomock.Any(),
							tCase.id,
							gomock.AssignableToTypeOf(stringType),
						).
						Return(
							tCase.serviceResult.user,
							tCase.serviceResult.err,
						).
						Times(1)
				} else if tCase.updateType == "email" {
					serviceMock.EXPECT().
						UpdateEmail(
							gomock.Any(),
							tCase.id,
							gomock.AssignableToTypeOf(stringType),
						).
						Return(
							tCase.serviceResult.user,
							tCase.serviceResult.err,
						).
						Times(1)
				}
			}

			req := httptest.NewRequest(
				"PUT",
				"http://localhost/api/user/"+tCase.id+"/update/"+tCase.updateType,
				tCase.reqBody,
			)
			req.SetPathValue("id", tCase.id)
			req.SetPathValue("type", tCase.updateType)
			req.AddCookie(
				&http.Cookie{Name: "access_token", Value: tCase.tokens[0], HttpOnly: true},
			)
			req.AddCookie(
				&http.Cookie{Name: "refresh_token", Value: tCase.tokens[1], HttpOnly: true},
			)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expCode, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.DeleteUser()
func TestDeleteUser(t *testing.T) {
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	log := getStubLogger()
	slog.SetDefault(log)
	serviceMock := mock.NewMockUserService(ctrl)
	router := chi.NewRouter()
	GetHandler(serviceMock, log).Register(log, router)

	cases := []struct {
		name          string
		id            string
		tokens        [2]string
		serviceResult error
		expCode       int
		expBody       string
	}{
		{
			name:    "incorrect_id",
			id:      "id",
			tokens:  generateTestTokens("id"),
			expCode: http.StatusBadRequest,
			expBody: prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:    "different_id's",
			id:      "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:  generateTestTokens("ssss"),
			expCode: http.StatusForbidden,
			expBody: prepareExpResponseBody(&responseError{"Access denied"}),
		},
		{
			name:          "service_return_error",
			id:            "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			tokens:        generateTestTokens("4fd047eb-1925-4d27-95f3-4bcda6ae201b"),
			serviceResult: &us.ServiceError{ClientMessage: "user not found"},
			expCode:       http.StatusBadRequest,
			expBody:       prepareExpResponseBody(&responseError{"user not found"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.serviceResult != nil {
				serviceMock.EXPECT().
					DeleteUserService(
						gomock.Any(),
						tCase.id,
					).
					Return(tCase.serviceResult).
					Times(1)
			}

			req := httptest.NewRequest(
				"DELETE",
				"http://localhost/api/user/"+tCase.id+"/delete",
				nil,
			)
			req.SetPathValue("id", tCase.id)
			req.AddCookie(
				&http.Cookie{Name: "access_token", Value: tCase.tokens[0], HttpOnly: true},
			)
			req.AddCookie(
				&http.Cookie{Name: "refresh_token", Value: tCase.tokens[1], HttpOnly: true},
			)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expCode, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}
