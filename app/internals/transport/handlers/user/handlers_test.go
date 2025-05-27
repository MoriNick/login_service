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
	"login/pkg/session"
	"net/http"
	"net/http/httptest"
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

func prepareTestRouter(us *mock.MockUserService, sm *mock.MockSessionManager) chi.Router {
	log := slog.New(discardHandler{})
	router := chi.NewRouter()

	sm.EXPECT().
		AuthMiddleware(log).
		Return(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		})

	GetHandler(us, sm, log).Register(router)

	return router
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
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

	var strType string

	type serviceResultType struct {
		userId string
		err    error
	}

	type sessionResultType struct {
		session *session.Session
		err     error
	}

	cases := []struct {
		name          string
		body          io.Reader
		serviceResult *serviceResultType
		sessionResult *sessionResultType
		expStatus     int
		expBody       string
	}{
		{
			name:      "parse_body_error",
			body:      strings.NewReader(""),
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:      "invalid_input_parameters",
			body:      prepareTestRequestBody(&registrationEntity{Email: "aaa"}),
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidEmail.Error()}),
		},
		{
			name: "service_return_with_error",
			body: prepareTestRequestBody(
				&registrationEntity{
					Email:    "email@mail.ru",
					Nickname: "user1",
					Password: "12345678",
				},
			),
			serviceResult: &serviceResultType{
				"",
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"email already exist"}),
		},
		{
			name: "cannot_craete_session",
			body: prepareTestRequestBody(
				&registrationEntity{
					Email:    "email@mail.ru",
					Nickname: "user1",
					Password: "12345678",
				},
			),
			serviceResult: &serviceResultType{"userId", nil},
			sessionResult: &sessionResultType{nil, errors.New("something wrong")},
			expStatus:     http.StatusInternalServerError,
			expBody:       prepareExpResponseBody(&responseError{"internal error"}),
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
			serviceResult: &serviceResultType{"userId", nil},
			sessionResult: &sessionResultType{&session.Session{Id: "session_id"}, nil},
			expStatus:     http.StatusOK,
			expBody:       prepareExpResponseBody(&responseUserId{"userId"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://localhost/api/user/registration", tCase.body)
			w := httptest.NewRecorder()

			if tCase.serviceResult != nil {
				serviceMock.EXPECT().
					Registration(
						gomock.Any(),
						gomock.AssignableToTypeOf(strType),
						gomock.AssignableToTypeOf(strType),
						gomock.AssignableToTypeOf(strType),
					).
					Return(
						tCase.serviceResult.userId,
						tCase.serviceResult.err,
					).
					Times(1)
			}

			if tCase.sessionResult != nil {
				sessionManagerMock.EXPECT().
					CreateAndSaveSession(
						gomock.Any(),
						tCase.serviceResult.userId,
					).
					Return(
						tCase.sessionResult.session,
						tCase.sessionResult.err,
					).
					Times(1)

				if tCase.sessionResult.err == nil {
					sessionManagerMock.EXPECT().
						SetUpdatedSessionCookie(
							gomock.Any(),
							tCase.sessionResult.session.Id,
						).
						Do(func(w http.ResponseWriter, sessionId string) {
							http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sessionId})
						}).
						Times(1)
				}
			}

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
			if tCase.expStatus == http.StatusOK {
				cookies := w.Result().Cookies()
				require.Equal(t, 1, len(cookies))
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
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

	var strType string

	type serviceResultType struct {
		userId string
		err    error
	}

	type loadSessionType struct {
		session *session.Session
		err     error
	}

	type createSessionType struct {
		session *session.Session
		err     error
	}

	cases := []struct {
		name          string
		body          io.Reader
		serviceResult *serviceResultType
		loadSession   *loadSessionType
		createSession *createSessionType
		expStatus     int
		expBody       string
	}{
		{
			name:      "parse_body_error",
			body:      strings.NewReader(""),
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:      "invalid_parameters",
			body:      prepareTestRequestBody(&loginEntity{Param: "aaa"}),
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidParameter.Error()}),
		},
		{
			name: "service_return_with_error",
			body: prepareTestRequestBody(&loginEntity{Param: "email@mail.ru", Password: "12345678"}),
			serviceResult: &serviceResultType{
				"",
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"email already exist"}),
		},
		{
			name:          "cannot_load_session",
			body:          prepareTestRequestBody(&loginEntity{Param: "email@mail.ru", Password: "12345678"}),
			serviceResult: &serviceResultType{"", nil},
			loadSession:   &loadSessionType{nil, errors.New("something wrong")},
			expStatus:     http.StatusInternalServerError,
			expBody:       prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:          "cannot_create_session",
			body:          prepareTestRequestBody(&loginEntity{Param: "email@mail.ru", Password: "12345678"}),
			serviceResult: &serviceResultType{"", nil},
			loadSession:   &loadSessionType{nil, nil},
			createSession: &createSessionType{nil, errors.New("something wrong")},
			expStatus:     http.StatusInternalServerError,
			expBody:       prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:          "without_errors",
			body:          prepareTestRequestBody(&loginEntity{Param: "user1", Password: "12345678"}),
			serviceResult: &serviceResultType{"id", nil},
			loadSession:   &loadSessionType{&session.Session{Id: "session_id"}, nil},
			expStatus:     http.StatusOK,
			expBody:       prepareExpResponseBody(&responseUserId{"id"}),
		},
	}

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
						tCase.serviceResult.userId,
						tCase.serviceResult.err,
					).
					Times(1)
			}

			if tCase.loadSession != nil {
				sessionManagerMock.EXPECT().
					LoadSession(
						gomock.Any(),
						tCase.serviceResult.userId,
					).
					Return(
						tCase.loadSession.session,
						tCase.loadSession.err,
					).
					Times(1)

				// to check "without_errors"
				if tCase.loadSession.err == nil && tCase.loadSession.session != nil {
					sessionManagerMock.EXPECT().
						SetUpdatedSessionCookie(
							gomock.Any(),
							tCase.loadSession.session.Id,
						).
						Do(func(w http.ResponseWriter, sessionId string) {
							http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sessionId})
						}).
						Times(1)
				}
			}

			if tCase.createSession != nil {
				sessionManagerMock.EXPECT().
					CreateAndSaveSession(
						gomock.Any(),
						tCase.serviceResult.userId,
					).
					Return(
						tCase.createSession.session,
						tCase.createSession.err,
					).
					Times(1)
			}

			req := httptest.NewRequest("POST", "http://localhost/api/user/login", tCase.body)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
			if tCase.expStatus == http.StatusOK {
				cookies := w.Result().Cookies()
				require.Equal(t, 1, len(cookies))
			}
		})
	}
}

// Check all errors in handlers.GetUser()
func TestGetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

	type serviceResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name          string
		userId        string
		serviceResult *serviceResultType
		expStatus     int
		expBody       string
	}{
		{
			name:      "invalid_user_id",
			userId:    "id",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:   "service_return_with_error",
			userId: "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
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

				sessionManagerMock.EXPECT().
					GetSessionFromContext(gomock.Any()).
					Return(&session.Session{UserId: tCase.userId}).
					Times(1)
			}

			req := httptest.NewRequest("GET", "http://localhost/api/user/"+tCase.userId, nil)
			req.SetPathValue("id", tCase.userId)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.GetAllUsers()
func TestGetAllUsers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

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
		expStatus     int
		expBody       string
	}{
		{
			name:      "empty_parameters",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"empty limit or offset"}),
		},
		{
			name:      "empty_offset",
			limit:     "10",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"empty limit or offset"}),
		},
		{
			name:      "empty_limit",
			offset:    "10",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"empty limit or offset"}),
		},
		{
			name:      "incorrect_limit",
			limit:     "-10",
			offset:    "10",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"incorrect limit parameter"}),
		},
		{
			name:      "incorrect_offset",
			limit:     "10",
			offset:    "-10",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"incorrect offset parameter"}),
		},
		{
			name:   "service_return_with_error",
			limit:  "3",
			offset: "0",
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "internal error", Err: errors.New("internalsss")},
			},
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"internal error"}),
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

			req := httptest.NewRequest(
				"GET",
				"http://localhost/api/user/all?limit="+tCase.limit+"&offset="+tCase.offset,
				nil,
			)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.UpdateUser()
func TestUpdateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

	var stringType string

	type serviceResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name          string
		id            string
		updateType    string
		reqBody       io.Reader
		serviceResult *serviceResultType
		expStatus     int
		expBody       string
	}{
		{
			name:       "invalid_id",
			id:         "idd",
			updateType: "invalid",
			expStatus:  http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:       "incorrect_type",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "invalid",
			expStatus:  http.StatusNotFound,
			expBody:    prepareExpResponseBody(&responseError{"page not found"}),
		},
		{
			name:       "incorrect_body_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "password",
			reqBody:    strings.NewReader(""),
			expStatus:  http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:       "invalid_new_password_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "password",
			reqBody:    prepareTestRequestBody(&updatePassword{NewPassword: "ss"}),
			expStatus:  http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidPassword.Error()}),
		},
		{
			name:       "serivce_return_error_in_update_password",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "password",
			reqBody:    prepareTestRequestBody(&updatePassword{NewPassword: "len_password_>_8"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "incorrect old password"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"incorrect old password"}),
		},
		{
			name:       "incorrect_body_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "nickname",
			reqBody:    strings.NewReader(""),
			expStatus:  http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:       "invalid_nickname_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "nickname",
			reqBody:    prepareTestRequestBody(&updateNickname{"00"}),
			expStatus:  http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidNickname.Error()}),
		},
		{
			name:       "service_return_error_in_update_nickname",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "nickname",
			reqBody:    prepareTestRequestBody(&updateNickname{"Nicky"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "nickname already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"nickname already exist"}),
		},
		{
			name:       "incorrect_body_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "email",
			reqBody:    strings.NewReader(""),
			expStatus:  http.StatusInternalServerError,
			expBody:    prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:       "invalid_email_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "email",
			reqBody:    prepareTestRequestBody(&updateEmail{"email"}),
			expStatus:  http.StatusBadRequest,
			expBody:    prepareExpResponseBody(&responseError{errInvalidEmail.Error()}),
		},
		{
			name:       "service_return_error_in_update_email",
			id:         "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			updateType: "email",
			reqBody:    prepareTestRequestBody(&updateEmail{"email@mail.ru"}),
			serviceResult: &serviceResultType{
				nil,
				&us.ServiceError{ClientMessage: "email already exist"},
			},
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{"email already exist"}),
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

			if tCase.name != "invalid_id" {
				sessionManagerMock.EXPECT().
					GetSessionFromContext(gomock.Any()).
					Return(&session.Session{UserId: tCase.id}).
					Times(1)
			}

			req := httptest.NewRequest(
				"PUT",
				"http://localhost/api/user/"+tCase.id+"/update/"+tCase.updateType,
				tCase.reqBody,
			)
			req.SetPathValue("id", tCase.id)
			req.SetPathValue("type", tCase.updateType)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

// Check all errors in handlers.DeleteUser()
func TestDeleteUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	onceInitValidator.Do(onceInitValidatorFunc)
	serviceMock := mock.NewMockUserService(ctrl)
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	router := prepareTestRouter(serviceMock, sessionManagerMock)

	sessionCookie := http.Cookie{Name: "session_id", Value: "sss"}

	type destroySessionType struct {
		err error
	}

	type serviceResultType struct {
		err error
	}

	cases := []struct {
		name           string
		id             string
		setCookie      bool
		serviceResult  *serviceResultType
		destroySession *destroySessionType
		expStatus      int
		expBody        string
	}{
		{
			name:      "invalid_id",
			id:        "id",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&responseError{errInvalidUserId.Error()}),
		},
		{
			name:      "empty_session_cookie",
			id:        "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			expStatus: http.StatusInternalServerError,
			expBody:   prepareExpResponseBody(&responseError{"internal error"}),
		},
		{
			name:          "service_return_with_error",
			id:            "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			setCookie:     true,
			serviceResult: &serviceResultType{&us.ServiceError{ClientMessage: "user not found"}},
			expStatus:     http.StatusBadRequest,
			expBody:       prepareExpResponseBody(&responseError{"user not found"}),
		},
		{
			name:           "destroy_session_return_with_error",
			id:             "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			setCookie:      true,
			serviceResult:  &serviceResultType{nil},
			destroySession: &destroySessionType{err: errors.New("something wrong")},
			expStatus:      http.StatusInternalServerError,
			expBody:        prepareExpResponseBody(&responseError{"internal error"}),
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
					Return(tCase.serviceResult.err).
					Times(1)
			}

			if tCase.destroySession != nil {
				sessionManagerMock.EXPECT().
					DestroySession(
						gomock.Any(),
						sessionCookie.Value,
					).
					Return(
						tCase.destroySession.err,
					).
					Times(1)
			}

			if tCase.name != "invalid_id" {
				sessionManagerMock.EXPECT().
					GetSessionFromContext(gomock.Any()).
					Return(&session.Session{UserId: tCase.id}).
					Times(1)

				if tCase.setCookie {
					sessionManagerMock.EXPECT().
						GetSessionCookie(gomock.Any()).
						Return(&http.Cookie{Name: "session_id", Value: "sss"}).
						Times(1)
				} else {
					sessionManagerMock.EXPECT().
						GetSessionCookie(gomock.Any()).
						Return(nil)
				}
			}

			req := httptest.NewRequest(
				"DELETE",
				"http://localhost/api/user/"+tCase.id+"/delete",
				nil,
			)
			req.SetPathValue("id", tCase.id)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}

func TestReadAndValidateUserId(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type bodyType struct {
		UserId string `json:"userId"`
		Err    error  `json:"err"`
	}

	onceInitValidator.Do(onceInitValidatorFunc)
	sessionManagerMock := mock.NewMockSessionManager(ctrl)
	handler := &userHandler{sm: sessionManagerMock}
	router := chi.NewRouter()
	router.Get("/api/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		userId, status, err := handler.readAndValidateUserId(r)

		if status == 0 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(status)
		}
		_ = json.NewEncoder(w).Encode(&bodyType{UserId: userId, Err: err})
	})

	type getSessionContextType struct {
		session *session.Session
	}

	cases := []struct {
		name              string
		userId            string
		getSessionContext *getSessionContextType
		expStatus         int
		expBody           string
	}{
		{
			name:      "invalid_user_id",
			userId:    "invalidUserID",
			expStatus: http.StatusBadRequest,
			expBody:   prepareExpResponseBody(&bodyType{Err: errInvalidUserId}),
		},
		{
			name:              "empty_session",
			userId:            "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			getSessionContext: &getSessionContextType{session: nil},
			expStatus:         http.StatusInternalServerError,
			expBody:           prepareExpResponseBody(&bodyType{Err: errors.New("empty session")}),
		},
		{
			name:              "access_denied",
			userId:            "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			getSessionContext: &getSessionContextType{session: &session.Session{UserId: "4fd047eb-1925-4d27-95f3-4bcda6ae201a"}},
			expStatus:         http.StatusForbidden,
			expBody:           prepareExpResponseBody(&bodyType{Err: errors.New("access denied")}),
		},
		{
			name:              "without_errors",
			userId:            "4fd047eb-1925-4d27-95f3-4bcda6ae201b",
			getSessionContext: &getSessionContextType{session: &session.Session{UserId: "4fd047eb-1925-4d27-95f3-4bcda6ae201b"}},
			expStatus:         http.StatusOK,
			expBody:           prepareExpResponseBody(&bodyType{UserId: "4fd047eb-1925-4d27-95f3-4bcda6ae201b"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://localhost/api/user/"+tCase.userId, nil)
			r.SetPathValue("id", tCase.userId)

			if tCase.getSessionContext != nil {
				sessionManagerMock.EXPECT().
					GetSessionFromContext(gomock.AssignableToTypeOf(r)).
					Return(tCase.getSessionContext.session).
					Times(1)
			}

			w := httptest.NewRecorder()

			router.ServeHTTP(w, r)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}
