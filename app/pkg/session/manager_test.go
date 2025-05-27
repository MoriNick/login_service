package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

type discardHandler struct{}

func (dh discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (dh discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (dh discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return dh }
func (dh discardHandler) WithGroup(name string) slog.Handler        { return dh }

func prepareManager(ctx context.Context, store SessionStore) *SessionManager {
	gcInterval := time.Duration(10 * time.Second)
	idleExpiration := time.Duration(5 * time.Second)
	absoluteExpiration := time.Duration(15 * time.Second)
	cookieName := "session_id"

	return NewSessionManager(
		ctx,
		store,
		gcInterval,
		idleExpiration,
		absoluteExpiration,
		cookieName,
	)
}

func TestCreateAndSaveSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockSessionStore(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := prepareManager(ctx, mockStore)
	userId := "xxx-xxx-xxx"
	var sessionType *Session

	cases := []struct {
		name        string
		storeResult error
		expErr      error
	}{
		{
			name:        "store_return_with_error",
			storeResult: errors.New("database error"),
			expErr:      errors.New("database error"),
		},
		{
			name:        "without_errors",
			storeResult: nil,
			expErr:      nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockStore.EXPECT().
				Write(ctx, gomock.AssignableToTypeOf(sessionType)).
				Return(tCase.storeResult).
				Times(1)

			session, err := manager.CreateAndSaveSession(ctx, userId)

			if tCase.expErr != nil {
				require.EqualError(t, err, tCase.expErr.Error())
			} else {
				require.Equal(t, session.UserId, userId)
			}
		})
	}
}

func TestLoadSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := NewMockSessionStore(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := prepareManager(ctx, mockStore)
	userId := "xxx-xxx-xxx"

	type readResultType struct {
		session *Session
		err     error
	}

	type updateResultType struct {
		err error
	}

	cases := []struct {
		name         string
		readResult   *readResultType
		updateResult *updateResultType
		expErr       error
	}{
		{
			name:       "read_return_with_error",
			readResult: &readResultType{session: nil, err: errors.New("database error")},
			expErr:     errors.New("database error"),
		},
		{
			name:       "read_return_empty_session_without_error",
			readResult: &readResultType{session: nil, err: nil},
			expErr:     nil,
		},
		{
			name:       "session_is_valid",
			readResult: &readResultType{session: newSession(userId), err: nil},
			expErr:     nil,
		},
		{
			name: "session_is_invalid_update_return_with_error",
			readResult: &readResultType{session: &Session{
				Id:             "",
				UserId:         userId,
				LastActivityAt: time.Now().Add(-manager.idleExpiration * time.Second),
				LastUpdateAt:   time.Now(),
			}, err: nil},
			updateResult: &updateResultType{err: errors.New("database error")},
			expErr:       errors.New("database error"),
		},
		{
			name: "session_is_invalid_update_return_without_error",
			readResult: &readResultType{session: &Session{
				Id:             "",
				UserId:         userId,
				LastActivityAt: time.Now().Add(-manager.idleExpiration * time.Second),
				LastUpdateAt:   time.Now(),
			}, err: nil},
			updateResult: &updateResultType{err: nil},
			expErr:       nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mockStore.EXPECT().
				ReadByUserId(ctx, userId).
				Return(tCase.readResult.session, tCase.readResult.err).
				Times(1)

			if tCase.updateResult != nil {
				mockStore.EXPECT().
					Update(ctx, tCase.readResult.session).
					Return(tCase.updateResult.err).
					Times(1)
			}

			session, err := manager.LoadSession(ctx, userId)

			if err != nil {
				require.EqualError(t, err, tCase.expErr.Error())
			}
			if session != nil {
				require.Equal(t, session.UserId, userId)
			}
		})
	}
}

func nextFunc(w http.ResponseWriter, r *http.Request) {
	var v interface{}
	if v = r.Context().Value(SessionContextKey("session")); v == nil {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// to check behaviour when nextFunc delete session
	if session, ok := v.(*Session); ok {
		if session.UserId == "delete_me" {
			http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1})
		}
	}
}

func TestAuthMiddleware(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	log := slog.New(discardHandler{})
	mockStore := NewMockSessionStore(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := prepareManager(ctx, mockStore)
	auth := manager.AuthMiddleware(log)

	type readResultType struct {
		session *Session
		err     error
	}

	type saveResultType struct {
		err error
	}

	errorUnauthorizedString := "{\"error\":\"unauthorized\"}\n"
	errorInternalString := "{\"error\":\"internal error\"}\n"
	inputCookie := &http.Cookie{
		Name:  manager.CookieName,
		Value: "session_cookie_value",
	}

	cases := []struct {
		name          string
		sessionCookie *http.Cookie
		readResult    *readResultType
		saveResult    *saveResultType
		expStatus     int
		expBody       string
	}{
		{
			name:          "without_cookie",
			sessionCookie: nil,
			expStatus:     http.StatusUnauthorized,
			expBody:       errorUnauthorizedString,
		},
		{
			name:          "read_return_error",
			sessionCookie: inputCookie,
			readResult:    &readResultType{session: nil, err: errors.New("database error")},
			expStatus:     http.StatusInternalServerError,
			expBody:       errorInternalString,
		},
		{
			name:          "read_return_empty_session",
			sessionCookie: inputCookie,
			readResult:    &readResultType{session: nil, err: nil},
			expStatus:     http.StatusUnauthorized,
			expBody:       errorUnauthorizedString,
		},
		{
			name:          "save_return_error",
			sessionCookie: inputCookie,
			readResult:    &readResultType{session: newSession("userID"), err: nil},
			saveResult:    &saveResultType{err: errors.New("database error")},
			expStatus:     http.StatusInternalServerError,
			expBody:       errorInternalString,
		},
		{
			name:          "next_function_delete_session",
			sessionCookie: inputCookie,
			readResult:    &readResultType{session: newSession("delete_me"), err: nil},
			expStatus:     http.StatusOK,
			expBody:       "",
		},
		{
			name:          "without_error",
			sessionCookie: inputCookie,
			readResult:    &readResultType{session: newSession("userID"), err: nil},
			saveResult:    &saveResultType{err: nil},
			expStatus:     http.StatusOK,
			expBody:       "",
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.readResult != nil {
				mockStore.EXPECT().
					ReadBySessionId(ctx, inputCookie.Value).
					Return(tCase.readResult.session, tCase.readResult.err).
					Times(1)
			}

			if tCase.saveResult != nil {
				// to check context changes in authMiddleware
				ctxToWrite := context.WithValue(ctx, SessionContextKey("session"), tCase.readResult.session)
				mockStore.EXPECT().
					Write(ctxToWrite, tCase.readResult.session).
					Return(tCase.saveResult.err).
					Times(1)
			}

			req := httptest.NewRequestWithContext(ctx, "GET", "http://localhost/api/test/auth_middleware", nil)
			if tCase.sessionCookie != nil {
				req.AddCookie(tCase.sessionCookie)
			}
			w := httptest.NewRecorder()

			auth(http.HandlerFunc(nextFunc)).ServeHTTP(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			if tCase.expStatus == http.StatusUnauthorized || tCase.expStatus == http.StatusInternalServerError {
				require.Equal(t, tCase.expBody, w.Body.String())
			} else {
				cookieString := w.Header().Get("Set-Cookie")
				cookie, _ := http.ParseSetCookie(cookieString)

				// to check successful behaviour and when nextFunc delete session
				if tCase.readResult.session.UserId == "delete_me" {
					require.Equal(t, time.Time{}, cookie.Expires)
					require.Equal(t, -1, cookie.MaxAge)
				} else {
					require.Greater(t, cookie.Expires, time.Now().UTC())
				}
			}
		})
	}
}
