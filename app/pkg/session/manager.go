package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type SessionContextKey string

type SessionManager struct {
	ctx                context.Context
	store              SessionStore
	idleExpiration     time.Duration
	absoluteExpiration time.Duration
	CookieName         string
}

func NewSessionManager(
	ctx context.Context,
	store SessionStore,
	gcInterval,
	idleExpiration,
	absoluteExpiration time.Duration,
	cookieName string) *SessionManager {

	m := &SessionManager{
		store:              store,
		idleExpiration:     idleExpiration,
		absoluteExpiration: absoluteExpiration,
		CookieName:         cookieName,
	}

	go m.gc(ctx, gcInterval)

	return m
}

func (sm *SessionManager) CreateAndSaveSession(ctx context.Context, userId string) (*Session, error) {
	session := newSession(userId)

	if err := sm.store.Write(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (sm *SessionManager) LoadSession(ctx context.Context, userId string) (*Session, error) {
	session, err := sm.store.ReadByUserId(ctx, userId)
	if err != nil {
		return nil, err
	}

	if session != nil {
		if sm.validate(session) {
			return session, nil
		}

		if err := sm.update(ctx, session); err != nil {
			return nil, err
		}

		return session, nil
	}

	return nil, nil
}

func (sm *SessionManager) DestroySession(ctx context.Context, sessionId string) error {
	if err := sm.store.Destroy(ctx, sessionId); err != nil {
		return err
	}
	return nil
}

func (sm *SessionManager) GetSessionCookie(r *http.Request) *http.Cookie {
	cookie, _ := r.Cookie(sm.CookieName)
	return cookie
}

func (sm *SessionManager) SetUpdatedSessionCookie(w http.ResponseWriter, sessionId string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sm.CookieName,
		Value:    sessionId,
		Path:     "/",
		Domain:   "localhost",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sm.idleExpiration),
	})
}

func (sm *SessionManager) SetDeadSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sm.CookieName, MaxAge: -1})
}

func (sm *SessionManager) GetSessionFromContext(r *http.Request) *Session {
	sessionAny := r.Context().Value(SessionContextKey("session"))

	if session, ok := sessionAny.(*Session); ok {
		return session
	}

	return nil
}

func (sm *SessionManager) save(ctx context.Context, session *Session) error {
	session.LastActivityAt = time.Now()
	session.LastUpdateAt = time.Now()

	if err := sm.store.Write(ctx, session); err != nil {
		return err
	}
	return nil
}

func (sm *SessionManager) update(ctx context.Context, session *Session) error {
	session.Id = generateSessionId()
	session.LastActivityAt = time.Now()
	session.LastUpdateAt = time.Now()

	if err := sm.store.Update(ctx, session); err != nil {
		return err
	}
	return nil
}

func (sm *SessionManager) validate(session *Session) bool {
	if time.Since(session.LastActivityAt) > sm.idleExpiration {
		return false
	}
	return true
}

func (sm *SessionManager) AuthMiddleware(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sm.CookieName)
			if err != nil {
				errorHandler(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			session, err := sm.store.ReadBySessionId(r.Context(), cookie.Value)
			if err != nil {
				log.Error("AuthMiddleware: " + err.Error())
				errorHandler(w, http.StatusInternalServerError, "internal error")
				return
			}

			if session == nil {
				errorHandler(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			ctx := context.WithValue(r.Context(), SessionContextKey("session"), session)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)

			if cookies := w.Header().Values("Set-Cookie"); len(cookies) > 0 {
				for _, cookie := range cookies {
					if strings.Contains(cookie, sm.CookieName) &&
						strings.Contains(cookie, "Max-Age=0") {
						return
					}
				}
			}

			if err := sm.save(r.Context(), session); err != nil {
				log.Error("AuthMiddleware: " + err.Error())
				errorHandler(w, http.StatusInternalServerError, "internal error")
			}

			cookie.Expires = time.Now().Add(sm.idleExpiration)
			http.SetCookie(w, cookie)
		})
	}
}

func (sm *SessionManager) gc(ctx context.Context, d time.Duration) {
	ticker := time.NewTicker(d)

	for range ticker.C {
		select {
		case <-ctx.Done():
			return
		default:
			_ = sm.store.GC(ctx, sm.absoluteExpiration)
		}
	}
}

func errorHandler(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(
		struct {
			Error string `json:"error"`
		}{Error: message},
	)
}
