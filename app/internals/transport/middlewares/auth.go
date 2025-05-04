package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"login/pkg/tokens"

	"github.com/go-chi/chi/middleware"
)

func AuthMiddleware(l *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return auth(l, next)
	}
}

func auth(log *slog.Logger, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		access, err := r.Cookie("access_token")
		if err != nil {
			errorHandler(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		refresh, err := r.Cookie("refresh_token")
		if err != nil {
			errorHandler(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		tks := tokens.InsertTokens(access.Value, refresh.Value)
		if err := tks.Validate(); err != nil {
			if errors.Is(err, tokens.ErrRefreshExpired) {
				errorHandler(w, http.StatusUnauthorized, "Unauthorized")
				return
			} else if errors.Is(err, tokens.ErrAccessExpired) {
				_ = tks.Refresh()
				http.SetCookie(w, &http.Cookie{Name: "access_token", Value: tks.GetAccess(), HttpOnly: true})
				http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: tks.GetRefresh(), HttpOnly: true})
			} else {
				log.Error("Auth: "+err.Error(), "request_id", middleware.GetReqID(r.Context()))
				errorHandler(w, http.StatusInternalServerError, "Internal error")
				return
			}
		}

		nCtx := context.WithValue(r.Context(), "user_id", tks.GetId())

		next.ServeHTTP(w, r.WithContext(nCtx))
	}
}

func errorHandler(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(
		struct {
			Error string `json:"error"`
		}{Error: message},
	)
}
