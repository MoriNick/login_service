package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"login/pkg/logger"
	"login/pkg/tokens"
)

func Auth(next http.HandlerFunc) http.HandlerFunc {
	log := logger.GetLogger()
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info("Auth user")

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
				log.Error("Auth error", log.String("err", err.Error()))
				errorHandler(w, http.StatusInternalServerError, "Internal error")
				return
			}
		}

		log.Info("Successful auth", log.String("user_id", tks.GetId()))

		rctx := r.Context()
		nctx := context.WithValue(rctx, "user_id", tks.GetId())

		next(w, r.WithContext(nctx))
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
