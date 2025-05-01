package user

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"login/internals/transport/middlewares"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type userHandler struct {
	log *slog.Logger
	us  UserService
}

type Handler interface {
	Register(*slog.Logger, chi.Router)
}

func GetHandler(service UserService, log *slog.Logger) Handler {
	return &userHandler{us: service, log: log}
}

func (uh *userHandler) Register(l *slog.Logger, router chi.Router) {
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(
		middleware.RequestLogger(
			&middleware.DefaultLogFormatter{Logger: log.Default(), NoColor: true},
		),
	)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(30 * time.Second))

	router.Route("/api/user", func(r chi.Router) {
		r.Post("/registration", uh.Registration)
		r.Post("/login", uh.Login)
		r.Delete("/{id}/logout", uh.Logout)

		auth := middlewares.AuthMiddleware(l)
		r.With(auth).Get("/{id}", uh.GetUser)
		r.With(auth).Get("/all", uh.GetAllUsers)
		r.With(auth).Put("/{id}/update/{type}", uh.UpdateUser)
		r.With(auth).Delete("/{id}/delete", uh.DeleteUser)
	})
}

func (uh *userHandler) Registration(w http.ResponseWriter, r *http.Request) {
	uh.log.Info("Registration user")

	candidate := &registrationEntity{}
	if err := json.NewDecoder(r.Body).Decode(candidate); err != nil {
		uh.log.Error("Body parser", "error", err.Error())
		errorHandler(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := validateRegistration(candidate); err != nil {
		uh.log.Info("Invalid parameters",
			"email", candidate.Email,
			"nickname", candidate.Nickname,
			"password", candidate.Password,
		)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	id, access, refresh, err := uh.us.Registration(candidate.Email, candidate.Nickname, candidate.Password)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}
	uh.log.Info("Successful registration",
		"user_id", id,
		"access", access,
		"refresh", refresh,
	)

	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: access, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh, HttpOnly: true})

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

func (uh *userHandler) Login(w http.ResponseWriter, r *http.Request) {
	uh.log.Info("Login user")

	candidate := &loginEntity{}
	if err := json.NewDecoder(r.Body).Decode(candidate); err != nil {
		uh.log.Error("Body parser", "error", err.Error())
		errorHandler(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := validateLogin(candidate); err != nil {
		uh.log.Info("Invalid parameters",
			"param", candidate.Param,
			"passwrod", candidate.Password,
		)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	id, access, refresh, err := uh.us.Login(candidate.Param, candidate.Password)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}
	uh.log.Info("Successful login",
		"user_id", id,
		"access", access,
		"refresh", refresh,
	)

	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: access, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh, HttpOnly: true})

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

func (uh *userHandler) Logout(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uh.log.Info("Logout user", "user_id", id)

	if err := validateUserId(id); err != nil {
		uh.log.Info("Incorrect user id", "user_id", id)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "access_token", MaxAge: -1, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", MaxAge: -1, HttpOnly: true})

	uh.log.Info("Successful logout", "user_id", id)

	w.WriteHeader(http.StatusOK)
}

func (uh *userHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uh.log.Info("Getting user", "user_id", id)

	if err := validateUserId(id); err != nil {
		uh.log.Info("Incorrect user id", "user_id", id)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := uh.us.GetUser(id)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}

	response := convertUser(user.Id, user.Email, user.Nickname)

	uh.log.Info("Getting user was successful", "user_id", id)

	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	uh.log.Info("Getting all users")

	limit := r.URL.Query().Get("limit")
	offset := r.URL.Query().Get("offset")
	if limit == "" || offset == "" {
		uh.log.Info("Empty parameters", "limit", limit, "offset", offset)
		errorHandler(w, http.StatusBadRequest, "Empty limit or offset")
		return
	}

	uintLimit, err := strconv.ParseUint(limit, 10, 64)
	if err != nil {
		uh.log.Info("Incorrect limit parameter", "limit", limit)
		errorHandler(w, http.StatusBadRequest, "Incorrect limit parameter")
		return
	}
	uintOffset, err := strconv.ParseUint(offset, 10, 64)
	if err != nil {
		uh.log.Info("Incorrect offset parameter", "offset", offset)
		errorHandler(w, http.StatusBadRequest, "Incorrect offset parameter")
		return
	}

	users, err := uh.us.GetAllUsers(uintLimit, uintOffset)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}

	response := make([]*responseUser, len(users))
	for i, user := range users {
		response[i] = convertUser(user.Id, user.Email, user.Nickname)
	}

	uh.log.Info("Getting all users was successful", "limit", limit, "offset", offset)

	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	t := chi.URLParam(r, "type")
	userId := chi.URLParam(r, "id")
	uh.log.Info("Update user", "type", t, "user_id", userId)

	if err := validateUserId(userId); err != nil {
		uh.log.Info("Incorrect user id", "user_id", userId)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	if targetId := r.Context().Value("user_id"); targetId != nil {
		if targetId != userId {
			errorHandler(w, http.StatusForbidden, "Access denied")
			return
		}
	}

	var response *responseUser

	if t == "password" {
		entity := &updatePassword{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			uh.log.Error("Body parser", "error", err.Error())
			errorHandler(w, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validatePassword(entity.NewPassword); err != nil {
			uh.log.Info("Invalid parameters",
				"new_password", entity.NewPassword,
			)
			errorHandler(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdatePassword(userId, entity.OldPassword, entity.NewPassword)
		if err != nil {
			uh.serviceErrorHandler(w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else if t == "nickname" {
		entity := &updateNickname{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			uh.log.Error("Body parser", "error", err.Error())
			errorHandler(w, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validateNickname(entity.NewNickname); err != nil {
			uh.log.Info("Invalid parameters",
				"new_nickname", entity.NewNickname,
			)
			errorHandler(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdateNickname(userId, entity.NewNickname)
		if err != nil {
			uh.serviceErrorHandler(w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else if t == "email" {
		entity := &updateEmail{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			uh.log.Error("Body parser", "error", err.Error())
			errorHandler(w, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validateEmail(entity.NewEmail); err != nil {
			uh.log.Info("Invalid parameters",
				"new_email", entity.NewEmail,
			)
			errorHandler(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdateEmail(userId, entity.NewEmail)
		if err != nil {
			uh.serviceErrorHandler(w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else {
		errorHandler(w, http.StatusNotFound, "Page not found")
		return
	}

	uh.log.Info("User updated", "type", t, "user_id", userId)
	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	uh.log.Info("Delete user", "user_id", id)

	if err := validateUserId(id); err != nil {
		uh.log.Info("Incorrect user id", "user_id", id)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	if targetId := r.Context().Value("user_id"); targetId != nil {
		if targetId != id {
			errorHandler(w, http.StatusForbidden, "Access denied")
			return
		}
	}

	err := uh.us.DeleteUserService(id)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}
	uh.log.Info("User deleted", "user_id", id)

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

/*
func (uh *userHandler) RefreshPassword(w http.ResponseWriter, r *http.Request) {
	uh.log.Info("Refresh password")

	entity := &refreshPassword{}
	if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
		uh.log.Error("Body parser", "error", err.Error())
		errorHandler(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := validateRefreshPassword(entity); err != nil {
		uh.log.Info("Invalid parameters",
			"email", entity.Email,
			"new_password", entity.NewPassword,
		)
		errorHandler(w, http.StatusBadRequest, err.Error())
		return
	}

	userId, err := uh.us.RefreshPassword(entity.Email, entity.NewPassword)
	if err != nil {
		uh.serviceErrorHandler(w, err)
		return
	}

	uh.log.Info("Password refreshed", "user_id", userId)

	w.WriteHeader(http.StatusOK)
}
*/

func (uh *userHandler) serviceErrorHandler(w http.ResponseWriter, err error) {
	se := parseServiceError(err)
	if se == nil {
		uh.log.Error("Error from service was return in an invalid form")
		errorHandler(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if se.Code < 500 {
		uh.log.Info("Finish with user error")
	}
	errorHandler(w, se.Code, se.Message)
}

func convertUser(id, email, nickname string) *responseUser {
	return &responseUser{
		Id:       id,
		Email:    email,
		Nickname: nickname,
	}
}

func renderJson(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func errorHandler(w http.ResponseWriter, code int, message string) {
	renderJson(w, responseError{Error: message}, code)
}
