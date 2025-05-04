package user

import (
	"context"
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
	candidate := &registrationEntity{}
	if err := json.NewDecoder(r.Body).Decode(candidate); err != nil {
		logError := &logErrorType{
			log:     uh.log,
			reqId:   middleware.GetReqID(r.Context()),
			name:    "JsonDecode",
			message: err.Error(),
		}
		errorHandler(w, logError, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := validateRegistration(candidate); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	id, access, refresh, err := uh.us.Registration(r.Context(), candidate.Email, candidate.Nickname, candidate.Password)
	if err != nil {
		uh.serviceErrorHandler(r.Context(), w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: access, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh, HttpOnly: true})

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

func (uh *userHandler) Login(w http.ResponseWriter, r *http.Request) {
	candidate := &loginEntity{}
	if err := json.NewDecoder(r.Body).Decode(candidate); err != nil {
		logError := &logErrorType{
			log:     uh.log,
			reqId:   middleware.GetReqID(r.Context()),
			name:    "JsonDecode",
			message: err.Error(),
		}
		errorHandler(w, logError, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := validateLogin(candidate); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	id, access, refresh, err := uh.us.Login(r.Context(), candidate.Param, candidate.Password)
	if err != nil {
		uh.serviceErrorHandler(r.Context(), w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: access, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh, HttpOnly: true})

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

func (uh *userHandler) Logout(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateUserId(id); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "access_token", MaxAge: -1, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", MaxAge: -1, HttpOnly: true})

	w.WriteHeader(http.StatusOK)
}

func (uh *userHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateUserId(id); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	user, err := uh.us.GetUser(r.Context(), id)
	if err != nil {
		uh.serviceErrorHandler(r.Context(), w, err)
		return
	}

	response := convertUser(user.Id, user.Email, user.Nickname)

	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	offset := r.URL.Query().Get("offset")
	if limit == "" || offset == "" {
		errorHandler(w, nil, http.StatusBadRequest, "Empty limit or offset")
		return
	}

	uintLimit, err := strconv.ParseUint(limit, 10, 64)
	if err != nil {
		errorHandler(w, nil, http.StatusBadRequest, "Incorrect limit parameter")
		return
	}
	uintOffset, err := strconv.ParseUint(offset, 10, 64)
	if err != nil {
		errorHandler(w, nil, http.StatusBadRequest, "Incorrect offset parameter")
		return
	}

	users, err := uh.us.GetAllUsers(r.Context(), uintLimit, uintOffset)
	if err != nil {
		uh.serviceErrorHandler(r.Context(), w, err)
		return
	}

	response := make([]*responseUser, len(users))
	for i, user := range users {
		response[i] = convertUser(user.Id, user.Email, user.Nickname)
	}

	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	t := chi.URLParam(r, "type")
	userId := chi.URLParam(r, "id")

	if err := validateUserId(userId); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	if targetId := r.Context().Value("user_id"); targetId != nil {
		if targetId != userId {
			errorHandler(w, nil, http.StatusForbidden, "Access denied")
			return
		}
	}

	var response *responseUser

	if t == "password" {
		entity := &updatePassword{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			logError := &logErrorType{
				log:     uh.log,
				reqId:   middleware.GetReqID(r.Context()),
				name:    "JsonDecode",
				message: err.Error(),
			}
			errorHandler(w, logError, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validatePassword(entity.NewPassword); err != nil {
			errorHandler(w, nil, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdatePassword(r.Context(), userId, entity.OldPassword, entity.NewPassword)
		if err != nil {
			uh.serviceErrorHandler(r.Context(), w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else if t == "nickname" {
		entity := &updateNickname{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			logError := &logErrorType{
				log:     uh.log,
				reqId:   middleware.GetReqID(r.Context()),
				name:    "JsonDecode",
				message: err.Error(),
			}
			errorHandler(w, logError, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validateNickname(entity.NewNickname); err != nil {
			errorHandler(w, nil, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdateNickname(r.Context(), userId, entity.NewNickname)
		if err != nil {
			uh.serviceErrorHandler(r.Context(), w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else if t == "email" {
		entity := &updateEmail{}
		if err := json.NewDecoder(r.Body).Decode(entity); err != nil {
			logError := &logErrorType{
				log:     uh.log,
				reqId:   middleware.GetReqID(r.Context()),
				name:    "JsonDecode",
				message: err.Error(),
			}
			errorHandler(w, logError, http.StatusInternalServerError, "Internal error")
			return
		}

		if err := validateEmail(entity.NewEmail); err != nil {
			errorHandler(w, nil, http.StatusBadRequest, err.Error())
			return
		}

		user, err := uh.us.UpdateEmail(r.Context(), userId, entity.NewEmail)
		if err != nil {
			uh.serviceErrorHandler(r.Context(), w, err)
			return
		}

		response = convertUser(user.Id, user.Email, user.Nickname)

	} else {
		errorHandler(w, nil, http.StatusNotFound, "Page not found")
		return
	}

	renderJson(w, response, http.StatusOK)
}

func (uh *userHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateUserId(id); err != nil {
		errorHandler(w, nil, http.StatusBadRequest, err.Error())
		return
	}

	if targetId := r.Context().Value("user_id"); targetId != nil {
		if targetId != id {
			errorHandler(w, nil, http.StatusForbidden, "Access denied")
			return
		}
	}

	err := uh.us.DeleteUserService(r.Context(), id)
	if err != nil {
		uh.serviceErrorHandler(r.Context(), w, err)
		return
	}

	renderJson(w, responseUserId{Id: id}, http.StatusOK)
}

func (uh *userHandler) serviceErrorHandler(ctx context.Context, w http.ResponseWriter, err error) {
	logError, clientMessage := parseServiceError(uh.log, middleware.GetReqID(ctx), err)

	var code int
	if len(logError.message) > 0 {
		code = http.StatusInternalServerError
	} else {
		code = http.StatusBadRequest
		logError = nil
	}

	errorHandler(w, logError, code, clientMessage)
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

func errorHandler(w http.ResponseWriter, logError *logErrorType, code int, clientMessage string) {
	if logError != nil {
		logError.log.Error(logError.name+": "+logError.message, slog.String("request_id", logError.reqId))
	}

	renderJson(w, responseError{Error: clientMessage}, code)
}
