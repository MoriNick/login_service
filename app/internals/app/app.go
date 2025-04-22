package app

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	db "login/internals/database/postgres"
	"login/internals/database/repositories"
	us "login/internals/services/user"
	uh "login/internals/transport/handlers/user"
	"login/internals/transport/router"

	"login/pkg/logger"
)

type app struct {
	log     *logger.Logger
	storage *db.DB
	router  *http.ServeMux
	srv     *http.Server
}

func (a *app) initStorage() {
	storage, err := db.NewStorage()
	if err != nil {
		a.fatalServer(err)
	}
	a.storage = storage
}

func (a *app) initLayers() {
	userRepository := repositories.NewUserRepository(a.storage)
	userService := us.NewService(userRepository, a.log)
	userHandler := uh.GetHandler(userService, a.log)
	userHandler.Register(a.router)
}

func (a *app) startHTTP() {
	srv := &http.Server{
		Handler: a.router,
		Addr:    ":" + os.Getenv("PORT"),
	}

	a.log.Info("Starting server...")
	go func(s *http.Server) {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.fatalServer(err)
		}
	}(srv)

	a.srv = srv
}

func (a *app) fatalServer(err error) {
	a.log.Fatal("Fatal error", a.log.String("error", err.Error()))
}

func (a *app) shutdown() {
	a.log.Info("Shutdown application...")
	ctx, serverCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := a.srv.Shutdown(ctx)
	if err != nil {
		a.fatalServer(err)
	}
	serverCancel()

	a.storage.Close()
	a.log.Info("Application successful shutdown")
}

func newApp() *app {
	return &app{
		log:    logger.GetLogger(),
		router: router.NewRouter(),
	}
}

func Run() {
	app := newApp()

	app.initStorage()
	app.initLayers()
	app.startHTTP()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	<-c

	app.shutdown()
}
