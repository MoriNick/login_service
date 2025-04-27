package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	db "login/internals/database/postgres"
	repo "login/internals/database/repositories"
	us "login/internals/services/user"
	uh "login/internals/transport/handlers/user"
	"login/pkg/logger"

	"golang.org/x/sync/errgroup"
)

func main() {
	mainCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	l := logger.GetLogger()
	router := http.NewServeMux()

	storage, err := db.NewStorage()
	if err != nil {
		l.Fatal("Database error", l.String("error", err.Error()))
	}

	userRepo := repo.NewUserRepository(storage)
	userService := us.NewService(userRepo, l)
	userHandler := uh.GetHandler(userService, l)
	userHandler.Register(router)

	srv := &http.Server{
		Addr:    net.JoinHostPort("", os.Getenv("PORT")),
		Handler: router,
		BaseContext: func(_ net.Listener) context.Context {
			return mainCtx
		},
	}

	g, gCtx := errgroup.WithContext(mainCtx)
	g.Go(func() error {
		l.Info("Starting server...", l.String("addr", net.JoinHostPort("localhost", os.Getenv("PORT"))))
		return srv.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		l.Info("Shutdown application...")
		ctx, serverCancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = srv.Shutdown(ctx)
		if err != nil {
			return err
		}
		serverCancel()
		storage.Close()
		l.Info("Application successful shutdown")
		return nil
	})

	if err := g.Wait(); err != nil && errors.Is(err, http.ErrServerClosed) {
		l.Fatal("Fatal error", l.String("error", err.Error()))
	}
}
