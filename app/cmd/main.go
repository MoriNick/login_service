package main

import (
	"context"
	"errors"
	"log/slog"
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

	"github.com/go-chi/chi"
	"golang.org/x/sync/errgroup"
)

func main() {
	mainCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(l)
	router := chi.NewRouter()
	cfg, err := NewConfig()
	if err != nil {
		l.Error("Database configuration error", "error", err.Error())
		os.Exit(1)
	}

	DBConfig := cfg.GetDBConfig()
	storage, err := db.NewStorage(mainCtx, DBConfig)
	if err != nil {
		l.Error("Database error", "error", err.Error())
		os.Exit(1)
	}

	userRepo := repo.NewUserRepository(storage)
	userService := us.NewService(userRepo, l)
	userHandler := uh.GetHandler(userService, l)
	userHandler.Register(l, router)

	srv := &http.Server{
		Addr:    net.JoinHostPort(cfg.Host, cfg.Port),
		Handler: router,
		BaseContext: func(_ net.Listener) context.Context {
			return mainCtx
		},
	}

	g, gCtx := errgroup.WithContext(mainCtx)
	g.Go(func() error {
		l.Info("Starting server", "addr", net.JoinHostPort(cfg.Host, cfg.Port))
		return srv.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		l.Info("Shutdown application")
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
		l.Error("Fatal error", "error", err.Error())
		os.Exit(1)
	}
}
