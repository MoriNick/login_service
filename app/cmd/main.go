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
	"login/pkg/session"

	"github.com/go-chi/chi"
	"golang.org/x/sync/errgroup"
)

func main() {
	mainCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := newConfig()
	if err != nil {
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).Error("Configuration error", "error", err.Error())
		os.Exit(1)
	}

	l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(l)

	router := chi.NewRouter()

	storage, err := db.NewStorage(mainCtx, cfg.GetDBConfig())
	if err != nil {
		l.Error("Database error", "error", err.Error())
		os.Exit(1)
	}

	if err := uh.InitValidator(); err != nil {
		l.Error("Init validator error", "error", err.Error())
		os.Exit(1)
	}

	sessionManager := session.NewSessionManager(
		mainCtx,
		repo.NewSessionRepo(storage),
		time.Duration(10*time.Second), //gcInterval
		time.Duration(10*time.Minute), //idleExpiration
		time.Duration(30*time.Minute), //absoluteExpiration
		"session_id",                  //cookieName
	)

	userRepo := repo.NewUserRepo(storage)
	userService := us.NewService(userRepo)
	userHandler := uh.GetHandler(userService, sessionManager, l)
	userHandler.Register(router)

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
