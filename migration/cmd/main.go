package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const defaultPort = "5432"
const defaultSSLMode = "disable"

var (
	ErrEmptyHost     = errors.New("empty database host")
	ErrEmptyUser     = errors.New("empty database user")
	ErrEmptyPassword = errors.New("empty database password")
)

func connDBString() (string, error) {
	var host, port, user, password, sslmode string

	if host = os.Getenv("DB_HOST"); len(host) == 0 {
		return "", ErrEmptyHost
	}

	if port = os.Getenv("DB_PORT"); len(port) == 0 {
		port = defaultPort
	}

	if user = os.Getenv("DB_USER"); len(user) == 0 {
		return "", ErrEmptyUser
	}

	if password = os.Getenv("DB_PASSWORD"); len(password) == 0 {
		return "", ErrEmptyPassword
	}

	if sslmode = os.Getenv("DB_SSLMODE"); len(sslmode) == 0 {
		sslmode = defaultSSLMode
	}

	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/login_service?sslmode=%s",
		user,
		password,
		host,
		port,
		sslmode,
	), nil
}

func main() {
	sourcePath := "file://migrations"
	dbUrl, err := connDBString()
	if err != nil {
		log.Fatal(err)
	}

	migrator, err := migrate.New(sourcePath, dbUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer migrator.Close()

	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatal(err)
	}

	version, dirty, err := migrator.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Applied migration: %d, Dirty: %t\n", version, dirty)
}
