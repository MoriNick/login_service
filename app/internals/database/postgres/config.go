package postgres

import (
	"errors"
	"fmt"
	"os"
)

const defaultPort = "5432"
const defaultSSLMode = "disable"

var (
	ErrEmptyHost     = errors.New("empty database host")
	ErrEmptyUser     = errors.New("empty database user")
	ErrEmptyPassword = errors.New("empty database password")
)

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	SSLMode  string
}

func NewDBConfig() (*DBConfig, error) {
	cfg := &DBConfig{}

	if cfg.Host = os.Getenv("DB_HOST"); len(cfg.Host) == 0 {
		return nil, ErrEmptyHost
	}

	if cfg.Port = os.Getenv("DB_PORT"); len(cfg.Port) == 0 {
		cfg.Port = defaultPort
	}

	if cfg.User = os.Getenv("DB_USER"); len(cfg.User) == 0 {
		return nil, ErrEmptyUser
	}

	if cfg.Password = os.Getenv("DB_PASSWORD"); len(cfg.Password) == 0 {
		return nil, ErrEmptyPassword
	}

	if cfg.SSLMode = os.Getenv("DB_SSLMODE"); len(cfg.SSLMode) == 0 {
		cfg.SSLMode = defaultSSLMode
	}

	return cfg, nil
}

func (cfg *DBConfig) ConnString() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/login_service?sslmode=%s",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.SSLMode,
	)
}
