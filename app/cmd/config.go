package main

import (
	"log/slog"
	db "login/internals/database/postgres"
	"os"
)

const defaultPort = "5000"
const defaultLogLevel = slog.LevelInfo

type Config struct {
	Host     string
	Port     string
	LogLevel slog.Level
	dbConfig *db.DBConfig
}

var logLevelMap = map[string]slog.Level{
	"DEBUG": slog.LevelDebug,
	"INFO":  slog.LevelInfo,
	"WARN":  slog.LevelWarn,
	"ERROR": slog.LevelError,
}

func newConfig() (*Config, error) {
	cfg := &Config{}

	cfg.Host = os.Getenv("HOST")

	if cfg.Port = os.Getenv("PORT"); len(cfg.Port) == 0 {
		cfg.Port = defaultPort
	}

	var ok bool
	if cfg.LogLevel, ok = logLevelMap[os.Getenv("LOG_LEVEL")]; !ok {
		cfg.LogLevel = defaultLogLevel
	}

	dbConfig, err := db.NewDBConfig()
	if err != nil {
		return nil, err
	}
	cfg.dbConfig = dbConfig

	return cfg, nil
}

func (c Config) GetDBConfig() *db.DBConfig {
	return c.dbConfig
}
