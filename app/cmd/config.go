package main

import (
	db "login/internals/database/postgres"
	"os"
)

const defaultPort = "5000"

type Config struct {
	Host     string
	Port     string
	dbConfig *db.DBConfig
}

func NewConfig() (*Config, error) {
	cfg := &Config{}

	cfg.Host = os.Getenv("HOST")

	if cfg.Port = os.Getenv("PORT"); len(cfg.Port) == 0 {
		cfg.Port = defaultPort
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
