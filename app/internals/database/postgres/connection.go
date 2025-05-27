package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewStorage(ctx context.Context, cfg *DBConfig) (*pgxpool.Pool, error) {
	config := initConfig(cfg.ConnString())
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	err = pool.Ping(ctx)
	return pool, err
}

func initConfig(connString string) *pgxpool.Config {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil
	}

	config.MaxConns = 4
	config.MinConns = 2
	config.MaxConnIdleTime = time.Duration(10 * time.Minute)
	config.HealthCheckPeriod = time.Duration(10 * time.Minute)

	return config
}
