package postgres

import (
	"context"
	"login/internals/database/repositories"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool   *pgxpool.Pool
	config *pgxpool.Config
}

func NewStorage(ctx context.Context, cfg *DBConfig) (*DB, error) {
	config := initConfig(cfg.ConnString())
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	err = pool.Ping(ctx)
	return &DB{pool, config}, err
}

func initConfig(connString string) *pgxpool.Config {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil
	}

	return config
}

func (p *DB) Acquire(ctx context.Context) (c repositories.Conn, err error) {
	return p.pool.Acquire(ctx)
}

func (p *DB) Close() {
	p.pool.Close()
}
