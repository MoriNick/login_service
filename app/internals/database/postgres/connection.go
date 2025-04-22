package postgres

import (
	"context"
	"login/internals/database/repositories"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool   *pgxpool.Pool
	config *pgxpool.Config
}

func NewStorage() (*DB, error) {
	config := initConfig()
	pool, _ := pgxpool.NewWithConfig(context.Background(), config)
	err := pool.Ping(context.Background())
	return &DB{pool, config}, err
}

func initConfig() *pgxpool.Config {
	config, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
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
