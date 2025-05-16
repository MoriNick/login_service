package postgres

import (
	"context"
	"errors"
	"login/internals/database/repositories"
	"login/pkg/session"
	"time"

	"github.com/jackc/pgx/v5"
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

func (p *DB) ReadBySessionId(ctx context.Context, sessionId string) (*session.Session, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `select id, user_id, updated_at, last_activity_at from sessions where id = $1`
	session := &session.Session{}

	if err := conn.QueryRow(ctx, sql, sessionId).
		Scan(
			&session.Id,
			&session.UserId,
			&session.LastUpdateAt,
			&session.LastActivityAt,
		); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return session, nil
}

func (p *DB) ReadByUserId(ctx context.Context, userId string) (*session.Session, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `select id, user_id, updated_at, last_activity_at from sessions where user_id = $1`
	session := &session.Session{}

	if err := conn.QueryRow(ctx, sql, userId).
		Scan(
			session.Id,
			session.UserId,
			session.LastUpdateAt,
			session.LastActivityAt,
		); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return session, nil
}

func (p *DB) Write(ctx context.Context, session *session.Session) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	readSQL := `select user_id from sessions where id = $1 `
	var userId string
	if err := conn.QueryRow(ctx, readSQL, session.Id).Scan(&userId); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sql := `insert into sessions(id, user_id, updated_at, last_activity_at) values ($1, $2, $3, $4)`
			if _, err := conn.Exec(ctx, sql, session.Id, session.UserId, session.LastUpdateAt, session.LastActivityAt); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	updateSQL := `update sessions set id = $1, updated_at = $2, last_activity_at = $3 where user_id = $4`
	if _, err := conn.Exec(ctx, updateSQL, session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId); err != nil {
		return err
	}

	return nil
}

func (p *DB) Update(ctx context.Context, session *session.Session) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `update sessions set id = $1, updated_at = $2, last_activity_at = $3 where user_id = $4`
	if _, err := conn.Exec(ctx, sql, session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId); err != nil {
		return err
	}

	return nil
}

func (p *DB) Destroy(ctx context.Context, sessionId string) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `delete from sessions where id = $1`
	if _, err := conn.Exec(ctx, sql, sessionId); err != nil {
		return err
	}

	return nil
}

func (p *DB) GC(ctx context.Context, absoluteExpiration time.Duration) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `delete from sessions where updated_at < $1`
	if _, err := conn.Exec(ctx, sql, absoluteExpiration); err != nil {
		return err
	}
	return nil
}
