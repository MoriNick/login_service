package repositories

import (
	"context"

	db "github.com/jackc/pgx/v5"
	dbconn "github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNoRows = db.ErrNoRows
)

//go:generate mockgen -package repositories -source=storage.go -destination=storage_mock.go
type Storage interface {
	Acquire(ctx context.Context) (c Conn, err error)
	Close()
}

type Conn interface {
	Release()
	QueryRow(ctx context.Context, sql string, args ...any) db.Row
	Query(ctx context.Context, sql string, args ...any) (db.Rows, error)
	Exec(ctx context.Context, sql string, arguments ...any) (dbconn.CommandTag, error)
}

// used by mockgen
type Row interface {
	db.Row
}

// used by mockgen
type Rows interface {
	db.Rows
}

// used by TestSQLAndReleaseConnection()
var newCommandTag = dbconn.NewCommandTag
