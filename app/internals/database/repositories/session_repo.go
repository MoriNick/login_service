package repositories

import (
	"context"
	"errors"
	"login/pkg/session"
	"time"
)

type sessionRepo struct {
	st Storage
}

func NewSessionRepo(s Storage) *sessionRepo {
	return &sessionRepo{s}
}

func (sr sessionRepo) ReadBySessionId(ctx context.Context, sessionId string) (*session.Session, error) {
	sql := `select id, user_id, updated_at, last_activity_at from sessions where id = $1`
	session := session.Session{}

	if err := sr.st.QueryRow(ctx, sql, sessionId).
		Scan(
			&session.Id,
			&session.UserId,
			&session.LastUpdateAt,
			&session.LastActivityAt,
		); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &session, nil
}

func (sr sessionRepo) ReadByUserId(ctx context.Context, userId string) (*session.Session, error) {
	sql := `select id, user_id, updated_at, last_activity_at from sessions where user_id = $1`
	session := session.Session{}

	if err := sr.st.QueryRow(ctx, sql, userId).
		Scan(
			&session.Id,
			&session.UserId,
			&session.LastUpdateAt,
			&session.LastActivityAt,
		); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &session, nil
}

func (sr sessionRepo) Write(ctx context.Context, session *session.Session) (err error) {
	tx, err := sr.st.Begin(ctx)
	if err != nil {
		return
	}
	defer func() {
		switch err {
		case nil:
			err = tx.Commit(ctx)
		default:
			_ = tx.Rollback(ctx)
		}
	}()

	selectSQL := `select user_id from sessions where id = $1`
	insertSQL := `insert into sessions(id, user_id, updated_at, last_activity_at) values ($1, $2, $3, $4)`
	updateSQL := `update sessions set id = $1, updated_at = $2, last_activity_at = $3 where user_id = $4`
	var userId string

	if err := tx.QueryRow(ctx, selectSQL, session.Id).Scan(&userId); err != nil {
		if errors.Is(err, ErrNoRows) {
			if _, err := tx.Exec(ctx, insertSQL, session.Id, session.UserId, session.LastUpdateAt, session.LastActivityAt); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	if _, err := tx.Exec(ctx, updateSQL, session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId); err != nil {
		return err
	}

	return
}

func (sr sessionRepo) Update(ctx context.Context, session *session.Session) error {
	sql := `update sessions set id = $1, updated_at = $2, last_activity_at = $3 where user_id = $4`
	if _, err := sr.st.Exec(ctx, sql, session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId); err != nil {
		return err
	}

	return nil
}

func (sr sessionRepo) Destroy(ctx context.Context, sessionId string) error {
	sql := `delete from sessions where id = $1`
	if _, err := sr.st.Exec(ctx, sql, sessionId); err != nil {
		return err
	}

	return nil
}

func (sr sessionRepo) GC(ctx context.Context, absoluteExpiration time.Duration) error {
	sql := `delete from sessions where updated_at < $1`
	if _, err := sr.st.Exec(ctx, sql, time.Now().Add(-absoluteExpiration)); err != nil {
		return err
	}
	return nil
}
