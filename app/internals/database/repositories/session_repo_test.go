package repositories

import (
	"context"
	"errors"
	"log"
	"login/pkg/session"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
)

func TestReadBySessionId(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)
	queryRegexp := "^select (.+) from sessions where id = .1$"
	columns := []string{"id", "user_id", "updated_at", "last_activity_at"}
	tm := time.Now()

	type expResultType struct {
		session *session.Session
		err     error
	}

	cases := []struct {
		name      string
		rows      *pgxmock.Rows
		err       error
		expResult *expResultType
	}{
		{
			name:      "empty_rows",
			rows:      pgxmock.NewRows(columns),
			expResult: &expResultType{nil, nil},
		},
		{
			name:      "return_error",
			err:       errors.New("something error"),
			expResult: &expResultType{nil, errors.New("something error")},
		},
		{
			name: "without_errors",
			rows: pgxmock.NewRows(columns).AddRow("s_id", "u_id", tm, tm),
			expResult: &expResultType{
				session: &session.Session{
					Id:             "s_id",
					UserId:         "u_id",
					LastUpdateAt:   tm,
					LastActivityAt: tm,
				},
				err: nil,
			},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.err != nil {
				mock.ExpectQuery(queryRegexp).
					WithArgs("session_id").
					WillReturnError(tCase.err)
			} else if tCase.rows != nil {
				mock.ExpectQuery(queryRegexp).
					WithArgs("session_id").
					WillReturnRows(tCase.rows)
			}

			session, err := repo.ReadBySessionId(context.Background(), "session_id")

			require.Equal(t, session, tCase.expResult.session)
			if err != nil {
				require.Equal(t, tCase.expResult.err, err)
			}
		})
	}
}

func TestReadByUserId(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)
	queryRegexp := "^select (.+) from sessions where user_id = .1$"
	columns := []string{"id", "user_id", "updated_at", "last_activity_at"}
	tm := time.Now()

	type expResultType struct {
		session *session.Session
		err     error
	}

	cases := []struct {
		name      string
		rows      *pgxmock.Rows
		err       error
		expResult *expResultType
	}{
		{
			name:      "empty_rows",
			rows:      pgxmock.NewRows(columns),
			expResult: &expResultType{nil, nil},
		},
		{
			name:      "return_error",
			err:       errors.New("something error"),
			expResult: &expResultType{nil, errors.New("something error")},
		},
		{
			name: "without_errors",
			rows: pgxmock.NewRows(columns).AddRow("s_id", "u_id", tm, tm),
			expResult: &expResultType{
				session: &session.Session{
					Id:             "s_id",
					UserId:         "u_id",
					LastUpdateAt:   tm,
					LastActivityAt: tm,
				},
				err: nil,
			},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.err != nil {
				mock.ExpectQuery(queryRegexp).
					WithArgs("user_id").
					WillReturnError(tCase.err)
			} else if tCase.rows != nil {
				mock.ExpectQuery(queryRegexp).
					WithArgs("user_id").
					WillReturnRows(tCase.rows)
			}

			session, err := repo.ReadByUserId(context.Background(), "user_id")

			require.Equal(t, session, tCase.expResult.session)
			if err != nil {
				require.Equal(t, tCase.expResult.err, err)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)
	querySelectRegexp := "^select user_id from sessions where id = .1$"
	queryInsertRegexp := "^insert into sessions\\(id, user_id, updated_at, last_activity_at\\) values \\(.1, .2, .3, .4\\)$"
	queryUpdateRegexp := "^update sessions set id = .1, updated_at = .2, last_activity_at = .3 where user_id = .4$"
	emptyTestRow := pgxmock.NewRows([]string{"user_id"})
	testRow := pgxmock.NewRows([]string{"user_id"}).AddRow("u_id")
	tm := time.Now()

	cases := []struct {
		name             string
		session          *session.Session
		row              *pgxmock.Rows
		querySelectError error
		queryInsertError error
		queryUpdateError error
		expResult        error
	}{
		{
			name:             "select_return_error",
			session:          &session.Session{Id: "session_id"},
			querySelectError: errors.New("something error"),
			expResult:        errors.New("something error"),
		},
		{
			name:             "insert_return_error",
			session:          &session.Session{Id: "session_id"},
			row:              emptyTestRow,
			queryInsertError: errors.New("something error"),
			expResult:        errors.New("something error"),
		},
		{
			name:      "insert_return_without_errors",
			session:   &session.Session{Id: "session_id", UserId: "u_id", LastUpdateAt: tm, LastActivityAt: tm},
			row:       emptyTestRow,
			expResult: nil,
		},
		{
			name:             "update_return_error",
			session:          &session.Session{Id: "session_id", UserId: "u_id", LastUpdateAt: tm, LastActivityAt: tm},
			row:              testRow,
			queryUpdateError: errors.New("something error"),
			expResult:        errors.New("something error"),
		},
		{
			name:      "update_return_without_errors",
			session:   &session.Session{Id: "session_id", UserId: "u_id", LastUpdateAt: tm, LastActivityAt: tm},
			row:       testRow,
			expResult: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			mock.ExpectBegin()

			if tCase.querySelectError != nil {
				mock.ExpectQuery(querySelectRegexp).
					WithArgs("session_id").
					WillReturnError(tCase.querySelectError)
			} else if tCase.row != nil {
				mock.ExpectQuery(querySelectRegexp).
					WithArgs("session_id").
					WillReturnRows(tCase.row)
			}

			if tCase.queryInsertError != nil {
				mock.ExpectExec(queryInsertRegexp).
					WithArgs(tCase.session.Id, tCase.session.UserId, tCase.session.LastUpdateAt, tCase.session.LastActivityAt).
					WillReturnError(tCase.queryInsertError)
			} else if tCase.row == emptyTestRow {
				mock.ExpectExec(queryInsertRegexp).
					WithArgs(tCase.session.Id, tCase.session.UserId, tCase.session.LastUpdateAt, tCase.session.LastActivityAt).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			if tCase.queryUpdateError != nil {
				mock.ExpectExec(queryUpdateRegexp).
					WithArgs(tCase.session.Id, tCase.session.LastUpdateAt, tCase.session.LastActivityAt, tCase.session.UserId).
					WillReturnError(tCase.queryUpdateError)
			} else if tCase.row == testRow {
				testRow.AddRow("u_id")
				mock.ExpectExec(queryUpdateRegexp).
					WithArgs(tCase.session.Id, tCase.session.LastUpdateAt, tCase.session.LastActivityAt, tCase.session.UserId).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
			}

			if tCase.expResult == nil {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}

			err := repo.Write(context.Background(), tCase.session)
			require.Equal(t, tCase.expResult, err)
		})
	}
}

func TestUpdate(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)

	sql := "^update sessions set id = .1, updated_at = .2, last_activity_at = .3 where user_id = .4$"
	session := &session.Session{Id: "s_id", UserId: "u_id", LastUpdateAt: time.Now(), LastActivityAt: time.Now()}

	cases := []struct {
		name       string
		queryError error
		expResult  error
	}{
		{
			name:       "return_error",
			queryError: errors.New("something error"),
			expResult:  errors.New("something error"),
		},
		{
			name:      "return_without_errors",
			expResult: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectExec(sql).
					WithArgs(session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId).
					WillReturnError(tCase.queryError)
			} else {
				mock.ExpectExec(sql).
					WithArgs(session.Id, session.LastUpdateAt, session.LastActivityAt, session.UserId).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
			}

			err := repo.Update(context.Background(), session)

			require.Equal(t, tCase.expResult, err)
		})
	}
}

func TestDestroy(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)

	sql := "^delete from sessions where id = .1$"
	sessionId := "session_id"

	cases := []struct {
		name       string
		queryError error
		expResult  error
	}{
		{
			name:       "return_error",
			queryError: errors.New("something error"),
			expResult:  errors.New("something error"),
		},
		{
			name:      "return_without_errors",
			expResult: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectExec(sql).
					WithArgs(sessionId).
					WillReturnError(tCase.queryError)
			} else {
				mock.ExpectExec(sql).
					WithArgs(sessionId).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			}

			err := repo.Destroy(context.Background(), sessionId)

			require.Equal(t, tCase.expResult, err)
		})
	}
}

func TestGC(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewSessionRepo(mock)

	sql := "^delete from sessions where updated_at < .1$"
	absoluteExpiration := time.Duration(2 * time.Second)

	cases := []struct {
		name       string
		queryError error
		expResult  error
	}{
		{
			name:       "return_error",
			queryError: errors.New("something error"),
			expResult:  errors.New("something error"),
		},
		{
			name:      "return_without_errors",
			expResult: nil,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectExec(sql).
					WithArgs(pgxmock.AnyArg()).
					WillReturnError(tCase.queryError)
			} else {
				mock.ExpectExec(sql).
					WithArgs(pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			}

			err := repo.GC(context.Background(), absoluteExpiration)

			require.Equal(t, tCase.expResult, err)
		})
	}
}
