package repositories

import (
	"context"
	"errors"
	"log"
	"login/internals/models"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"
)

func TestCreateUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^insert into users \\(id, email, nickname, password\\) values \\(uuid_generate_v4\\(\\), .1, .2, .3\\) returning id$"
	user := struct {
		email    string
		nickname string
		password string
	}{"email", "nickname", "password"}

	type expResultType struct {
		id  string
		err error
	}

	cases := []struct {
		name        string
		queryError  error
		returningId string
		expResult   *expResultType
	}{
		{
			name:       "return_error",
			queryError: errors.New("something error"),
			expResult:  &expResultType{"", errors.New("something error")},
		},
		{
			name:        "return_without_error",
			returningId: "u_id",
			expResult:   &expResultType{"u_id", nil},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(user.email, user.nickname, user.password).
					WillReturnError(tCase.queryError)
			} else if len(tCase.returningId) > 0 {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(user.email, user.nickname, user.password).
					WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(tCase.returningId))
			}

			id, err := repo.CreateUser(context.Background(), user.email, user.nickname, user.password)

			require.Equal(t, tCase.expResult.id, id)
			require.Equal(t, tCase.expResult.err, err)
		})
	}
}

func TestSelectUserById(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^select id, email, nickname, password from users where id = .1$"
	inputId := "user_id"

	type expResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		queryError  error
		queryResult *pgxmock.Rows
		expResult   *expResultType
	}{
		{
			name:        "select_return_empty_row",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}),
			expResult:   &expResultType{nil, nil},
		},
		{
			name:       "select_return_error",
			queryError: errors.New("something error"),
			expResult:  &expResultType{nil, errors.New("something error")},
		},
		{
			name:        "return_without_errors",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}).AddRow(inputId, "email", "nickname", "password"),
			expResult:   &expResultType{&models.User{"user_id", "email", "nickname", "password"}, nil},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputId).
					WillReturnError(tCase.queryError)
			} else if tCase.queryResult != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputId).
					WillReturnRows(tCase.queryResult)
			}

			user, err := repo.SelectUserById(context.Background(), inputId)

			require.Equal(t, tCase.expResult.user, user)
			require.Equal(t, tCase.expResult.err, err)
		})
	}
}

func TestSelectAllUsers(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^select id, email, nickname, password from users limit .1 offset .2"
	columns := []string{"id", "email", "nickname", "password"}
	var inputLimit uint64 = 10
	var inputOffset uint64 = 12

	type expResultType struct {
		users []models.User
		err   error
	}

	cases := []struct {
		name       string
		queryError error
		queryRows  *pgxmock.Rows
		expResult  *expResultType
	}{
		{
			name:       "query_return_error",
			queryError: errors.New("something error"),
			queryRows:  pgxmock.NewRows(columns),
			expResult:  &expResultType{nil, errors.New("something error")},
		},
		{
			name:      "query_return_empty_rows",
			queryRows: pgxmock.NewRows(columns),
			expResult: &expResultType{[]models.User{}, nil},
		},
		{
			name:      "scan_return_error",
			queryRows: pgxmock.NewRows(columns).AddRow("id", "email", "nickname", "password").RowError(0, errors.New("row error")),
			expResult: &expResultType{nil, errors.New("row error")},
		},
		{
			name:      "return_without_errors",
			queryRows: pgxmock.NewRows(columns).AddRow("id", "email", "nickname", "password"),
			expResult: &expResultType{users: []models.User{{"id", "email", "nickname", "password"}}},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputLimit, inputOffset).
					WillReturnError(tCase.queryError)
			} else if tCase.queryRows != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputLimit, inputOffset).
					WillReturnRows(tCase.queryRows)
			}

			users, err := repo.SelectAllUsers(context.Background(), inputLimit, inputOffset)

			require.Equal(t, tCase.expResult.err, err)
			require.Equal(t, tCase.expResult.users, users)
		})
	}
}

func TestSelectUserByEmail(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^select id, email, nickname, password from users where email = .1$"
	inputEmail := "email"

	type expResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		queryError  error
		queryResult *pgxmock.Rows
		expResult   *expResultType
	}{
		{
			name:        "select_return_empty_row",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}),
			expResult:   &expResultType{nil, nil},
		},
		{
			name:       "select_return_error",
			queryError: errors.New("something error"),
			expResult:  &expResultType{nil, errors.New("something error")},
		},
		{
			name:        "return_without_errors",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}).AddRow("user_id", inputEmail, "nickname", "password"),
			expResult:   &expResultType{&models.User{"user_id", "email", "nickname", "password"}, nil},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputEmail).
					WillReturnError(tCase.queryError)
			} else if tCase.queryResult != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputEmail).
					WillReturnRows(tCase.queryResult)
			}

			user, err := repo.SelectUserByEmail(context.Background(), inputEmail)

			require.Equal(t, tCase.expResult.user, user)
			require.Equal(t, tCase.expResult.err, err)
		})
	}
}

func TestSelectUserByNickname(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^select id, email, nickname, password from users where nickname = .1$"
	inputNickname := "nickname"

	type expResultType struct {
		user *models.User
		err  error
	}

	cases := []struct {
		name        string
		queryError  error
		queryResult *pgxmock.Rows
		expResult   *expResultType
	}{
		{
			name:        "select_return_empty_row",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}),
			expResult:   &expResultType{nil, nil},
		},
		{
			name:       "select_return_error",
			queryError: errors.New("something error"),
			expResult:  &expResultType{nil, errors.New("something error")},
		},
		{
			name:        "return_without_errors",
			queryResult: pgxmock.NewRows([]string{"id", "email", "nickname", "password"}).AddRow("user_id", "email", inputNickname, "password"),
			expResult:   &expResultType{&models.User{"user_id", "email", "nickname", "password"}, nil},
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			if tCase.queryError != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputNickname).
					WillReturnError(tCase.queryError)
			} else if tCase.queryResult != nil {
				mock.ExpectQuery(sqlRegexp).
					WithArgs(inputNickname).
					WillReturnRows(tCase.queryResult)
			}

			user, err := repo.SelectUserByNickname(context.Background(), inputNickname)

			require.Equal(t, tCase.expResult.user, user)
			require.Equal(t, tCase.expResult.err, err)
		})
	}
}

func TestUpdateUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^update users set email = .1, nickname = .2, password = .3 where id = .4$"
	inputUser := &models.User{"id", "email", "nickname", "password"}

	cases := []struct {
		name       string
		queryError error
		expResult  error
	}{
		{
			name:       "query_return_error",
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
				mock.ExpectExec(sqlRegexp).
					WithArgs(inputUser.Email, inputUser.Nickname, inputUser.Password, inputUser.Id).
					WillReturnError(tCase.queryError)
			} else {
				mock.ExpectExec(sqlRegexp).
					WithArgs(inputUser.Email, inputUser.Nickname, inputUser.Password, inputUser.Id).
					WillReturnResult(pgxmock.NewResult("UPDATE", 1))
			}

			err := repo.UpdateUser(context.Background(), inputUser)

			require.Equal(t, tCase.expResult, err)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		log.Fatal(err)
	}
	defer mock.Close()

	repo := NewUserRepo(mock)
	sqlRegexp := "^delete from users where id = .1$"
	inputId := "user_id"

	cases := []struct {
		name       string
		queryError error
		expResult  error
	}{
		{
			name:       "query_return_error",
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
				mock.ExpectExec(sqlRegexp).
					WithArgs(inputId).
					WillReturnError(tCase.queryError)
			} else {
				mock.ExpectExec(sqlRegexp).
					WithArgs(inputId).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			}

			err := repo.DeleteUser(context.Background(), inputId)

			require.Equal(t, tCase.expResult, err)
		})
	}
}
