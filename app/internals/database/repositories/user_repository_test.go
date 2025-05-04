package repositories

import (
	"context"
	"errors"
	"login/internals/models"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Protection queries and check of the use of the conn.Release()
func TestSQLAndReleaseConnection(t *testing.T) {
	const (
		queryRow = iota
		query
		exec
	)

	const (
		createUser = iota
		selectAll
		selectById
		selectByEmail
		selectByNickname
		updateUser
		deleteUser
	)

	sqlCreateUser := `^(INSERT INTO users \(id, email, nickname, password\) VALUES\(uuid_generate_v4\(\), \$1, \$2, \$3\) RETURNING id)$`
	sqlSelectAll := `^(SELECT id, email, nickname, password FROM users LIMIT \$1 OFFSET \$2)$`
	sqlSelectById := `^(SELECT id, email, nickname, password FROM users WHERE id=\$1)$`
	sqlSelectByEmail := `^(SELECT id, email, nickname, password FROM users WHERE email=\$1)$`
	sqlSelectByNickname := `^(SELECT id, email, nickname, password FROM users WHERE nickname=\$1)$`
	sqlUpdateUser := `^(UPDATE users SET email=\$1, nickname=\$2, password=\$3 WHERE id=\$4)$`
	sqlDeleteUser := `^(DELETE FROM users WHERE id=\$1)$`

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storageMock := NewMockStorage(ctrl)
	connMock := NewMockConn(ctrl)
	rowMock := NewMockRow(ctrl)
	repo := NewUserRepository(storageMock)

	testUser := models.User{
		Id:       "id",
		Email:    "email",
		Nickname: "nickname",
		Password: "pass",
	}
	ctx := context.Background()
	var limit uint64 = 10
	var offset uint64 = 0
	var cTag = newCommandTag("string")

	cases := []struct {
		name      string
		queryFunc int
		sql       string
		queryArgs []any
		testFunc  int
		expErr    error
	}{
		{
			name:      "check_sql_from_CreateUser",
			queryFunc: queryRow,
			sql:       sqlCreateUser,
			queryArgs: []any{testUser.Email, testUser.Nickname, testUser.Password},
			testFunc:  createUser,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_SelectAllUsers",
			queryFunc: query,
			sql:       sqlSelectAll,
			queryArgs: []any{limit, offset},
			testFunc:  selectAll,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_SelectById",
			queryFunc: queryRow,
			sql:       sqlSelectById,
			queryArgs: []any{testUser.Id},
			testFunc:  selectById,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_SelectByEmail",
			queryFunc: queryRow,
			sql:       sqlSelectByEmail,
			queryArgs: []any{testUser.Email},
			testFunc:  selectByEmail,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_SelectByNickname",
			queryFunc: queryRow,
			sql:       sqlSelectByNickname,
			queryArgs: []any{testUser.Nickname},
			testFunc:  selectByNickname,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_UpdateUser",
			queryFunc: exec,
			sql:       sqlUpdateUser,
			queryArgs: []any{testUser.Email, testUser.Nickname, testUser.Password, testUser.Id},
			testFunc:  updateUser,
			expErr:    errors.New("expected error"),
		},
		{
			name:      "check_sql_from_DeleteUser",
			queryFunc: exec,
			sql:       sqlDeleteUser,
			queryArgs: []any{testUser.Id},
			testFunc:  deleteUser,
			expErr:    errors.New("expected error"),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			storageMock.EXPECT().
				Acquire(gomock.AssignableToTypeOf(ctx)).
				Return(connMock, nil).
				Times(1)

			connMock.EXPECT().
				Release().
				Times(1)

			switch tCase.queryFunc {
			case queryRow:
				connMock.EXPECT().
					QueryRow(
						gomock.AssignableToTypeOf(ctx),
						gomock.Regex(tCase.sql),
						tCase.queryArgs,
					).
					Return(rowMock).
					Times(1)

			case query:
				connMock.EXPECT().
					Query(
						gomock.AssignableToTypeOf(ctx),
						gomock.Regex(tCase.sql),
						tCase.queryArgs,
					).
					Return(nil, tCase.expErr).
					Times(1)

			case exec:
				connMock.EXPECT().
					Exec(
						gomock.AssignableToTypeOf(ctx),
						gomock.Regex(tCase.sql),
						tCase.queryArgs,
					).
					Return(cTag, tCase.expErr).
					Times(1)
			}

			var err error
			switch tCase.testFunc {
			case createUser:
				rowMock.EXPECT().
					Scan(gomock.AssignableToTypeOf(&testUser.Id)).
					Return(tCase.expErr).
					Times(1)
				_, err = repo.CreateUser(ctx, testUser.Email, testUser.Nickname, testUser.Password)
			case selectById:
				rowMock.EXPECT().
					Scan(
						gomock.AssignableToTypeOf(&testUser.Id),
						gomock.AssignableToTypeOf(&testUser.Email),
						gomock.AssignableToTypeOf(&testUser.Nickname),
						gomock.AssignableToTypeOf(&testUser.Password),
					).
					Return(tCase.expErr).
					Times(1)
				_, err = repo.SelectUserById(ctx, testUser.Id)
			case selectByEmail:
				rowMock.EXPECT().
					Scan(
						gomock.AssignableToTypeOf(&testUser.Id),
						gomock.AssignableToTypeOf(&testUser.Email),
						gomock.AssignableToTypeOf(&testUser.Nickname),
						gomock.AssignableToTypeOf(&testUser.Password),
					).
					Return(tCase.expErr).
					Times(1)
				_, err = repo.SelectUserByEmail(ctx, testUser.Email)
			case selectByNickname:
				rowMock.EXPECT().
					Scan(
						gomock.AssignableToTypeOf(&testUser.Id),
						gomock.AssignableToTypeOf(&testUser.Email),
						gomock.AssignableToTypeOf(&testUser.Nickname),
						gomock.AssignableToTypeOf(&testUser.Password),
					).
					Return(tCase.expErr).
					Times(1)
				_, err = repo.SelectUserByNickname(ctx, testUser.Nickname)
			case selectAll:
				_, err = repo.SelectAllUsers(ctx, limit, offset)
			case updateUser:
				err = repo.UpdateUser(ctx, &testUser)
			case deleteUser:
				err = repo.DeleteUser(ctx, testUser.Id)
			}

			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
		})
	}
}
