package repositories

import (
	"context"
	"errors"

	"login/internals/models"
)

type UserRepository struct {
	st Storage
}

func NewUserRepo(s Storage) *UserRepository {
	return &UserRepository{s}
}

func (ur *UserRepository) CreateUser(ctx context.Context, email, nickname, password string) (string, error) {
	sql := `insert into users (id, email, nickname, password) values (uuid_generate_v4(), $1, $2, $3) returning id`
	var id string

	if err := ur.st.QueryRow(ctx, sql, email, nickname, password).Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

func (ur *UserRepository) SelectUserById(ctx context.Context, id string) (*models.User, error) {
	sql := `select id, email, nickname, password from users where id = $1`
	var user models.User

	if err := ur.st.QueryRow(ctx, sql, id).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error) {
	sql := `select id, email, nickname, password from users limit $1 offset $2`
	rows, err := ur.st.Query(ctx, sql, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]models.User, 0, limit)
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.Id, &user.Email, &user.Nickname, &user.Password)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return users, nil
}

func (ur *UserRepository) SelectUserByEmail(ctx context.Context, email string) (*models.User, error) {
	sql := `select id, email, nickname, password from users where email = $1`
	var user models.User

	if err := ur.st.QueryRow(ctx, sql, email).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectUserByNickname(ctx context.Context, nickname string) (*models.User, error) {
	sql := `select id, email, nickname, password from users where nickname = $1`
	var user models.User

	if err := ur.st.QueryRow(ctx, sql, nickname).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	sql := `update users set email = $1, nickname = $2, password = $3 where id = $4`

	_, err := ur.st.Exec(ctx, sql, user.Email, user.Nickname, user.Password, user.Id)

	return err
}

func (ur *UserRepository) DeleteUser(ctx context.Context, id string) error {
	sql := `delete from users where id = $1`

	_, err := ur.st.Exec(ctx, sql, id)

	return err
}
