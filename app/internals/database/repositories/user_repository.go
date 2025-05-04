package repositories

import (
	"context"
	"errors"

	"login/internals/models"
)

type UserRepository struct {
	Storage
}

func NewUserRepository(s Storage) *UserRepository {
	return &UserRepository{s}
}

func (ur *UserRepository) CreateUser(ctx context.Context, email, nickname, password string) (string, error) {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Release()

	sql := `INSERT INTO users (id, email, nickname, password) VALUES(uuid_generate_v4(), $1, $2, $3) RETURNING id`
	var id string

	if err := conn.QueryRow(ctx, sql, email, nickname, password).Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

func (ur *UserRepository) SelectUserById(ctx context.Context, id string) (*models.User, error) {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE id=$1`
	var user models.User

	if err := conn.QueryRow(ctx, sql, id).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectAllUsers(ctx context.Context, limit, offset uint64) ([]models.User, error) {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users LIMIT $1 OFFSET $2`
	rows, err := conn.Query(ctx, sql, limit, offset)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.Id, &user.Email, &user.Nickname, &user.Password)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (ur *UserRepository) SelectUserByEmail(ctx context.Context, email string) (*models.User, error) {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE email=$1`
	var user models.User

	if err := conn.QueryRow(ctx, sql, email).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectUserByNickname(ctx context.Context, nickname string) (*models.User, error) {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE nickname=$1`
	var user models.User

	if err := conn.QueryRow(ctx, sql, nickname).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `UPDATE users SET email=$1, nickname=$2, password=$3 WHERE id=$4`

	_, err = conn.Exec(ctx, sql, user.Email, user.Nickname, user.Password, user.Id)

	return err
}

func (ur *UserRepository) DeleteUser(ctx context.Context, id string) error {
	conn, err := ur.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `DELETE FROM users WHERE id=$1`

	_, err = conn.Exec(ctx, sql, id)

	return err
}
