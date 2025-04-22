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

func (ur *UserRepository) CreateUser(email, nickname, password string) (string, error) {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return "", err
	}
	defer conn.Release()

	sql := `INSERT INTO users (id, email, nickname, password) VALUES(uuid_generate_v4(), $1, $2, $3) RETURNING id`
	var id string

	if err := conn.QueryRow(context.Background(), sql, email, nickname, password).Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

func (ur *UserRepository) SelectUserById(id string) (*models.User, error) {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE id=$1`
	var user models.User

	if err := conn.QueryRow(context.Background(), sql, id).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectAllUsers(limit, offset uint64) ([]models.User, error) {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users LIMIT $1 OFFSET $2`
	rows, err := conn.Query(context.Background(), sql, limit, offset)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

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

func (ur *UserRepository) SelectUserByEmail(email string) (*models.User, error) {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE email=$1`
	var user models.User

	if err := conn.QueryRow(context.Background(), sql, email).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) SelectUserByNickname(nickname string) (*models.User, error) {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	sql := `SELECT id, email, nickname, password FROM users WHERE nickname=$1`
	var user models.User

	if err := conn.QueryRow(context.Background(), sql, nickname).
		Scan(&user.Id, &user.Email, &user.Nickname, &user.Password); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (ur *UserRepository) UpdateUser(user *models.User) error {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `UPDATE users SET email=$1, nickname=$2, password=$3 WHERE id=$4`

	_, err = conn.Exec(context.Background(), sql, user.Email, user.Nickname, user.Password, user.Id)

	return err
}

func (ur *UserRepository) DeleteUser(id string) error {
	conn, err := ur.Acquire(context.Background())
	if err != nil {
		return err
	}
	defer conn.Release()

	sql := `DELETE FROM users WHERE id=$1`

	_, err = conn.Exec(context.Background(), sql, id)

	return err
}
