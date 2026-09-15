package postgres

import (
	"context"
	"errors"

	"erp/services/identity-service/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

const selectUser = `
	SELECT u.id, u.email, u.password_hash, u.name, u.role_id, u.created_at, r.code, r.name
	FROM users u JOIN roles r ON r.id = u.role_id
`

func (r *UserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, name, role_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`, user.Email, user.PasswordHash, user.Name, user.RoleID).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return domain.User{}, err
	}
	return r.GetByID(ctx, user.ID)
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	return r.scan(ctx, selectUser+` WHERE u.email=$1`, email)
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (domain.User, error) {
	return r.scan(ctx, selectUser+` WHERE u.id=$1`, id)
}

func (r *UserRepo) List(ctx context.Context) ([]domain.User, error) {
	rows, err := r.pool.Query(ctx, selectUser+` ORDER BY u.name, u.email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.RoleID, &u.CreatedAt, &u.RoleCode, &u.RoleName); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *UserRepo) Update(ctx context.Context, user domain.User) (domain.User, error) {
	_, err := r.pool.Exec(ctx, `
		UPDATE users SET email=$2, password_hash=$3, name=$4, role_id=$5
		WHERE id=$1
	`, user.ID, user.Email, user.PasswordHash, user.Name, user.RoleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	return r.GetByID(ctx, user.ID)
}

func (r *UserRepo) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

func (r *UserRepo) scan(ctx context.Context, q string, arg any) (domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, q, arg).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.RoleID, &u.CreatedAt, &u.RoleCode, &u.RoleName)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	return u, err
}
