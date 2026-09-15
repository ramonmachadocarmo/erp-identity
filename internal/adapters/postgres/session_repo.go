package postgres

import (
	"context"

	"erp/services/identity-service/internal/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

func (r *SessionRepo) Create(ctx context.Context, s domain.Session) (domain.Session, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4)
		RETURNING id, issued_at
	`, s.UserID, s.ExpiresAt, s.UserAgent, s.IP).Scan(&s.ID, &s.IssuedAt)
	return s, err
}

func (r *SessionRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id=$1 AND revoked_at IS NULL
		RETURNING id
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
