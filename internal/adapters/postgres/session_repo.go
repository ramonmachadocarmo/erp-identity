package postgres

import (
	"context"
	"errors"
	"time"

	"erp/services/identity-service/internal/domain"

	"github.com/jackc/pgx/v5"
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
		INSERT INTO sessions (user_id, expires_at, user_agent, ip, refresh_hash, refresh_expires_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6)
		RETURNING id, issued_at
	`, s.UserID, s.ExpiresAt, s.UserAgent, s.IP, s.RefreshHash, s.RefreshExpiresAt).Scan(&s.ID, &s.IssuedAt)
	return s, err
}

func (r *SessionRepo) GetByRefreshHash(ctx context.Context, hash string) (domain.Session, bool, error) {
	var s domain.Session
	var refresh, prev *string
	var refreshExp *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, issued_at, expires_at, revoked_at, refresh_hash, prev_refresh_hash, refresh_rotated_at, refresh_expires_at
		FROM sessions WHERE refresh_hash=$1 OR prev_refresh_hash=$1
		ORDER BY (refresh_hash=$1) DESC LIMIT 1
	`, hash).Scan(&s.ID, &s.UserID, &s.IssuedAt, &s.ExpiresAt, &s.RevokedAt, &refresh, &prev, &s.RefreshRotatedAt, &refreshExp)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, false, domain.ErrNotFound
	}
	if err != nil {
		return domain.Session{}, false, err
	}
	if refresh != nil {
		s.RefreshHash = *refresh
	}
	if prev != nil {
		s.PrevRefreshHash = *prev
	}
	if refreshExp != nil {
		s.RefreshExpiresAt = *refreshExp
	}
	return s, s.RefreshHash != hash, nil
}

func (r *SessionRepo) RotateRefresh(ctx context.Context, id, prevHash, newHash string, expiresAt time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE sessions
		SET prev_refresh_hash=$2, refresh_hash=$3, refresh_rotated_at=CURRENT_TIMESTAMP, refresh_expires_at=$4
		WHERE id=$1 AND revoked_at IS NULL
	`, id, prevHash, newHash, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidRefresh
	}
	return nil
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
