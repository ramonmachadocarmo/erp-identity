package domain

import (
	"context"
	"time"
)

// Session is one login. ExpiresAt is its absolute end (SESSION_MAX_TTL after login); the refresh
// token slides inside that limit — see RefreshExpiresAt — and rotates on every use.
type Session struct {
	ID               string
	UserID           string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	UserAgent        string
	IP               string
	RefreshHash      string
	PrevRefreshHash  string
	RefreshRotatedAt *time.Time
	RefreshExpiresAt time.Time
}

// SessionRepository is the durable, Postgres-backed audit record of every login.
type SessionRepository interface {
	Create(ctx context.Context, s Session) (Session, error)
	Revoke(ctx context.Context, id string) error
	// RevokeAllForUser revokes every still-active session for a user (e.g. on
	// account deletion) and returns their ids so the caller can also evict the
	// matching fast-lookup entries from SessionCache.
	RevokeAllForUser(ctx context.Context, userID string) ([]string, error)
	// GetByRefreshHash finds the session whose current OR previous refresh token hash matches;
	// matchedPrev reports which one, so a rotated-out token can be told apart from the live one.
	GetByRefreshHash(ctx context.Context, hash string) (s Session, matchedPrev bool, err error)
	// RotateRefresh installs newHash as the current refresh token (prevHash becomes the previous
	// one) and slides the refresh expiry. It only touches sessions that are not revoked.
	RotateRefresh(ctx context.Context, id, prevHash, newHash string, expiresAt time.Time) error
}

// SessionCache is the fast, Redis-backed per-request existence check.
type SessionCache interface {
	Put(ctx context.Context, sessionID, userID string, ttl time.Duration) error
	Delete(ctx context.Context, sessionID string) error
}
