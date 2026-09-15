package domain

import (
	"context"
	"time"
)

type Session struct {
	ID        string
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	UserAgent string
	IP        string
}

// SessionRepository is the durable, Postgres-backed audit record of every login.
type SessionRepository interface {
	Create(ctx context.Context, s Session) (Session, error)
	Revoke(ctx context.Context, id string) error
	// RevokeAllForUser revokes every still-active session for a user (e.g. on
	// account deletion) and returns their ids so the caller can also evict the
	// matching fast-lookup entries from SessionCache.
	RevokeAllForUser(ctx context.Context, userID string) ([]string, error)
}

// SessionCache is the fast, Redis-backed per-request existence check.
type SessionCache interface {
	Put(ctx context.Context, sessionID, userID string, ttl time.Duration) error
	Delete(ctx context.Context, sessionID string) error
}
