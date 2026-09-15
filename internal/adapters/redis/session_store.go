package redisadapter

import (
	"context"
	"time"

	"erp/pkg/rbac"

	"github.com/redis/go-redis/v9"
)

type SessionStore struct {
	client *redis.Client
}

func NewSessionStore(client *redis.Client) *SessionStore {
	return &SessionStore{client: client}
}

func (s *SessionStore) Put(ctx context.Context, sessionID, userID string, ttl time.Duration) error {
	return s.client.Set(ctx, rbac.SessionKey(sessionID), userID, ttl).Err()
}

func (s *SessionStore) Delete(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, rbac.SessionKey(sessionID)).Err()
}
