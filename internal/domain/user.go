package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailTaken         = errors.New("email already registered")
	ErrNotFound           = errors.New("not found")
	ErrInvalid            = errors.New("invalid")
	// ErrInvalidRefresh: unknown, expired, revoked or reused refresh token — the client must log in again.
	ErrInvalidRefresh = errors.New("invalid refresh token")
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	RoleID       string
	RoleCode     string // populated by repo JOIN, not a DB column on users
	RoleName     string // populated by repo JOIN, not a DB column on users
	CreatedAt    time.Time
}

type UserRepository interface {
	Create(ctx context.Context, user User) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	List(ctx context.Context) ([]User, error)
	Update(ctx context.Context, user User) (User, error)
	Delete(ctx context.Context, id string) error
	Count(ctx context.Context) (int, error)
}
