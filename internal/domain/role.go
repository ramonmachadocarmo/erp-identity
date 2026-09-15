package domain

import (
	"context"
	"errors"
	"time"
)

const MasterRoleCode = "MASTER"
const DefaultRoleCode = "SEM_ACESSO"

var (
	ErrForbidden  = errors.New("forbidden")
	ErrLastMaster = errors.New("cannot remove the last MASTER user")
	ErrCodeTaken  = errors.New("role code already exists")
	ErrInUse      = errors.New("cannot delete: role is assigned to a user")
)

type Role struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	IsMaster  bool      `json:"is_master"`
	IsSystem  bool      `json:"is_system"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ModulePermission struct {
	Module string
	Level  int
}

type MenuPermission struct {
	MenuKey string
	Level   int
}

type RoleRepository interface {
	Create(ctx context.Context, role Role) (Role, error)
	Update(ctx context.Context, role Role) (Role, error)
	Delete(ctx context.Context, id string) error
	GetByID(ctx context.Context, id string) (Role, error)
	GetByCode(ctx context.Context, code string) (Role, error)
	List(ctx context.Context) ([]Role, error)
	ModulePermissions(ctx context.Context, roleID string) ([]ModulePermission, error)
	MenuPermissions(ctx context.Context, roleID string) ([]MenuPermission, error)
	SetPermissions(ctx context.Context, roleID string, modules []ModulePermission, menus []MenuPermission) error
}
