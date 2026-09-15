package application

import (
	"context"
	"strings"

	"erp/services/identity-service/internal/domain"
)

type RoleService struct {
	roles domain.RoleRepository
}

func NewRoleService(roles domain.RoleRepository) *RoleService {
	return &RoleService{roles: roles}
}

func (s *RoleService) Create(ctx context.Context, code, name string) (domain.Role, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	name = strings.TrimSpace(name)
	if code == "" || name == "" {
		return domain.Role{}, domain.ErrInvalid
	}
	if _, err := s.roles.GetByCode(ctx, code); err == nil {
		return domain.Role{}, domain.ErrCodeTaken
	}
	return s.roles.Create(ctx, domain.Role{Code: code, Name: name})
}

func (s *RoleService) Update(ctx context.Context, id, name string) (domain.Role, error) {
	cur, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return domain.Role{}, err
	}
	cur.Name = strings.TrimSpace(name)
	if cur.Name == "" {
		return domain.Role{}, domain.ErrInvalid
	}
	return s.roles.Update(ctx, cur)
}

func (s *RoleService) Delete(ctx context.Context, id string) error {
	role, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if role.IsMaster || role.IsSystem {
		return domain.ErrForbidden
	}
	return s.roles.Delete(ctx, id)
}

func (s *RoleService) List(ctx context.Context) ([]domain.Role, error) { return s.roles.List(ctx) }

func (s *RoleService) Get(ctx context.Context, id string) (domain.Role, error) {
	return s.roles.GetByID(ctx, id)
}

func (s *RoleService) GetByCode(ctx context.Context, code string) (domain.Role, error) {
	return s.roles.GetByCode(ctx, code)
}

func (s *RoleService) Permissions(ctx context.Context, roleID string) ([]domain.ModulePermission, []domain.MenuPermission, error) {
	modules, err := s.roles.ModulePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, err
	}
	menus, err := s.roles.MenuPermissions(ctx, roleID)
	return modules, menus, err
}

func (s *RoleService) SetPermissions(ctx context.Context, roleID string, modules []domain.ModulePermission, menus []domain.MenuPermission) error {
	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role.IsMaster {
		return domain.ErrForbidden // master's access is hardcoded, never matrix-driven
	}
	return s.roles.SetPermissions(ctx, roleID, modules, menus)
}

func (s *RoleService) ModuleMap(ctx context.Context, roleID string) (map[string]int, error) {
	perms, err := s.roles.ModulePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(perms))
	for _, p := range perms {
		m[p.Module] = p.Level
	}
	return m, nil
}

func (s *RoleService) MenuMap(ctx context.Context, roleID string) (map[string]int, error) {
	perms, err := s.roles.MenuPermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]int, len(perms))
	for _, p := range perms {
		m[p.MenuKey] = p.Level
	}
	return m, nil
}
