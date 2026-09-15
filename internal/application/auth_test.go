package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"erp/services/identity-service/internal/domain"
)

type memUsers struct {
	byID    map[string]domain.User
	byEmail map[string]domain.User
	n       int
}

func (m *memUsers) Create(_ context.Context, user domain.User) (domain.User, error) {
	m.n++
	user.ID = fmt.Sprintf("u%d", m.n)
	if m.byID == nil {
		m.byID = map[string]domain.User{}
		m.byEmail = map[string]domain.User{}
	}
	m.byID[user.ID] = user
	m.byEmail[user.Email] = user
	return user, nil
}

func (m *memUsers) GetByEmail(_ context.Context, email string) (domain.User, error) {
	u, ok := m.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (m *memUsers) GetByID(_ context.Context, id string) (domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (m *memUsers) List(context.Context) ([]domain.User, error) {
	out := make([]domain.User, 0, len(m.byID))
	for _, u := range m.byID {
		out = append(out, u)
	}
	return out, nil
}

func (m *memUsers) Update(_ context.Context, user domain.User) (domain.User, error) {
	cur, ok := m.byID[user.ID]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	delete(m.byEmail, cur.Email)
	m.byID[user.ID] = user
	m.byEmail[user.Email] = user
	return user, nil
}

func (m *memUsers) Count(context.Context) (int, error) { return len(m.byID), nil }

func (m *memUsers) Delete(_ context.Context, id string) error {
	u, ok := m.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	delete(m.byEmail, u.Email)
	delete(m.byID, id)
	return nil
}

type memRoles struct {
	byID   map[string]domain.Role
	byCode map[string]domain.Role
	n      int
}

func newMemRoles() *memRoles {
	m := &memRoles{byID: map[string]domain.Role{}, byCode: map[string]domain.Role{}}
	m.seed(domain.DefaultRoleCode, "Sem acesso", false)
	m.seed(domain.MasterRoleCode, "Master", true)
	return m
}

func (m *memRoles) seed(code, name string, isMaster bool) domain.Role {
	m.n++
	role := domain.Role{ID: fmt.Sprintf("r%d", m.n), Code: code, Name: name, IsMaster: isMaster}
	m.byID[role.ID] = role
	m.byCode[role.Code] = role
	return role
}

func (m *memRoles) Create(_ context.Context, role domain.Role) (domain.Role, error) {
	return m.seed(role.Code, role.Name, role.IsMaster), nil
}

func (m *memRoles) Update(_ context.Context, role domain.Role) (domain.Role, error) {
	m.byID[role.ID] = role
	m.byCode[role.Code] = role
	return role, nil
}

func (m *memRoles) Delete(_ context.Context, id string) error {
	delete(m.byCode, m.byID[id].Code)
	delete(m.byID, id)
	return nil
}

func (m *memRoles) GetByID(_ context.Context, id string) (domain.Role, error) {
	r, ok := m.byID[id]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

func (m *memRoles) GetByCode(_ context.Context, code string) (domain.Role, error) {
	r, ok := m.byCode[code]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

func (m *memRoles) List(context.Context) ([]domain.Role, error) {
	out := make([]domain.Role, 0, len(m.byID))
	for _, r := range m.byID {
		out = append(out, r)
	}
	return out, nil
}

func (m *memRoles) ModulePermissions(context.Context, string) ([]domain.ModulePermission, error) {
	return nil, nil
}

func (m *memRoles) MenuPermissions(context.Context, string) ([]domain.MenuPermission, error) {
	return nil, nil
}

func (m *memRoles) SetPermissions(context.Context, string, []domain.ModulePermission, []domain.MenuPermission) error {
	return nil
}

type memSessions struct{ n int }

func (m *memSessions) Create(_ context.Context, s domain.Session) (domain.Session, error) {
	m.n++
	s.ID = fmt.Sprintf("s%d", m.n)
	return s, nil
}

func (m *memSessions) Revoke(context.Context, string) error { return nil }

func (m *memSessions) RevokeAllForUser(context.Context, string) ([]string, error) { return nil, nil }

type memCache struct{}

func (m *memCache) Put(context.Context, string, string, time.Duration) error { return nil }
func (m *memCache) Delete(context.Context, string) error                    { return nil }

func newTestAuthService(users domain.UserRepository) *AuthService {
	roles := NewRoleService(newMemRoles())
	return NewAuthService(users, roles, &memSessions{}, &memCache{}, "secret", "erp-identity", time.Hour)
}

func TestCreateAndList(t *testing.T) {
	svc := newTestAuthService(&memUsers{})
	if _, err := svc.Create(context.Background(), "a@erp.local", "123", "A", ""); err != domain.ErrInvalid {
		t.Fatalf("%v", err)
	}
	u, err := svc.Create(context.Background(), "a@erp.local", "secret1", "Ana", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "secret1" || u.Name != "Ana" {
		t.Fatalf("%+v", u)
	}
	if _, err := svc.Create(context.Background(), "a@erp.local", "secret1", "Ana", ""); err != domain.ErrEmailTaken {
		t.Fatalf("%v", err)
	}
	list, err := svc.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %+v", err, list)
	}
}

func TestUpdateUser(t *testing.T) {
	repo := &memUsers{}
	svc := newTestAuthService(repo)
	u, err := svc.Create(context.Background(), "a@erp.local", "secret1", "Ana", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), "b@erp.local", "secret1", "Bia", ""); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Update(context.Background(), u.ID, "a2@erp.local", "", "Ana 2", u.RoleID, domain.DefaultRoleCode)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "a2@erp.local" || got.Name != "Ana 2" || got.PasswordHash != u.PasswordHash {
		t.Fatalf("%+v", got)
	}
	if _, err := svc.Update(context.Background(), u.ID, "b@erp.local", "", "Ana", u.RoleID, domain.DefaultRoleCode); err != domain.ErrEmailTaken {
		t.Fatalf("%v", err)
	}
	if _, err := svc.Update(context.Background(), u.ID, "a2@erp.local", "123", "Ana", u.RoleID, domain.DefaultRoleCode); err != domain.ErrInvalid {
		t.Fatalf("%v", err)
	}
}
