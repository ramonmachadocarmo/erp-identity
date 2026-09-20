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

type memSessions struct {
	n    int
	byID map[string]*domain.Session
}

func (m *memSessions) Create(_ context.Context, s domain.Session) (domain.Session, error) {
	m.n++
	s.ID = fmt.Sprintf("s%d", m.n)
	if m.byID == nil {
		m.byID = map[string]*domain.Session{}
	}
	cp := s
	m.byID[s.ID] = &cp
	return s, nil
}

func (m *memSessions) Revoke(_ context.Context, id string) error {
	if s, ok := m.byID[id]; ok && s.RevokedAt == nil {
		now := time.Now()
		s.RevokedAt = &now
	}
	return nil
}

func (m *memSessions) RevokeAllForUser(context.Context, string) ([]string, error) { return nil, nil }

func (m *memSessions) GetByRefreshHash(_ context.Context, hash string) (domain.Session, bool, error) {
	for _, s := range m.byID {
		if s.RefreshHash == hash {
			return *s, false, nil
		}
	}
	for _, s := range m.byID {
		if s.PrevRefreshHash == hash {
			return *s, true, nil
		}
	}
	return domain.Session{}, false, domain.ErrNotFound
}

func (m *memSessions) RotateRefresh(_ context.Context, id, prevHash, newHash string, expiresAt time.Time) error {
	s, ok := m.byID[id]
	if !ok || s.RevokedAt != nil {
		return domain.ErrInvalidRefresh
	}
	now := time.Now()
	s.PrevRefreshHash, s.RefreshHash, s.RefreshRotatedAt, s.RefreshExpiresAt = prevHash, newHash, &now, expiresAt
	return nil
}

type memCache struct{ keys map[string]bool }

func (m *memCache) Put(_ context.Context, id, _ string, _ time.Duration) error {
	if m.keys == nil {
		m.keys = map[string]bool{}
	}
	m.keys[id] = true
	return nil
}
func (m *memCache) Delete(_ context.Context, id string) error {
	delete(m.keys, id)
	return nil
}

var testLifetimes = Lifetimes{Access: 5 * time.Minute, Refresh: time.Hour, SessionMax: 2 * time.Hour}

func newTestAuthService(users domain.UserRepository) *AuthService {
	svc, _, _ := newTestAuthServiceWithStores(users)
	return svc
}

func newTestAuthServiceWithStores(users domain.UserRepository) (*AuthService, *memSessions, *memCache) {
	roles := NewRoleService(newMemRoles())
	sessions, cache := &memSessions{}, &memCache{}
	return NewAuthService(users, roles, sessions, cache, "secret", "erp-identity", testLifetimes), sessions, cache
}

func loginTestUser(t *testing.T, svc *AuthService) Tokens {
	t.Helper()
	if _, err := svc.Create(context.Background(), "a@erp.local", "123456", "A", ""); err != nil {
		t.Fatal(err)
	}
	_, tokens, err := svc.Login(context.Background(), "a@erp.local", "123456", "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestLoginIssuesShortAccessTokenAndRefreshToken(t *testing.T) {
	svc, sessions, cache := newTestAuthServiceWithStores(&memUsers{})
	tokens := loginTestUser(t, svc)
	if tokens.Access == "" || tokens.Refresh == "" || tokens.ExpiresIn != 300 {
		t.Fatalf("%+v", tokens)
	}
	s := sessions.byID["s1"]
	if s.RefreshHash == "" || s.RefreshHash == tokens.Refresh {
		t.Fatal("only the hash of the refresh token may be stored")
	}
	if !cache.keys["s1"] {
		t.Fatal("session should be in the fast-lookup cache")
	}
}

func TestRefreshRotatesTokenAndRevokesOnReuse(t *testing.T) {
	svc, sessions, cache := newTestAuthServiceWithStores(&memUsers{})
	first := loginTestUser(t, svc)
	ctx := context.Background()

	_, second, err := svc.Refresh(ctx, first.Refresh)
	if err != nil || second.Refresh == first.Refresh || second.Access == "" {
		t.Fatalf("refresh: %v %+v", err, second)
	}
	// The rotated token is accepted once more only inside the short grace window...
	if _, _, err := svc.Refresh(ctx, first.Refresh); err != nil {
		t.Fatalf("grace window reuse should pass: %v", err)
	}
	// ...but reused after it, it means the token leaked: the whole session dies.
	old := time.Now().Add(-time.Minute)
	sessions.byID["s1"].RefreshRotatedAt = &old
	sessions.byID["s1"].PrevRefreshHash = hashRefresh(first.Refresh)
	if _, _, err := svc.Refresh(ctx, first.Refresh); err != domain.ErrInvalidRefresh {
		t.Fatalf("reuse must be rejected: %v", err)
	}
	if sessions.byID["s1"].RevokedAt == nil || cache.keys["s1"] {
		t.Fatal("reuse should revoke the session and evict it from the cache")
	}
	// The newest token is dead too, because its session was revoked.
	latest := sessions.byID["s1"].RefreshHash
	_ = latest
	if _, _, err := svc.Refresh(ctx, second.Refresh); err != domain.ErrInvalidRefresh {
		t.Fatalf("revoked session must not refresh: %v", err)
	}
}

func TestRefreshRejectsUnknownExpiredAndLoggedOut(t *testing.T) {
	svc, sessions, _ := newTestAuthServiceWithStores(&memUsers{})
	tokens := loginTestUser(t, svc)
	ctx := context.Background()
	if _, _, err := svc.Refresh(ctx, ""); err != domain.ErrInvalidRefresh {
		t.Fatalf("empty: %v", err)
	}
	if _, _, err := svc.Refresh(ctx, "nope"); err != domain.ErrInvalidRefresh {
		t.Fatalf("unknown: %v", err)
	}

	sessions.byID["s1"].RefreshExpiresAt = time.Now().Add(-time.Second)
	if _, _, err := svc.Refresh(ctx, tokens.Refresh); err != domain.ErrInvalidRefresh {
		t.Fatalf("expired refresh window: %v", err)
	}

	svc2, _, _ := newTestAuthServiceWithStores(&memUsers{})
	t2 := loginTestUser(t, svc2)
	if err := svc2.Logout(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc2.Refresh(ctx, t2.Refresh); err != domain.ErrInvalidRefresh {
		t.Fatalf("logged-out session: %v", err)
	}
}

func TestRefreshRestoresSessionCacheAfterFlush(t *testing.T) {
	svc, _, cache := newTestAuthServiceWithStores(&memUsers{})
	tokens := loginTestUser(t, svc)
	delete(cache.keys, "s1")
	if _, _, err := svc.Refresh(context.Background(), tokens.Refresh); err != nil {
		t.Fatal(err)
	}
	if !cache.keys["s1"] {
		t.Fatal("refresh should re-create the cache entry")
	}
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
