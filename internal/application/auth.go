package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"erp/pkg/rbac"
	"erp/services/identity-service/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Lifetimes are the three clocks of a login: the short-lived access JWT, the refresh token that
// renews it (slides on every use, rotating), and the session's absolute maximum.
type Lifetimes struct {
	Access     time.Duration // access JWT, e.g. 5m
	Refresh    time.Duration // refresh token window, renewed on each refresh, e.g. 8h
	SessionMax time.Duration // hard cap from login, e.g. 12h
}

// refreshReuseGrace tolerates two tabs refreshing with the same token at nearly the same moment.
const refreshReuseGrace = 10 * time.Second

// Tokens is what a login/refresh hands to the client.
type Tokens struct {
	Access    string
	Refresh   string
	ExpiresIn int // access token lifetime, seconds
}

type AuthService struct {
	users     domain.UserRepository
	roles     *RoleService
	sessions  domain.SessionRepository
	cache     domain.SessionCache
	secret    string
	issuer    string
	lifetimes Lifetimes
}

func NewAuthService(users domain.UserRepository, roles *RoleService, sessions domain.SessionRepository, cache domain.SessionCache, secret, issuer string, lifetimes Lifetimes) *AuthService {
	return &AuthService{users: users, roles: roles, sessions: sessions, cache: cache, secret: secret, issuer: issuer, lifetimes: lifetimes}
}

func newRefreshToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashRefresh(token), nil
}

func hashRefresh(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create makes a new user. roleID empty resolves to the default no-access role.
// The public Register() path always calls this with roleID="" — a caller must
// never be able to choose their own role through self-registration.
func (s *AuthService) Create(ctx context.Context, email, password, name, roleID string) (domain.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if email == "" || len(password) < 6 {
		return domain.User{}, domain.ErrInvalid
	}
	if name == "" {
		name = email
	}
	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		return domain.User{}, domain.ErrEmailTaken
	}
	role, err := s.resolveRole(ctx, roleID)
	if err != nil {
		return domain.User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return domain.User{}, err
	}
	return s.users.Create(ctx, domain.User{Email: email, PasswordHash: string(hash), Name: name, RoleID: role.ID})
}

func (s *AuthService) resolveRole(ctx context.Context, roleID string) (domain.Role, error) {
	if roleID == "" {
		return s.roles.GetByCode(ctx, domain.DefaultRoleCode)
	}
	return s.roles.Get(ctx, roleID)
}

func (s *AuthService) Register(ctx context.Context, email, password, name string) (domain.User, Tokens, error) {
	return s.registerWithRole(ctx, email, password, name, "", "", "")
}

func (s *AuthService) registerWithRole(ctx context.Context, email, password, name, roleID, userAgent, ip string) (domain.User, Tokens, error) {
	user, err := s.Create(ctx, email, password, name, roleID)
	if err != nil {
		return domain.User{}, Tokens{}, err
	}
	tokens, err := s.startSession(ctx, user, userAgent, ip)
	return user, tokens, err
}

func (s *AuthService) List(ctx context.Context) ([]domain.User, error) {
	out, err := s.users.List(ctx)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []domain.User{}, nil
	}
	return out, nil
}

// Update edits a user, including its role. actingRoleCode is the caller's own
// role (from their JWT) — only a MASTER may grant the MASTER role to anyone,
// and the last remaining MASTER user can never be demoted away from MASTER.
func (s *AuthService) Update(ctx context.Context, id, email, password, name, roleID, actingRoleCode string) (domain.User, error) {
	cur, err := s.users.GetByID(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if email == "" || name == "" {
		return domain.User{}, domain.ErrInvalid
	}
	if password != "" && len(password) < 6 {
		return domain.User{}, domain.ErrInvalid
	}
	if other, err := s.users.GetByEmail(ctx, email); err == nil && other.ID != id {
		return domain.User{}, domain.ErrEmailTaken
	}
	role, err := s.roles.Get(ctx, roleID)
	if err != nil {
		return domain.User{}, domain.ErrInvalid
	}
	if role.IsMaster && actingRoleCode != domain.MasterRoleCode {
		return domain.User{}, domain.ErrForbidden
	}
	if cur.RoleCode == domain.MasterRoleCode && role.Code != domain.MasterRoleCode {
		if n, err := s.countMasters(ctx); err != nil || n <= 1 {
			return domain.User{}, domain.ErrLastMaster
		}
	}
	cur.Email = email
	cur.Name = name
	cur.RoleID = role.ID
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return domain.User{}, err
		}
		cur.PasswordHash = string(hash)
	}
	return s.users.Update(ctx, cur)
}

// Delete removes a user, refusing to remove the last remaining MASTER user (the
// same guard as demoting them away from MASTER — either way the system would be
// left with zero accounts able to bypass the permission matrix). Any of the
// user's still-active sessions are revoked first, so an already-issued token
// stops working immediately rather than lingering until natural expiry.
func (s *AuthService) Delete(ctx context.Context, id string) error {
	cur, err := s.users.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if cur.RoleCode == domain.MasterRoleCode {
		if n, err := s.countMasters(ctx); err != nil || n <= 1 {
			return domain.ErrLastMaster
		}
	}
	ids, err := s.sessions.RevokeAllForUser(ctx, id)
	if err != nil {
		return err
	}
	for _, sid := range ids {
		_ = s.cache.Delete(ctx, sid)
	}
	return s.users.Delete(ctx, id)
}

func (s *AuthService) countMasters(ctx context.Context) (int, error) {
	all, err := s.users.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range all {
		if u.RoleCode == domain.MasterRoleCode {
			n++
		}
	}
	return n, nil
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (domain.User, Tokens, error) {
	user, err := s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return domain.User{}, Tokens{}, domain.ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return domain.User{}, Tokens{}, domain.ErrInvalidCredentials
	}
	tokens, err := s.startSession(ctx, user, userAgent, ip)
	return user, tokens, err
}

// startSession creates the session (with its first refresh token) and mints the access JWT.
func (s *AuthService) startSession(ctx context.Context, user domain.User, userAgent, ip string) (Tokens, error) {
	refresh, refreshHash, err := newRefreshToken()
	if err != nil {
		return Tokens{}, err
	}
	now := time.Now()
	sessionEnd := now.Add(s.lifetimes.SessionMax)
	sess, err := s.sessions.Create(ctx, domain.Session{
		UserID: user.ID, ExpiresAt: sessionEnd, UserAgent: userAgent, IP: ip,
		RefreshHash: refreshHash, RefreshExpiresAt: earlier(now.Add(s.lifetimes.Refresh), sessionEnd),
	})
	if err != nil {
		return Tokens{}, err
	}
	if err := s.cache.Put(ctx, sess.ID, user.ID, s.lifetimes.SessionMax); err != nil {
		return Tokens{}, err
	}
	access, err := s.token(ctx, user, sess.ID)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{Access: access, Refresh: refresh, ExpiresIn: int(s.lifetimes.Access.Seconds())}, nil
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Refresh trades a valid refresh token for a new access JWT and a new (rotated) refresh token.
// The user and their role permissions are re-read, so permission changes reach a logged-in user
// within one access-token lifetime. A refresh token that was already rotated out and is presented
// again outside the grace window means it leaked: the whole session is revoked.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (domain.User, Tokens, error) {
	if refreshToken == "" {
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	hash := hashRefresh(refreshToken)
	sess, matchedPrev, err := s.sessions.GetByRefreshHash(ctx, hash)
	if err != nil {
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	now := time.Now()
	if sess.RevokedAt != nil {
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.RefreshExpiresAt) {
		_ = s.revokeSession(ctx, sess.ID)
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	if matchedPrev && (sess.RefreshRotatedAt == nil || now.Sub(*sess.RefreshRotatedAt) > refreshReuseGrace) {
		_ = s.revokeSession(ctx, sess.ID)
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		_ = s.revokeSession(ctx, sess.ID)
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	newRefresh, newHash, err := newRefreshToken()
	if err != nil {
		return domain.User{}, Tokens{}, err
	}
	if err := s.sessions.RotateRefresh(ctx, sess.ID, hash, newHash, earlier(now.Add(s.lifetimes.Refresh), sess.ExpiresAt)); err != nil {
		return domain.User{}, Tokens{}, domain.ErrInvalidRefresh
	}
	// Re-put the fast-lookup entry: keeps the session alive for the gateway and restores it if
	// the cache was flushed since login.
	if err := s.cache.Put(ctx, sess.ID, user.ID, sess.ExpiresAt.Sub(now)); err != nil {
		return domain.User{}, Tokens{}, err
	}
	access, err := s.token(ctx, user, sess.ID)
	if err != nil {
		return domain.User{}, Tokens{}, err
	}
	return user, Tokens{Access: access, Refresh: newRefresh, ExpiresIn: int(s.lifetimes.Access.Seconds())}, nil
}

func (s *AuthService) revokeSession(ctx context.Context, sessionID string) error {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	return s.cache.Delete(ctx, sessionID)
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	return s.cache.Delete(ctx, sessionID)
}

func (s *AuthService) Me(ctx context.Context, id string) (domain.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *AuthService) MenuPermissions(ctx context.Context, roleID string) (map[string]int, error) {
	return s.roles.MenuMap(ctx, roleID)
}

func (s *AuthService) SeedAdmin(ctx context.Context, password string) error {
	n, err := s.users.Count(ctx)
	if err != nil || n > 0 {
		return err
	}
	master, err := s.roles.GetByCode(ctx, domain.MasterRoleCode)
	if err != nil {
		return err
	}
	_, _, err = s.registerWithRole(ctx, "admin@erp.local", password, "Admin", master.ID, "", "")
	return err
}

func (s *AuthService) token(ctx context.Context, user domain.User, sessionID string) (string, error) {
	modules, err := s.roles.ModuleMap(ctx, user.RoleID)
	if err != nil {
		return "", err
	}
	claims := rbac.Claims{
		Email: user.Email, Name: user.Name, RoleCode: user.RoleCode,
		Modules: modules, SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			Issuer:    s.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.lifetimes.Access)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(s.secret))
}
