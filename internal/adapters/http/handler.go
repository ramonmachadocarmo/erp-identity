package httpadapter

import (
	"errors"
	"net/http"

	"erp/pkg/httpserver"
	"erp/services/identity-service/internal/application"
	"erp/services/identity-service/internal/domain"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	auth  *application.AuthService
	roles *application.RoleService
}

func New(auth *application.AuthService, roles *application.RoleService) *Handler {
	return &Handler{auth: auth, roles: roles}
}

func (h *Handler) RegisterRoutes(r *gin.Engine, jwt gin.HandlerFunc) {
	r.POST("/auth/register", h.register)
	r.POST("/auth/login", h.login)
	r.POST("/auth/refresh", h.refresh)
	r.GET("/auth/me", jwt, h.me)
	r.POST("/auth/logout", jwt, h.logout)
	r.GET("/users", jwt, h.list)
	r.POST("/users", jwt, h.create)
	r.PUT("/users/:id", jwt, h.update)
	r.DELETE("/users/:id", jwt, h.delete)
	r.GET("/roles", jwt, h.listRoles)
	r.POST("/roles", jwt, h.createRole)
	r.PUT("/roles/:id", jwt, h.updateRole)
	r.DELETE("/roles/:id", jwt, h.deleteRole)
	r.GET("/roles/:id/permissions", jwt, h.getPermissions)
	r.PUT("/roles/:id/permissions", jwt, h.setPermissions)
}

type credentials struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Name     string `json:"name"`
}

type userCreate struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Name     string `json:"name"`
	RoleID   string `json:"role_id" binding:"required"`
}

type userUpdate struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password"`
	Name     string `json:"name" binding:"required"`
	RoleID   string `json:"role_id" binding:"required"`
}

type roleInput struct {
	Code string `json:"code"`
	Name string `json:"name" binding:"required"`
}

type modulePermInput struct {
	Module string `json:"module"`
	Level  int    `json:"level"`
}

type menuPermInput struct {
	MenuKey string `json:"menu_key"`
	Level   int    `json:"level"`
}

type permissionsInput struct {
	Modules []modulePermInput `json:"modules"`
	Menus   []menuPermInput   `json:"menus"`
}

func (h *Handler) register(c *gin.Context) {
	var in credentials
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	if in.Name == "" {
		in.Name = in.Email
	}
	user, tokens, err := h.auth.Register(c.Request.Context(), in.Email, in.Password, in.Name)
	if errors.Is(err, domain.ErrEmailTaken) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, h.sessionResponse(c, user, tokens))
}

// sessionResponse is the shared login/register/refresh payload. "token" stays the access JWT so
// existing clients keep working until they adopt refresh_token.
func (h *Handler) sessionResponse(c *gin.Context, user domain.User, tokens application.Tokens) gin.H {
	menuPerms, _ := h.auth.MenuPermissions(c.Request.Context(), user.RoleID)
	return gin.H{
		"token": tokens.Access, "refresh_token": tokens.Refresh, "expires_in": tokens.ExpiresIn,
		"user": publicUser(user), "menu_permissions": menuPerms,
	}
}

func (h *Handler) login(c *gin.Context) {
	var in credentials
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	user, tokens, err := h.auth.Login(c.Request.Context(), in.Email, in.Password, c.GetHeader("User-Agent"), c.ClientIP())
	if err != nil {
		httpserver.Error(c, http.StatusUnauthorized, domain.ErrInvalidCredentials)
		return
	}
	c.JSON(http.StatusOK, h.sessionResponse(c, user, tokens))
}

func (h *Handler) refresh(c *gin.Context) {
	var in struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	user, tokens, err := h.auth.Refresh(c.Request.Context(), in.RefreshToken)
	if errors.Is(err, domain.ErrInvalidRefresh) {
		httpserver.Error(c, http.StatusUnauthorized, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, h.sessionResponse(c, user, tokens))
}

func (h *Handler) logout(c *gin.Context) {
	_ = h.auth.Logout(c.Request.Context(), c.GetString("session_id"))
	c.Status(http.StatusNoContent)
}

func (h *Handler) me(c *gin.Context) {
	user, err := h.auth.Me(c.Request.Context(), c.GetString("user_id"))
	if err != nil {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	// menu_permissions lets a client that only kept the token (mobile session
	// restore) refresh the role's menu levels without a new login.
	out := publicUser(user)
	out["menu_permissions"], _ = h.auth.MenuPermissions(c.Request.Context(), user.RoleID)
	c.JSON(http.StatusOK, out)
}

func (h *Handler) list(c *gin.Context) {
	out, err := h.auth.List(c.Request.Context())
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	pub := make([]gin.H, 0, len(out))
	for _, u := range out {
		pub = append(pub, publicUser(u))
	}
	c.JSON(http.StatusOK, pub)
}

func (h *Handler) create(c *gin.Context) {
	var in userCreate
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	user, err := h.auth.Create(c.Request.Context(), in.Email, in.Password, in.Name, in.RoleID)
	if errors.Is(err, domain.ErrEmailTaken) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if errors.Is(err, domain.ErrInvalid) {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, publicUser(user))
}

func (h *Handler) update(c *gin.Context) {
	var in userUpdate
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	user, err := h.auth.Update(c.Request.Context(), c.Param("id"), in.Email, in.Password, in.Name, in.RoleID, c.GetString("role"))
	if errors.Is(err, domain.ErrNotFound) {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, domain.ErrEmailTaken) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if errors.Is(err, domain.ErrForbidden) {
		httpserver.Error(c, http.StatusForbidden, err)
		return
	}
	if errors.Is(err, domain.ErrLastMaster) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if errors.Is(err, domain.ErrInvalid) {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, publicUser(user))
}

func (h *Handler) delete(c *gin.Context) {
	err := h.auth.Delete(c.Request.Context(), c.Param("id"))
	if errors.Is(err, domain.ErrNotFound) {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, domain.ErrLastMaster) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) listRoles(c *gin.Context) {
	out, err := h.roles.List(c.Request.Context())
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handler) createRole(c *gin.Context) {
	var in roleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	role, err := h.roles.Create(c.Request.Context(), in.Code, in.Name)
	if errors.Is(err, domain.ErrCodeTaken) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if errors.Is(err, domain.ErrInvalid) {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, role)
}

func (h *Handler) updateRole(c *gin.Context) {
	var in roleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	role, err := h.roles.Update(c.Request.Context(), c.Param("id"), in.Name)
	if errors.Is(err, domain.ErrNotFound) {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, domain.ErrInvalid) {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, role)
}

func (h *Handler) deleteRole(c *gin.Context) {
	err := h.roles.Delete(c.Request.Context(), c.Param("id"))
	if errors.Is(err, domain.ErrNotFound) {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, domain.ErrForbidden) {
		httpserver.Error(c, http.StatusForbidden, err)
		return
	}
	if errors.Is(err, domain.ErrInUse) {
		httpserver.Error(c, http.StatusConflict, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) getPermissions(c *gin.Context) {
	modules, menus, err := h.roles.Permissions(c.Request.Context(), c.Param("id"))
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"modules": modulePermsJSON(modules), "menus": menuPermsJSON(menus)})
}

func (h *Handler) setPermissions(c *gin.Context) {
	var in permissionsInput
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.Error(c, http.StatusBadRequest, err)
		return
	}
	modules := make([]domain.ModulePermission, 0, len(in.Modules))
	for _, m := range in.Modules {
		modules = append(modules, domain.ModulePermission{Module: m.Module, Level: m.Level})
	}
	menus := make([]domain.MenuPermission, 0, len(in.Menus))
	for _, m := range in.Menus {
		menus = append(menus, domain.MenuPermission{MenuKey: m.MenuKey, Level: m.Level})
	}
	err := h.roles.SetPermissions(c.Request.Context(), c.Param("id"), modules, menus)
	if errors.Is(err, domain.ErrForbidden) {
		httpserver.Error(c, http.StatusForbidden, err)
		return
	}
	if errors.Is(err, domain.ErrNotFound) {
		httpserver.Error(c, http.StatusNotFound, err)
		return
	}
	if err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func modulePermsJSON(modules []domain.ModulePermission) []gin.H {
	out := make([]gin.H, 0, len(modules))
	for _, m := range modules {
		out = append(out, gin.H{"module": m.Module, "level": m.Level})
	}
	return out
}

func menuPermsJSON(menus []domain.MenuPermission) []gin.H {
	out := make([]gin.H, 0, len(menus))
	for _, m := range menus {
		out = append(out, gin.H{"menu_key": m.MenuKey, "level": m.Level})
	}
	return out
}

func publicUser(u domain.User) gin.H {
	return gin.H{
		"id": u.ID, "email": u.Email, "name": u.Name, "created_at": u.CreatedAt,
		"role_id": u.RoleID, "role_code": u.RoleCode, "role_name": u.RoleName,
	}
}
