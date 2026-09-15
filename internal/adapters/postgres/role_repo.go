package postgres

import (
	"context"
	"errors"

	"erp/services/identity-service/internal/domain"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RoleRepo struct {
	pool *pgxpool.Pool
}

func NewRoleRepo(pool *pgxpool.Pool) *RoleRepo {
	return &RoleRepo{pool: pool}
}

const selectRole = `SELECT id, code, name, is_master, is_system, created_at, updated_at FROM roles`

func (r *RoleRepo) Create(ctx context.Context, role domain.Role) (domain.Role, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO roles (code, name)
		VALUES ($1, $2)
		RETURNING id, is_master, is_system, created_at, updated_at
	`, role.Code, role.Name).Scan(&role.ID, &role.IsMaster, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return domain.Role{}, err
	}
	return role, nil
}

func (r *RoleRepo) Update(ctx context.Context, role domain.Role) (domain.Role, error) {
	err := r.pool.QueryRow(ctx, `
		UPDATE roles SET name=$2, updated_at=CURRENT_TIMESTAMP
		WHERE id=$1
		RETURNING code, is_master, is_system, created_at, updated_at
	`, role.ID, role.Name).Scan(&role.Code, &role.IsMaster, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Role{}, domain.ErrNotFound
	}
	return role, err
}

func (r *RoleRepo) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM roles WHERE id=$1`, id)
	if isForeignKeyViolation(err) {
		return domain.ErrInUse
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *RoleRepo) GetByID(ctx context.Context, id string) (domain.Role, error) {
	return r.scan(ctx, selectRole+` WHERE id=$1`, id)
}

func (r *RoleRepo) GetByCode(ctx context.Context, code string) (domain.Role, error) {
	return r.scan(ctx, selectRole+` WHERE code=$1`, code)
}

func (r *RoleRepo) List(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.pool.Query(ctx, selectRole+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Role
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.ID, &role.Code, &role.Name, &role.IsMaster, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *RoleRepo) ModulePermissions(ctx context.Context, roleID string) ([]domain.ModulePermission, error) {
	rows, err := r.pool.Query(ctx, `SELECT module, level FROM role_module_permissions WHERE role_id=$1 ORDER BY module`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ModulePermission
	for rows.Next() {
		var p domain.ModulePermission
		if err := rows.Scan(&p.Module, &p.Level); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *RoleRepo) MenuPermissions(ctx context.Context, roleID string) ([]domain.MenuPermission, error) {
	rows, err := r.pool.Query(ctx, `SELECT menu_key, level FROM role_menu_permissions WHERE role_id=$1 ORDER BY menu_key`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.MenuPermission
	for rows.Next() {
		var p domain.MenuPermission
		if err := rows.Scan(&p.MenuKey, &p.Level); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *RoleRepo) SetPermissions(ctx context.Context, roleID string, modules []domain.ModulePermission, menus []domain.MenuPermission) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM role_module_permissions WHERE role_id=$1`, roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_menu_permissions WHERE role_id=$1`, roleID); err != nil {
		return err
	}
	for _, m := range modules {
		if m.Level <= 0 {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_module_permissions (role_id, module, level) VALUES ($1, $2, $3)`, roleID, m.Module, m.Level); err != nil {
			return err
		}
	}
	for _, m := range menus {
		if m.Level <= 0 {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_menu_permissions (role_id, menu_key, level) VALUES ($1, $2, $3)`, roleID, m.MenuKey, m.Level); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *RoleRepo) scan(ctx context.Context, q string, arg any) (domain.Role, error) {
	var role domain.Role
	err := r.pool.QueryRow(ctx, q, arg).Scan(&role.ID, &role.Code, &role.Name, &role.IsMaster, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Role{}, domain.ErrNotFound
	}
	return role, err
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
