package model

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/zeromicro/go-zero/core/stores/cache"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
)

var _ RolePermissionsModel = (*customRolePermissionsModel)(nil)

type (
	// RolePermissionsModel is an interface to be customized, add more methods here,
	// and implement the added methods in customRolePermissionsModel.
	RolePermissionsModel interface {
		rolePermissionsModel
		AssignPermission(ctx context.Context, roleId, permissionId int64, createdBy sql.NullInt64) error
		AssignPermissions(ctx context.Context, roleId int64, permissionIds []int64, createdBy sql.NullInt64) error
		RemovePermission(ctx context.Context, roleId, permissionId int64) error
		RemovePermissions(ctx context.Context, roleId int64, permissionIds []int64) error
		RemoveAllRolePermissions(ctx context.Context, roleId int64) error
		FindByRoleId(ctx context.Context, roleId int64) ([]*RolePermissions, error)
		FindRolesByPermissionId(ctx context.Context, permissionId int64) ([]*RolePermissions, error)
		HasPermission(ctx context.Context, roleId, permissionId int64) (bool, error)
		HasAnyPermission(ctx context.Context, roleId int64, permissionIds []int64) (bool, error)
		HasAllPermissions(ctx context.Context, roleId int64, permissionIds []int64) (bool, error)
		FindByRoleIds(ctx context.Context, roleIds []int64) ([]*RolePermissions, error)
		FindRolesByPermissionIds(ctx context.Context, permissionIds []int64) ([]*RolePermissions, error)
		CountRolesByPermissionId(ctx context.Context, permissionId int64) (int64, error)
		CountPermissionsByRoleId(ctx context.Context, roleId int64) (int64, error)
		ReplaceRolePermissions(ctx context.Context, roleId int64, permissionIds []int64, createdBy sql.NullInt64) error
	}

	customRolePermissionsModel struct {
		*defaultRolePermissionsModel
	}
)

// NewRolePermissionsModel returns a model for the database table.
func NewRolePermissionsModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) RolePermissionsModel {
	return &customRolePermissionsModel{
		defaultRolePermissionsModel: newRolePermissionsModel(conn, c, opts...),
	}
}

// AssignPermission 为角色分配权限
func (m *customRolePermissionsModel) AssignPermission(ctx context.Context, roleId, permissionId int64, createdBy sql.NullInt64) error {
	// 检查是否已经存在
	existing, err := m.FindOneByRoleIdPermissionId(ctx, roleId, permissionId)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if existing != nil {
		return nil // 已存在，不需要重复分配
	}

	// 创建新的角色权限关联
	rolePermission := &RolePermissions{
		RoleId:       roleId,
		PermissionId: permissionId,
		CreatedBy:    createdBy,
	}

	_, err = m.Insert(ctx, rolePermission)
	return err
}

// AssignPermissions 为角色批量分配权限
func (m *customRolePermissionsModel) AssignPermissions(ctx context.Context, roleId int64, permissionIds []int64, createdBy sql.NullInt64) error {
	if len(permissionIds) == 0 {
		return nil
	}

	for _, permissionId := range permissionIds {
		if err := m.AssignPermission(ctx, roleId, permissionId, createdBy); err != nil {
			return err
		}
	}
	return nil
}

// RemovePermission 移除角色的权限
func (m *customRolePermissionsModel) RemovePermission(ctx context.Context, roleId, permissionId int64) error {
	// 查找现有记录
	existing, err := m.FindOneByRoleIdPermissionId(ctx, roleId, permissionId)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil // 不存在，无需删除
		}
		return err
	}

	// 物理删除
	return m.Delete(ctx, existing.Id)
}

// RemovePermissions 批量移除角色的权限
func (m *customRolePermissionsModel) RemovePermissions(ctx context.Context, roleId int64, permissionIds []int64) error {
	if len(permissionIds) == 0 {
		return nil
	}

	for _, permissionId := range permissionIds {
		if err := m.RemovePermission(ctx, roleId, permissionId); err != nil {
			return err
		}
	}
	return nil
}

// RemoveAllRolePermissions 移除角色的所有权限
func (m *customRolePermissionsModel) RemoveAllRolePermissions(ctx context.Context, roleId int64) error {
	query := fmt.Sprintf("delete from %s where role_id = $1", m.table)
	_, err := m.ExecNoCacheCtx(ctx, query, roleId)
	return err
}

// FindByRoleId 查询角色拥有的所有权限
func (m *customRolePermissionsModel) FindByRoleId(ctx context.Context, roleId int64) ([]*RolePermissions, error) {
	query := fmt.Sprintf("select %s from %s where role_id = $1 order by created_at", rolePermissionsRows, m.table)
	var resp []*RolePermissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, roleId)
	return resp, err
}

// FindRolesByPermissionId 查询拥有指定权限的所有角色
func (m *customRolePermissionsModel) FindRolesByPermissionId(ctx context.Context, permissionId int64) ([]*RolePermissions, error) {
	query := fmt.Sprintf("select %s from %s where permission_id = $1 order by created_at", rolePermissionsRows, m.table)
	var resp []*RolePermissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, permissionId)
	return resp, err
}

// HasPermission 检查角色是否拥有指定权限
func (m *customRolePermissionsModel) HasPermission(ctx context.Context, roleId, permissionId int64) (bool, error) {
	_, err := m.FindOneByRoleIdPermissionId(ctx, roleId, permissionId)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// HasAnyPermission 检查角色是否拥有任意一个指定权限
func (m *customRolePermissionsModel) HasAnyPermission(ctx context.Context, roleId int64, permissionIds []int64) (bool, error) {
	if len(permissionIds) == 0 {
		return false, nil
	}

	// 构建占位符
	placeholders := make([]string, len(permissionIds))
	args := make([]interface{}, len(permissionIds)+1)
	args[0] = roleId
	for i, permissionId := range permissionIds {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = permissionId
	}

	query := fmt.Sprintf("select count(1) from %s where role_id = $1 and permission_id IN (%s) limit 1", m.table, strings.Join(placeholders, ","))
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, args...)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HasAllPermissions 检查角色是否拥有所有指定权限
func (m *customRolePermissionsModel) HasAllPermissions(ctx context.Context, roleId int64, permissionIds []int64) (bool, error) {
	if len(permissionIds) == 0 {
		return true, nil
	}

	// 构建占位符
	placeholders := make([]string, len(permissionIds))
	args := make([]interface{}, len(permissionIds)+1)
	args[0] = roleId
	for i, permissionId := range permissionIds {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = permissionId
	}

	query := fmt.Sprintf("select count(1) from %s where role_id = $1 and permission_id IN (%s)", m.table, strings.Join(placeholders, ","))
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, args...)
	if err != nil {
		return false, err
	}
	return count == int64(len(permissionIds)), nil
}

// FindByRoleIds 批量查询多个角色的权限
func (m *customRolePermissionsModel) FindByRoleIds(ctx context.Context, roleIds []int64) ([]*RolePermissions, error) {
	if len(roleIds) == 0 {
		return []*RolePermissions{}, nil
	}

	// 构建占位符
	placeholders := make([]string, len(roleIds))
	args := make([]interface{}, len(roleIds))
	for i, roleId := range roleIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = roleId
	}

	query := fmt.Sprintf("select %s from %s where role_id IN (%s) order by role_id, created_at", rolePermissionsRows, m.table, strings.Join(placeholders, ","))
	var resp []*RolePermissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, args...)
	return resp, err
}

// FindRolesByPermissionIds 批量查询拥有指定权限的角色
func (m *customRolePermissionsModel) FindRolesByPermissionIds(ctx context.Context, permissionIds []int64) ([]*RolePermissions, error) {
	if len(permissionIds) == 0 {
		return []*RolePermissions{}, nil
	}

	// 构建占位符
	placeholders := make([]string, len(permissionIds))
	args := make([]interface{}, len(permissionIds))
	for i, permissionId := range permissionIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = permissionId
	}

	query := fmt.Sprintf("select %s from %s where permission_id IN (%s) order by permission_id, created_at", rolePermissionsRows, m.table, strings.Join(placeholders, ","))
	var resp []*RolePermissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, args...)
	return resp, err
}

// CountRolesByPermissionId 统计拥有指定权限的角色数量
func (m *customRolePermissionsModel) CountRolesByPermissionId(ctx context.Context, permissionId int64) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where permission_id = $1", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, permissionId)
	return count, err
}

// CountPermissionsByRoleId 统计角色拥有的权限数量
func (m *customRolePermissionsModel) CountPermissionsByRoleId(ctx context.Context, roleId int64) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where role_id = $1", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, roleId)
	return count, err
}

// ReplaceRolePermissions 替换角色的所有权限
func (m *customRolePermissionsModel) ReplaceRolePermissions(ctx context.Context, roleId int64, permissionIds []int64, createdBy sql.NullInt64) error {
	// 先移除角色的所有权限
	if err := m.RemoveAllRolePermissions(ctx, roleId); err != nil {
		return err
	}

	// 再分配新的权限
	if len(permissionIds) > 0 {
		return m.AssignPermissions(ctx, roleId, permissionIds, createdBy)
	}
	return nil
}
