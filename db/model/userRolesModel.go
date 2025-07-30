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

var _ UserRolesModel = (*customUserRolesModel)(nil)

type (
	// UserRolesModel is an interface to be customized, add more methods here,
	// and implement the added methods in customUserRolesModel.
	UserRolesModel interface {
		userRolesModel
		AssignRole(ctx context.Context, userId, roleId int64, createdBy sql.NullInt64) error
		AssignRoles(ctx context.Context, userId int64, roleIds []int64, createdBy sql.NullInt64) error
		RemoveRole(ctx context.Context, userId, roleId int64) error
		RemoveRoles(ctx context.Context, userId int64, roleIds []int64) error
		RemoveAllUserRoles(ctx context.Context, userId int64) error
		FindRolesByUserId(ctx context.Context, userId int64) ([]*UserRoles, error)
		FindUsersByRoleId(ctx context.Context, roleId int64) ([]*UserRoles, error)
		HasRole(ctx context.Context, userId, roleId int64) (bool, error)
		HasAnyRole(ctx context.Context, userId int64, roleIds []int64) (bool, error)
		HasAllRoles(ctx context.Context, userId int64, roleIds []int64) (bool, error)
		FindRolesByUserIds(ctx context.Context, userIds []int64) ([]*UserRoles, error)
		FindUsersByRoleIds(ctx context.Context, roleIds []int64) ([]*UserRoles, error)
		CountUsersByRoleId(ctx context.Context, roleId int64) (int64, error)
		CountRolesByUserId(ctx context.Context, userId int64) (int64, error)
		ReplaceUserRoles(ctx context.Context, userId int64, roleIds []int64, createdBy sql.NullInt64) error
	}

	customUserRolesModel struct {
		*defaultUserRolesModel
	}
)

// NewUserRolesModel returns a model for the database table.
func NewUserRolesModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) UserRolesModel {
	return &customUserRolesModel{
		defaultUserRolesModel: newUserRolesModel(conn, c, opts...),
	}
}

// AssignRole 为用户分配角色
func (m *customUserRolesModel) AssignRole(ctx context.Context, userId, roleId int64, createdBy sql.NullInt64) error {
	// 检查是否已存在
	existing, err := m.FindOneByUserIdRoleId(ctx, userId, roleId)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if existing != nil {
		return nil // 已存在，不重复分配
	}

	userRole := &UserRoles{
		UserId:    userId,
		RoleId:    roleId,
		CreatedBy: createdBy,
	}
	_, err = m.Insert(ctx, userRole)
	return err
}

// AssignRoles 为用户批量分配角色
func (m *customUserRolesModel) AssignRoles(ctx context.Context, userId int64, roleIds []int64, createdBy sql.NullInt64) error {
	if len(roleIds) == 0 {
		return nil
	}

	// 查询已存在的角色关联
	existingRoles, err := m.FindRolesByUserId(ctx, userId)
	if err != nil {
		return err
	}

	// 构建已存在角色ID的映射
	existingRoleMap := make(map[int64]bool)
	for _, ur := range existingRoles {
		existingRoleMap[ur.RoleId] = true
	}

	// 只插入不存在的角色关联
	for _, roleId := range roleIds {
		if !existingRoleMap[roleId] {
			userRole := &UserRoles{
				UserId:    userId,
				RoleId:    roleId,
				CreatedBy: createdBy,
			}
			if _, err := m.Insert(ctx, userRole); err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveRole 移除用户角色
func (m *customUserRolesModel) RemoveRole(ctx context.Context, userId, roleId int64) error {
	userRole, err := m.FindOneByUserIdRoleId(ctx, userId, roleId)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil // 不存在，视为成功
		}
		return err
	}
	return m.Delete(ctx, userRole.Id)
}

// RemoveRoles 批量移除用户角色
func (m *customUserRolesModel) RemoveRoles(ctx context.Context, userId int64, roleIds []int64) error {
	if len(roleIds) == 0 {
		return nil
	}

	// 构建占位符
	placeholders := make([]string, len(roleIds))
	args := make([]interface{}, len(roleIds)+1)
	args[0] = userId
	for i, roleId := range roleIds {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = roleId
	}

	// 先查询要删除的记录以清除缓存
	query := fmt.Sprintf("select %s from %s where user_id = $1 and role_id IN (%s)", userRolesRows, m.table, strings.Join(placeholders, ","))
	var toDelete []*UserRoles
	err := m.QueryRowsNoCacheCtx(ctx, &toDelete, query, args...)
	if err != nil {
		return err
	}

	// 构建缓存键
	keys := make([]string, 0, len(toDelete)*2)
	for _, ur := range toDelete {
		keys = append(keys, fmt.Sprintf("%s%v", cacheIamUserRolesIdPrefix, ur.Id))
		keys = append(keys, fmt.Sprintf("%s%v:%v", cacheIamUserRolesUserIdRoleIdPrefix, ur.UserId, ur.RoleId))
	}

	// 执行删除
	_, err = m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		deleteQuery := fmt.Sprintf("delete from %s where user_id = $1 and role_id IN (%s)", m.table, strings.Join(placeholders, ","))
		return conn.ExecCtx(ctx, deleteQuery, args...)
	}, keys...)
	return err
}

// RemoveAllUserRoles 移除用户的所有角色
func (m *customUserRolesModel) RemoveAllUserRoles(ctx context.Context, userId int64) error {
	// 先查询用户的所有角色以清除缓存
	userRoles, err := m.FindRolesByUserId(ctx, userId)
	if err != nil {
		return err
	}

	if len(userRoles) == 0 {
		return nil
	}

	// 构建缓存键
	keys := make([]string, 0, len(userRoles)*2)
	for _, ur := range userRoles {
		keys = append(keys, fmt.Sprintf("%s%v", cacheIamUserRolesIdPrefix, ur.Id))
		keys = append(keys, fmt.Sprintf("%s%v:%v", cacheIamUserRolesUserIdRoleIdPrefix, ur.UserId, ur.RoleId))
	}

	// 执行删除
	_, err = m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("delete from %s where user_id = $1", m.table)
		return conn.ExecCtx(ctx, query, userId)
	}, keys...)
	return err
}

// FindRolesByUserId 查询用户的所有角色
func (m *customUserRolesModel) FindRolesByUserId(ctx context.Context, userId int64) ([]*UserRoles, error) {
	query := fmt.Sprintf("select %s from %s where user_id = $1 order by created_at", userRolesRows, m.table)
	var resp []*UserRoles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, userId)
	return resp, err
}

// FindUsersByRoleId 查询拥有指定角色的所有用户
func (m *customUserRolesModel) FindUsersByRoleId(ctx context.Context, roleId int64) ([]*UserRoles, error) {
	query := fmt.Sprintf("select %s from %s where role_id = $1 order by created_at", userRolesRows, m.table)
	var resp []*UserRoles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, roleId)
	return resp, err
}

// HasRole 检查用户是否拥有指定角色
func (m *customUserRolesModel) HasRole(ctx context.Context, userId, roleId int64) (bool, error) {
	_, err := m.FindOneByUserIdRoleId(ctx, userId, roleId)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// HasAnyRole 检查用户是否拥有任意一个指定角色
func (m *customUserRolesModel) HasAnyRole(ctx context.Context, userId int64, roleIds []int64) (bool, error) {
	if len(roleIds) == 0 {
		return false, nil
	}

	// 构建占位符
	placeholders := make([]string, len(roleIds))
	args := make([]interface{}, len(roleIds)+1)
	args[0] = userId
	for i, roleId := range roleIds {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = roleId
	}

	query := fmt.Sprintf("select count(1) from %s where user_id = $1 and role_id IN (%s)", m.table, strings.Join(placeholders, ","))
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, args...)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// HasAllRoles 检查用户是否拥有所有指定角色
func (m *customUserRolesModel) HasAllRoles(ctx context.Context, userId int64, roleIds []int64) (bool, error) {
	if len(roleIds) == 0 {
		return true, nil
	}

	// 构建占位符
	placeholders := make([]string, len(roleIds))
	args := make([]interface{}, len(roleIds)+1)
	args[0] = userId
	for i, roleId := range roleIds {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = roleId
	}

	query := fmt.Sprintf("select count(1) from %s where user_id = $1 and role_id IN (%s)", m.table, strings.Join(placeholders, ","))
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, args...)
	if err != nil {
		return false, err
	}
	return count == int64(len(roleIds)), nil
}

// FindRolesByUserIds 批量查询多个用户的角色
func (m *customUserRolesModel) FindRolesByUserIds(ctx context.Context, userIds []int64) ([]*UserRoles, error) {
	if len(userIds) == 0 {
		return []*UserRoles{}, nil
	}

	// 构建占位符
	placeholders := make([]string, len(userIds))
	args := make([]interface{}, len(userIds))
	for i, userId := range userIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = userId
	}

	query := fmt.Sprintf("select %s from %s where user_id IN (%s) order by user_id, created_at", userRolesRows, m.table, strings.Join(placeholders, ","))
	var resp []*UserRoles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, args...)
	return resp, err
}

// FindUsersByRoleIds 批量查询拥有指定角色的用户
func (m *customUserRolesModel) FindUsersByRoleIds(ctx context.Context, roleIds []int64) ([]*UserRoles, error) {
	if len(roleIds) == 0 {
		return []*UserRoles{}, nil
	}

	// 构建占位符
	placeholders := make([]string, len(roleIds))
	args := make([]interface{}, len(roleIds))
	for i, roleId := range roleIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = roleId
	}

	query := fmt.Sprintf("select %s from %s where role_id IN (%s) order by role_id, created_at", userRolesRows, m.table, strings.Join(placeholders, ","))
	var resp []*UserRoles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, args...)
	return resp, err
}

// CountUsersByRoleId 统计拥有指定角色的用户数量
func (m *customUserRolesModel) CountUsersByRoleId(ctx context.Context, roleId int64) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where role_id = $1", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, roleId)
	return count, err
}

// CountRolesByUserId 统计用户拥有的角色数量
func (m *customUserRolesModel) CountRolesByUserId(ctx context.Context, userId int64) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where user_id = $1", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, userId)
	return count, err
}

// ReplaceUserRoles 替换用户的所有角色
func (m *customUserRolesModel) ReplaceUserRoles(ctx context.Context, userId int64, roleIds []int64, createdBy sql.NullInt64) error {
	// 先移除用户的所有角色
	if err := m.RemoveAllUserRoles(ctx, userId); err != nil {
		return err
	}

	// 再分配新的角色
	if len(roleIds) > 0 {
		return m.AssignRoles(ctx, userId, roleIds, createdBy)
	}
	return nil
}
