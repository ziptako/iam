package model

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeromicro/go-zero/core/stores/cache"
	"github.com/zeromicro/go-zero/core/stores/sqlc"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
)

var _ RolesModel = (*customRolesModel)(nil)

type (
	// RolesModel is an interface to be customized, add more methods here,
	// and implement the added methods in customRolesModel.
	RolesModel interface {
		rolesModel

		SoftDelete(ctx context.Context, id int64) error
		Restore(ctx context.Context, id int64) error

		Disable(ctx context.Context, id int64) error
		Enable(ctx context.Context, id int64) error

		BatchSoftDelete(ctx context.Context, ids []int64) error
		BatchDisable(ctx context.Context, ids []int64) error

		FindActiveById(ctx context.Context, id int64) (*Roles, error)
		FindById(ctx context.Context, id int64) (*Roles, error) // 包含已删除
		FindActiveByCode(ctx context.Context, code string) (*Roles, error)
		FindActiveByName(ctx context.Context, name string) (*Roles, error)
		FindByCode(ctx context.Context, code string) (*Roles, error)                         // 包含已删除
		FindByName(ctx context.Context, name string) (*Roles, error)                         // 包含已删除
		FindActiveWithPagination(ctx context.Context, limit, offset int32) ([]*Roles, error) // 默认包含已删除
		CountActive(ctx context.Context) (int64, error)
		SearchActiveByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Roles, error)
		CountActiveByKeyword(ctx context.Context, keyword string) (int64, error)

		ExistsByCode(ctx context.Context, code string, excludeId int64) (bool, error)
		ExistsByName(ctx context.Context, name string, excludeId int64) (bool, error)

		FindActiveRoles(ctx context.Context) ([]*Roles, error)
		FindRolesBySortOrder(ctx context.Context, limit int) ([]*Roles, error)

		// TODO: 低优先级方法
		// TODO: FindRolesWithPagination(ctx context.Context, page, pageSize int) ([]*Roles, int64, error)
		// TODO: SearchRolesByName(ctx context.Context, keyword string) ([]*Roles, error)
		// TODO: FindRolesByIds(ctx context.Context, ids []int64) ([]*Roles, error)
		// TODO: UpdateSortOrder(ctx context.Context, id int64, sortOrder int) error
		// TODO: FindRolesByPermission(ctx context.Context, permissionId int64) ([]*Roles, error)
		// TODO: FindDisabledRoles(ctx context.Context) ([]*Roles, error)
		// TODO: FindDeletedRoles(ctx context.Context) ([]*Roles, error)
	}

	customRolesModel struct {
		*defaultRolesModel
	}
)

// NewRolesModel returns a model for the database table.
func NewRolesModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) RolesModel {
	return &customRolesModel{
		defaultRolesModel: newRolesModel(conn, c, opts...),
	}
}

// FindActiveById 按ID查询活跃角色
func (m *customRolesModel) FindActiveById(ctx context.Context, id int64) (*Roles, error) {
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesIdKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		query := fmt.Sprintf("select %s from %s where id = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, id)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindById 按ID查询角色（包含已删除）
func (m *customRolesModel) FindById(ctx context.Context, id int64) (*Roles, error) {
	query := fmt.Sprintf("select %s from %s where id = $1 limit 1", rolesRows, m.table)
	var resp Roles
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, id)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindActiveByCode 按代码查询活跃角色
func (m *customRolesModel) FindActiveByCode(ctx context.Context, code string) (*Roles, error) {
	iamRolesCodeKey := fmt.Sprintf("%s%v", cacheIamRolesCodePrefix, code)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesCodeKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		query := fmt.Sprintf("select %s from %s where code = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, code)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindActiveByName 按名称查询活跃角色
func (m *customRolesModel) FindActiveByName(ctx context.Context, name string) (*Roles, error) {
	iamRolesNameKey := fmt.Sprintf("%s%v", cacheIamRolesNamePrefix, name)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesNameKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		query := fmt.Sprintf("select %s from %s where name = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, name)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindByCode 按代码查询角色（包含已删除）
func (m *customRolesModel) FindByCode(ctx context.Context, code string) (*Roles, error) {
	query := fmt.Sprintf("select %s from %s where code = $1 limit 1", rolesRows, m.table)
	var resp Roles
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, code)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindByName 按名称查询角色（包含已删除）
func (m *customRolesModel) FindByName(ctx context.Context, name string) (*Roles, error) {
	query := fmt.Sprintf("select %s from %s where name = $1 limit 1", rolesRows, m.table)
	var resp Roles
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, name)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// SoftDelete 软删除角色
func (m *customRolesModel) SoftDelete(ctx context.Context, id int64) error {
	one, err := m.FindOne(ctx, id)
	if err != nil {
		return err
	}
	one.DeletedAt.Valid = true
	one.DeletedAt.Time = time.Now()
	err = m.Update(ctx, one)
	return err
}

// Restore 恢复已删除角色
func (m *customRolesModel) Restore(ctx context.Context, id int64) error {
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set deleted_at = NULL where id = $1", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamRolesIdKey)
	return err
}

// Disable 禁用角色
func (m *customRolesModel) Disable(ctx context.Context, id int64) error {
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NOW() where id = $1 and deleted_at IS NULL and disabled_at IS NULL", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamRolesIdKey)
	return err
}

// Enable 启用角色
func (m *customRolesModel) Enable(ctx context.Context, id int64) error {
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NULL where id = $1 and deleted_at IS NULL", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamRolesIdKey)
	return err
}

// BatchSoftDelete 批量软删除
func (m *customRolesModel) BatchSoftDelete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	// 构建占位符
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	// 清除相关缓存
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	}

	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set deleted_at = NOW() where id IN (%s) and deleted_at IS NULL",
			m.table, strings.Join(placeholders, ","))
		return conn.ExecCtx(ctx, query, args...)
	}, keys...)
	return err
}

// BatchDisable 批量禁用
func (m *customRolesModel) BatchDisable(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	// 构建占位符
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	// 清除相关缓存
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	}

	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NOW() where id IN (%s) and deleted_at IS NULL and disabled_at IS NULL",
			m.table, strings.Join(placeholders, ","))
		return conn.ExecCtx(ctx, query, args...)
	}, keys...)
	return err
}

// ExistsByCode 检查角色代码是否存在（排除指定ID）
func (m *customRolesModel) ExistsByCode(ctx context.Context, code string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where code = $1 and id != $2 and deleted_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, code, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ExistsByName 检查角色名称是否存在（排除指定ID）
func (m *customRolesModel) ExistsByName(ctx context.Context, name string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where name = $1 and id != $2 and deleted_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, name, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// FindActiveRoles 查询所有活跃角色
func (m *customRolesModel) FindActiveRoles(ctx context.Context) ([]*Roles, error) {
	query := fmt.Sprintf("select %s from %s where deleted_at IS NULL and disabled_at IS NULL order by sort_order, created_at", rolesRows, m.table)
	var resp []*Roles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query)
	return resp, err
}

// FindActiveWithPagination 分页查询活跃角色
func (m *customRolesModel) FindActiveWithPagination(ctx context.Context, limit, offset int32) ([]*Roles, error) {
	query := fmt.Sprintf("select %s from %s where deleted_at IS NULL and disabled_at IS NULL order by sort_order, created_at limit $1 offset $2", rolesRows, m.table)
	var resp []*Roles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, limit, offset)
	return resp, err
}

// CountActive 统计活跃角色数量
func (m *customRolesModel) CountActive(ctx context.Context) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where deleted_at IS NULL and disabled_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query)
	return count, err
}

// SearchActiveByKeyword 按关键词搜索活跃角色
func (m *customRolesModel) SearchActiveByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Roles, error) {
	query := fmt.Sprintf("select %s from %s where deleted_at IS NULL and disabled_at IS NULL AND (name LIKE $1 OR code LIKE $1 OR description LIKE $1) order by sort_order, created_at limit $2 offset $3", rolesRows, m.table)
	var resp []*Roles
	keywordPattern := "%" + keyword + "%"
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, keywordPattern, limit, offset)
	return resp, err
}

// CountActiveByKeyword 按关键词统计活跃角色数量
func (m *customRolesModel) CountActiveByKeyword(ctx context.Context, keyword string) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where deleted_at IS NULL and disabled_at IS NULL AND (name LIKE $1 OR code LIKE $1 OR description LIKE $1)", m.table)
	var count int64
	keywordPattern := "%" + keyword + "%"
	err := m.QueryRowNoCacheCtx(ctx, &count, query, keywordPattern)
	return count, err
}

// FindRolesBySortOrder 按排序顺序查询角色
func (m *customRolesModel) FindRolesBySortOrder(ctx context.Context, limit int) ([]*Roles, error) {
	query := fmt.Sprintf("select %s from %s where deleted_at IS NULL order by sort_order, created_at limit $1", rolesRows, m.table)
	var resp []*Roles
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, limit)
	return resp, err
}

// FindOne 重写FindOne方法，排除已删除的记录
func (m *customRolesModel) FindOne(ctx context.Context, id int64) (*Roles, error) {
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, id)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesIdKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where id = $1 and deleted_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, id)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindOneByCode 重写FindOneByCode方法，排除已删除的记录
func (m *customRolesModel) FindOneByCode(ctx context.Context, code string) (*Roles, error) {
	iamRolesCodeKey := fmt.Sprintf("%s%v", cacheIamRolesCodePrefix, code)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesCodeKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where code = $1 and deleted_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, code)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindOneByName 重写FindOneByName方法，排除已删除的记录
func (m *customRolesModel) FindOneByName(ctx context.Context, name string) (*Roles, error) {
	iamRolesNameKey := fmt.Sprintf("%s%v", cacheIamRolesNamePrefix, name)
	var resp Roles
	err := m.QueryRowCtx(ctx, &resp, iamRolesNameKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where name = $1 and deleted_at IS NULL limit 1", rolesRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, name)
	})
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// Insert 插入角色并返回ID
func (m *customRolesModel) Insert(ctx context.Context, data *Roles) (sql.Result, error) {
	var insertedID int64
	iamRolesCodeKey := fmt.Sprintf("%s%v", cacheIamRolesCodePrefix, data.Code)
	iamRolesNameKey := fmt.Sprintf("%s%v", cacheIamRolesNamePrefix, data.Name)

	err := m.QueryRowNoCacheCtx(ctx, &insertedID, fmt.Sprintf("insert into %s (%s) values ($1, $2, $3, $4, $5, $6) RETURNING id", m.table, rolesRowsExpectAutoSet), data.Name, data.Code, data.Description, data.SortOrder, data.DisabledAt, data.DeletedAt)
	if err != nil {
		return nil, err
	}

	// 更新data对象的ID
	data.Id = insertedID

	// 清除相关缓存
	iamRolesIdKey := fmt.Sprintf("%s%v", cacheIamRolesIdPrefix, insertedID)
	_ = m.DelCacheCtx(ctx, iamRolesCodeKey, iamRolesIdKey, iamRolesNameKey)

	return &customResult{insertedID: insertedID}, nil
}
