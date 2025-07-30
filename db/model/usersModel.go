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

// customResult 自定义Result实现，用于PostgreSQL的RETURNING子句
type customResult struct {
	insertedID int64
}

// LastInsertId 返回插入的ID
func (r *customResult) LastInsertId() (int64, error) {
	return r.insertedID, nil
}

// RowsAffected 返回受影响的行数
func (r *customResult) RowsAffected() (int64, error) {
	return 1, nil
}

var _ UsersModel = (*customUsersModel)(nil)

type (
	// UsersModel is an interface to be customized, add more methods here,
	// and implement the added methods in customUsersModel.
	UsersModel interface {
		usersModel
		FindActiveById(ctx context.Context, id int64) (*Users, error)                // 查询活跃用户（未删除且未禁用）
		FindById(ctx context.Context, id int64) (*Users, error)                      // 查询用户（未删除）
		FindActiveByUsername(ctx context.Context, username string) (*Users, error)   // 按用户名查询活跃用户
		FindActiveByEmail(ctx context.Context, email string) (*Users, error)         // 按邮箱查询活跃用户
		FindByUsername(ctx context.Context, username string) (*Users, error)         // 按用户名查询用户（未删除）
		FindByEmail(ctx context.Context, email string) (*Users, error)               // 按邮箱查询用户（未删除）
		FindByNickname(ctx context.Context, nickname string) ([]*Users, error)       // 按昵称查询用户
		FindActiveByNickname(ctx context.Context, nickname string) ([]*Users, error) // 按昵称查询活跃用户

		SoftDelete(ctx context.Context, id int64) error         // 软删除用户
		Restore(ctx context.Context, id int64) error            // 恢复已删除用户
		Disable(ctx context.Context, id int64) error            // 禁用用户
		Enable(ctx context.Context, id int64) error             // 启用用户
		BatchSoftDelete(ctx context.Context, ids []int64) error // 批量软删除
		BatchDisable(ctx context.Context, ids []int64) error    // 批量禁用

		ExistsByUsername(ctx context.Context, username string, excludeId int64) (bool, error) // 检查用户名是否存在（排除指定ID）
		ExistsByEmail(ctx context.Context, email string, excludeId int64) (bool, error)       // 检查邮箱是否存在（排除指定ID）
		ExistsByPhone(ctx context.Context, phone string, excludeId int64) (bool, error)       // 检查手机号是否存在（排除指定ID）

		// 分页和统计方法
		FindActiveWithPagination(ctx context.Context, limit, offset int32) ([]*Users, error)              // 分页查询活跃用户
		CountActive(ctx context.Context) (int64, error)                                                   // 统计活跃用户数量
		SearchActiveByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Users, error) // 按关键词搜索活跃用户
		CountActiveByKeyword(ctx context.Context, keyword string) (int64, error)                          // 统计搜索结果数量

		/*
			TODO: 根据业务需求和性能优化，添加以下低优先级方法

			// 其他分页和统计方法
			FindWithPagination(ctx context.Context, page, pageSize int64) ([]*Users, int64, error)       // 分页查询
			CountDeleted(ctx context.Context) (int64, error)                                             // 统计已删除用户数量
			CountDisabled(ctx context.Context) (int64, error)                                            // 统计已禁用用户数量

			// 其他搜索方法
			SearchByKeyword(ctx context.Context, keyword string, limit int64) ([]*Users, error)         // 按关键词搜索（用户名、昵称、邮箱）
			FindByTimeRange(ctx context.Context, startTime, endTime string) ([]*Users, error)           // 按时间范围查询
			FindByPhone(ctx context.Context, phone string) (*Users, error)                              // 按手机号查询用户

			// 状态管理方法
			FindDisabled(ctx context.Context) ([]*Users, error)                                         // 查询所有禁用用户
			FindDeleted(ctx context.Context) ([]*Users, error)                                          // 查询所有已删除用户
			BatchEnable(ctx context.Context, ids []int64) error                                          // 批量启用
			BatchRestore(ctx context.Context, ids []int64) error                                         // 批量恢复

			// 角色关联方法
			FindByRoleId(ctx context.Context, roleId int64) ([]*Users, error)                           // 按角色ID查询用户
			FindActiveByRoleId(ctx context.Context, roleId int64) ([]*Users, error)                     // 按角色ID查询活跃用户
			FindByRoleCode(ctx context.Context, roleCode string) ([]*Users, error)                      // 按角色编码查询用户
		*/
	}

	customUsersModel struct {
		*defaultUsersModel
	}
)

// NewUsersModel returns a model for the database table.
func NewUsersModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) UsersModel {
	return &customUsersModel{
		defaultUsersModel: newUsersModel(conn, c, opts...),
	}
}

// FindActiveById 查询活跃用户（未删除且未禁用）
func (m *customUsersModel) FindActiveById(ctx context.Context, id int64) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where id = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", usersRows, m.table)
	var resp Users
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

// FindById 查询用户（未删除）
func (m *customUsersModel) FindById(ctx context.Context, id int64) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where id = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
	var resp Users
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

// FindActiveByUsername 按用户名查询活跃用户
func (m *customUsersModel) FindActiveByUsername(ctx context.Context, username string) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where username = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", usersRows, m.table)
	var resp Users
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, username)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindActiveByEmail 按邮箱查询活跃用户
func (m *customUsersModel) FindActiveByEmail(ctx context.Context, email string) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where email = $1 and deleted_at IS NULL and disabled_at IS NULL limit 1", usersRows, m.table)
	var resp Users
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, email)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindByUsername 按用户名查询用户（未删除）
func (m *customUsersModel) FindByUsername(ctx context.Context, username string) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where username = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
	var resp Users
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, username)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindByEmail 按邮箱查询用户（未删除）
func (m *customUsersModel) FindByEmail(ctx context.Context, email string) (*Users, error) {
	query := fmt.Sprintf("select %s from %s where email = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
	var resp Users
	err := m.QueryRowNoCacheCtx(ctx, &resp, query, email)
	switch {
	case err == nil:
		return &resp, nil
	case errors.Is(err, sqlc.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

// FindByNickname 按昵称查询用户
func (m *customUsersModel) FindByNickname(ctx context.Context, nickname string) ([]*Users, error) {
	query := fmt.Sprintf("select %s from %s where nickname = $1 and deleted_at IS NULL order by created_at", usersRows, m.table)
	var resp []*Users
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, nickname)
	return resp, err
}

// FindActiveByNickname 按昵称查询活跃用户
func (m *customUsersModel) FindActiveByNickname(ctx context.Context, nickname string) ([]*Users, error) {
	query := fmt.Sprintf("select %s from %s where nickname = $1 and deleted_at IS NULL and disabled_at IS NULL order by created_at", usersRows, m.table)
	var resp []*Users
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, nickname)
	return resp, err
}

// SoftDelete 软删除用户
func (m *customUsersModel) SoftDelete(ctx context.Context, id int64) error {
	one, err := m.FindOne(ctx, id)
	if err != nil {
		return err
	}
	one.DeletedAt.Valid = true
	one.DeletedAt.Time = time.Now()
	err = m.Update(ctx, one)
	return err
}

// Restore 恢复已删除用户
func (m *customUsersModel) Restore(ctx context.Context, id int64) error {
	iamUsersIdKey := fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set deleted_at = NULL where id = $1", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamUsersIdKey)
	return err
}

// Disable 禁用用户
func (m *customUsersModel) Disable(ctx context.Context, id int64) error {
	iamUsersIdKey := fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NOW() where id = $1 and deleted_at IS NULL and disabled_at IS NULL", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamUsersIdKey)
	return err
}

// Enable 启用用户
func (m *customUsersModel) Enable(ctx context.Context, id int64) error {
	iamUsersIdKey := fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NULL where id = $1 and deleted_at IS NULL", m.table)
		return conn.ExecCtx(ctx, query, id)
	}, iamUsersIdKey)
	return err
}

// BatchSoftDelete 批量软删除
func (m *customUsersModel) BatchSoftDelete(ctx context.Context, ids []int64) error {
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
		keys[i] = fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	}

	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set deleted_at = NOW() where id IN (%s) and deleted_at IS NULL",
			m.table, strings.Join(placeholders, ","))
		return conn.ExecCtx(ctx, query, args...)
	}, keys...)
	return err
}

// BatchDisable 批量禁用
func (m *customUsersModel) BatchDisable(ctx context.Context, ids []int64) error {
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
		keys[i] = fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	}

	_, err := m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		query := fmt.Sprintf("update %s set disabled_at = NOW() where id IN (%s) and deleted_at IS NULL and disabled_at IS NULL",
			m.table, strings.Join(placeholders, ","))
		return conn.ExecCtx(ctx, query, args...)
	}, keys...)
	return err
}

// ExistsByUsername 检查用户名是否存在（排除指定ID）
func (m *customUsersModel) ExistsByUsername(ctx context.Context, username string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where username = $1 and id != $2 and deleted_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, username, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ExistsByEmail 检查邮箱是否存在（排除指定ID）
func (m *customUsersModel) ExistsByEmail(ctx context.Context, email string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where email = $1 and id != $2 and deleted_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, email, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
func (m *customUsersModel) ExistsByPhone(ctx context.Context, phone string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where phone = $1 and id != $2 and deleted_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, phone, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// FindOne 重写FindOne方法，排除已删除的记录
func (m *customUsersModel) FindOne(ctx context.Context, id int64) (*Users, error) {
	iamUsersIdKey := fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, id)
	var resp Users
	err := m.QueryRowCtx(ctx, &resp, iamUsersIdKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where id = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
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

// FindOneByEmail 重写FindOneByEmail方法，排除已删除的记录
func (m *customUsersModel) FindOneByEmail(ctx context.Context, email sql.NullString) (*Users, error) {
	iamUsersEmailKey := fmt.Sprintf("%s%v", cacheIamUsersEmailPrefix, email.String)
	var resp Users
	err := m.QueryRowCtx(ctx, &resp, iamUsersEmailKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where email = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, email.String)
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

// FindOneByUsername 重写FindOneByUsername方法，排除已删除的记录
func (m *customUsersModel) FindOneByUsername(ctx context.Context, username string) (*Users, error) {
	iamUsersUsernameKey := fmt.Sprintf("%s%v", cacheIamUsersUsernamePrefix, username)
	var resp Users
	err := m.QueryRowCtx(ctx, &resp, iamUsersUsernameKey, func(ctx context.Context, conn sqlx.SqlConn, v any) error {
		// 排除软删除的
		query := fmt.Sprintf("select %s from %s where username = $1 and deleted_at IS NULL limit 1", usersRows, m.table)
		return conn.QueryRowCtx(ctx, v, query, username)
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

// FindActiveWithPagination 分页查询活跃用户
func (m *customUsersModel) FindActiveWithPagination(ctx context.Context, limit, offset int32) ([]*Users, error) {
	query := fmt.Sprintf("select %s from %s where deleted_at IS NULL and disabled_at IS NULL order by created_at desc limit $1 offset $2", usersRows, m.table)
	var resp []*Users
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, limit, offset)
	return resp, err
}

// CountActive 统计活跃用户数量
func (m *customUsersModel) CountActive(ctx context.Context) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s where deleted_at IS NULL and disabled_at IS NULL", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query)
	return count, err
}

// SearchActiveByKeyword 按关键词搜索活跃用户
func (m *customUsersModel) SearchActiveByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Users, error) {
	if strings.TrimSpace(keyword) == "" {
		return m.FindActiveWithPagination(ctx, limit, offset)
	}

	keywordPattern := "%" + keyword + "%"
	query := fmt.Sprintf(`select %s from %s 
		where deleted_at IS NULL and disabled_at IS NULL 
		and (username ILIKE $1 or email ILIKE $1 or nickname ILIKE $1) 
		order by created_at desc limit $2 offset $3`, usersRows, m.table)
	var resp []*Users
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, keywordPattern, limit, offset)
	return resp, err
}

// CountActiveByKeyword 统计搜索结果数量
func (m *customUsersModel) CountActiveByKeyword(ctx context.Context, keyword string) (int64, error) {
	if strings.TrimSpace(keyword) == "" {
		return m.CountActive(ctx)
	}

	keywordPattern := "%" + keyword + "%"
	query := fmt.Sprintf(`select count(1) from %s 
		where deleted_at IS NULL and disabled_at IS NULL 
		and (username ILIKE $1 or email ILIKE $1 or nickname ILIKE $1)`, m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, keywordPattern)
	return count, err
}

// Insert 重写Insert方法，使用PostgreSQL的RETURNING子句获取插入后的ID
func (m *customUsersModel) Insert(ctx context.Context, data *Users) (sql.Result, error) {
	// 使用QueryRowCtx来处理RETURNING子句，获取插入后的ID
	var insertedID int64
	query := fmt.Sprintf("insert into %s (%s) values ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id", m.table, usersRowsExpectAutoSet)
	err := m.QueryRowNoCacheCtx(ctx, &insertedID, query, data.Username, data.Email, data.PasswordHash, data.Salt, data.Nickname, data.Phone, data.DisabledAt, data.DeletedAt)
	if err != nil {
		return nil, err
	}

	// 设置插入后的ID到data对象中
	data.Id = insertedID

	// 清除相关缓存
	iamUsersIdKey := fmt.Sprintf("%s%v", cacheIamUsersIdPrefix, insertedID)
	iamUsersEmailKey := fmt.Sprintf("%s%v", cacheIamUsersEmailPrefix, data.Email)
	iamUsersPhoneKey := fmt.Sprintf("%s%v", cacheIamUsersPhonePrefix, data.Phone)
	iamUsersUsernameKey := fmt.Sprintf("%s%v", cacheIamUsersUsernamePrefix, data.Username)
	_, err = m.ExecCtx(ctx, func(ctx context.Context, conn sqlx.SqlConn) (result sql.Result, err error) {
		// 这里返回一个模拟的Result，包含正确的LastInsertId
		return &customResult{insertedID: insertedID}, nil
	}, iamUsersIdKey, iamUsersEmailKey, iamUsersPhoneKey, iamUsersUsernameKey)

	return &customResult{insertedID: insertedID}, err
}
