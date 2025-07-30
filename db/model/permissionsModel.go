package model

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/zeromicro/go-zero/core/stores/cache"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
)

var _ PermissionsModel = (*customPermissionsModel)(nil)

type (
	// PermissionsModel is an interface to be customized, add more methods here,
	// and implement the added methods in customPermissionsModel.
	PermissionsModel interface {
		permissionsModel
		FindByType(ctx context.Context, permType string) ([]*Permissions, error)                      // 按类型查询权限
		FindByResource(ctx context.Context, resource string) ([]*Permissions, error)                  // 按资源查询权限
		FindByResourceAndAction(ctx context.Context, resource, action string) ([]*Permissions, error) // 按资源和操作查询权限
		FindByCodePattern(ctx context.Context, pattern string) ([]*Permissions, error)                // 按编码模式查询权限

		ExistsByCode(ctx context.Context, code string, excludeId int64) (bool, error)                                                                // 检查编码是否存在（排除指定ID）
		ExistsByResourceActionType(ctx context.Context, resource, action, permType string, httpMethod sql.NullString, excludeId int64) (bool, error) // 检查权限组合是否存在

		// 分页和统计方法
		FindWithPagination(ctx context.Context, limit, offset int32) ([]*Permissions, error)                                  // 分页查询权限
		CountAll(ctx context.Context) (int64, error)                                                                          // 统计权限总数
		SearchByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Permissions, error)                     // 按关键词搜索权限
		CountByKeyword(ctx context.Context, keyword string) (int64, error)                                                    // 统计搜索结果数量
		SearchWithFilters(ctx context.Context, keyword, resource, action string, limit, offset int32) ([]*Permissions, error) // 带过滤条件的搜索
		CountWithFilters(ctx context.Context, keyword, resource, action string) (int64, error)                                // 统计过滤结果数量

		/*
			TODO: 根据业务需求和性能优化，添加以下低优先级方法

			// 分页和统计方法
			FindWithPagination(ctx context.Context, page, pageSize int64) ([]*Permissions, int64, error) // 分页查询
			CountByType(ctx context.Context, permType string) (int64, error)                      // 按类型统计权限数量
			CountByResource(ctx context.Context, resource string) (int64, error)                  // 按资源统计权限数量

			// 高级查询方法
			FindByMultipleTypes(ctx context.Context, types []string) ([]*Permissions, error)      // 按多个类型查询权限
			FindByMultipleResources(ctx context.Context, resources []string) ([]*Permissions, error) // 按多个资源查询权限
			FindPathPermissions(ctx context.Context) ([]*Permissions, error)                      // 查询所有路径权限
			FindMenuPermissions(ctx context.Context) ([]*Permissions, error)                      // 查询所有菜单权限
			FindButtonPermissions(ctx context.Context) ([]*Permissions, error)                    // 查询所有按钮权限

			// 搜索方法
			SearchByName(ctx context.Context, keyword string, limit int64) ([]*Permissions, error) // 按名称模糊搜索
			SearchByDescription(ctx context.Context, keyword string, limit int64) ([]*Permissions, error) // 按描述模糊搜索
			FindByTimeRange(ctx context.Context, startTime, endTime string) ([]*Permissions, error) // 按时间范围查询

			// 权限树和层级方法
			BuildPermissionTree(ctx context.Context) ([]*PermissionNode, error)                   // 构建权限树
			GroupByResource(ctx context.Context) (map[string][]*Permissions, error)               // 按资源分组
			GroupByType(ctx context.Context) (map[string][]*Permissions, error)                   // 按类型分组
		*/
	}

	customPermissionsModel struct {
		*defaultPermissionsModel
	}
)

// PermissionNode 权限树节点（为将来的权限树功能预留）
type PermissionNode struct {
	*Permissions
	Children []*PermissionNode
}

// NewPermissionsModel returns a model for the database table.
func NewPermissionsModel(conn sqlx.SqlConn, c cache.CacheConf, opts ...cache.Option) PermissionsModel {
	return &customPermissionsModel{
		defaultPermissionsModel: newPermissionsModel(conn, c, opts...),
	}
}

// Insert 插入权限并返回ID
func (m *customPermissionsModel) Insert(ctx context.Context, data *Permissions) (sql.Result, error) {
	var insertedID int64
	iamPermissionsCodeKey := fmt.Sprintf("%s%v", cacheIamPermissionsCodePrefix, data.Code)
	iamPermissionsResourceActionTypeHttpMethodKey := fmt.Sprintf("%s%v:%v:%v:%v", cacheIamPermissionsResourceActionTypeHttpMethodPrefix, data.Resource, data.Action, data.Type, data.HttpMethod)

	err := m.QueryRowNoCacheCtx(ctx, &insertedID, fmt.Sprintf("insert into %s (%s) values ($1, $2, $3, $4, $5, $6, $7) RETURNING id", m.table, permissionsRowsExpectAutoSet), data.Name, data.Code, data.Type, data.Resource, data.Action, data.HttpMethod, data.Description)
	if err != nil {
		return nil, err
	}

	// 更新data对象的ID
	data.Id = insertedID

	// 清除相关缓存
	iamPermissionsIdKey := fmt.Sprintf("%s%v", cacheIamPermissionsIdPrefix, insertedID)
	_ = m.DelCacheCtx(ctx, iamPermissionsCodeKey, iamPermissionsIdKey, iamPermissionsResourceActionTypeHttpMethodKey)

	return &customResult{insertedID: insertedID}, nil
}

// FindByType 按类型查询权限
func (m *customPermissionsModel) FindByType(ctx context.Context, permType string) ([]*Permissions, error) {
	query := fmt.Sprintf("select %s from %s where type = $1 order by created_at", permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, permType)
	return resp, err
}

// FindByResource 按资源查询权限
func (m *customPermissionsModel) FindByResource(ctx context.Context, resource string) ([]*Permissions, error) {
	query := fmt.Sprintf("select %s from %s where resource = $1 order by created_at", permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, resource)
	return resp, err
}

// FindByResourceAndAction 按资源和操作查询权限
func (m *customPermissionsModel) FindByResourceAndAction(ctx context.Context, resource, action string) ([]*Permissions, error) {
	query := fmt.Sprintf("select %s from %s where resource = $1 and action = $2 order by created_at", permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, resource, action)
	return resp, err
}

// FindByCodePattern 按编码模式查询权限
func (m *customPermissionsModel) FindByCodePattern(ctx context.Context, pattern string) ([]*Permissions, error) {
	query := fmt.Sprintf("select %s from %s where code LIKE $1 order by created_at", permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, pattern)
	return resp, err
}

// ExistsByCode 检查编码是否存在（排除指定ID）
func (m *customPermissionsModel) ExistsByCode(ctx context.Context, code string, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where code = $1 and id != $2", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, code, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ExistsByResourceActionType 检查权限组合是否存在
func (m *customPermissionsModel) ExistsByResourceActionType(ctx context.Context, resource, action, permType string, httpMethod sql.NullString, excludeId int64) (bool, error) {
	query := fmt.Sprintf("select count(1) from %s where resource = $1 and action = $2 and type = $3 and http_method = $4 and id != $5", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, resource, action, permType, httpMethod, excludeId)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// FindWithPagination 分页查询权限
func (m *customPermissionsModel) FindWithPagination(ctx context.Context, limit, offset int32) ([]*Permissions, error) {
	query := fmt.Sprintf("select %s from %s order by created_at desc limit $1 offset $2", permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, limit, offset)
	return resp, err
}

// CountAll 统计权限总数
func (m *customPermissionsModel) CountAll(ctx context.Context) (int64, error) {
	query := fmt.Sprintf("select count(1) from %s", m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query)
	return count, err
}

// SearchByKeyword 按关键词搜索权限
func (m *customPermissionsModel) SearchByKeyword(ctx context.Context, keyword string, limit, offset int32) ([]*Permissions, error) {
	if strings.TrimSpace(keyword) == "" {
		return m.FindWithPagination(ctx, limit, offset)
	}

	keywordPattern := "%" + keyword + "%"
	query := fmt.Sprintf(`select %s from %s 
		where name ILIKE $1 or code ILIKE $1 or description ILIKE $1 or resource ILIKE $1 or action ILIKE $1
		order by created_at desc limit $2 offset $3`, permissionsRows, m.table)
	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, keywordPattern, limit, offset)
	return resp, err
}

// CountByKeyword 统计搜索结果数量
func (m *customPermissionsModel) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	if strings.TrimSpace(keyword) == "" {
		return m.CountAll(ctx)
	}

	keywordPattern := "%" + keyword + "%"
	query := fmt.Sprintf(`select count(1) from %s 
		where name ILIKE $1 or code ILIKE $1 or description ILIKE $1 or resource ILIKE $1 or action ILIKE $1`, m.table)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, keywordPattern)
	return count, err
}

// SearchWithFilters 带过滤条件的搜索
func (m *customPermissionsModel) SearchWithFilters(ctx context.Context, keyword, resource, action string, limit, offset int32) ([]*Permissions, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// 构建搜索条件
	if strings.TrimSpace(keyword) != "" {
		keywordPattern := "%" + keyword + "%"
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d or code ILIKE $%d or description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, keywordPattern)
		argIndex++
	}

	if strings.TrimSpace(resource) != "" {
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIndex))
		args = append(args, resource)
		argIndex++
	}

	if strings.TrimSpace(action) != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIndex))
		args = append(args, action)
		argIndex++
	}

	// 构建查询语句
	var whereClause string
	if len(conditions) > 0 {
		whereClause = "where " + strings.Join(conditions, " and ")
	}

	query := fmt.Sprintf("select %s from %s %s order by created_at desc limit $%d offset $%d",
		permissionsRows, m.table, whereClause, argIndex, argIndex+1)
	args = append(args, limit, offset)

	var resp []*Permissions
	err := m.QueryRowsNoCacheCtx(ctx, &resp, query, args...)
	return resp, err
}

// CountWithFilters 统计过滤结果数量
func (m *customPermissionsModel) CountWithFilters(ctx context.Context, keyword, resource, action string) (int64, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// 构建搜索条件
	if strings.TrimSpace(keyword) != "" {
		keywordPattern := "%" + keyword + "%"
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d or code ILIKE $%d or description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, keywordPattern)
		argIndex++
	}

	if strings.TrimSpace(resource) != "" {
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIndex))
		args = append(args, resource)
		argIndex++
	}

	if strings.TrimSpace(action) != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIndex))
		args = append(args, action)
		argIndex++
	}

	// 构建查询语句
	var whereClause string
	if len(conditions) > 0 {
		whereClause = "where " + strings.Join(conditions, " and ")
	}

	query := fmt.Sprintf("select count(1) from %s %s", m.table, whereClause)
	var count int64
	err := m.QueryRowNoCacheCtx(ctx, &count, query, args...)
	return count, err
}
