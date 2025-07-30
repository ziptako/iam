package logic

import (
	"database/sql"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"

	"time"
)

// ModelToProtoUser 将model用户转换为proto用户
func ModelToProtoUser(source *model.Users) *iam.User {
	if source == nil {
		return nil
	}

	res := &iam.User{
		Id:        source.Id,
		Username:  source.Username,
		CreatedAt: source.CreatedAt.Unix(),
		UpdatedAt: source.UpdatedAt.Unix(),
	}

	// 处理可空字段
	if source.Email.Valid {
		res.Email = source.Email.String
	}
	if source.Nickname.Valid {
		res.Nickname = source.Nickname.String
	}
	if source.Phone.Valid {
		res.Phone = source.Phone.String
	}

	return res
}

// ProtoToModelUser 将proto用户转换为model用户
func ProtoToModelUser(source *iam.User) *model.Users {
	if source == nil {
		return nil
	}

	return &model.Users{
		Id:       source.Id,
		Username: source.Username,
		Email: sql.NullString{
			String: source.Email,
			Valid:  source.Email != "",
		},
		Nickname: sql.NullString{
			Valid:  source.Nickname != "",
			String: source.Nickname,
		},
		Phone: sql.NullString{
			Valid:  source.Phone != "",
			String: source.Phone,
		},
		CreatedAt: time.Unix(source.CreatedAt, 0),
		UpdatedAt: time.Unix(source.UpdatedAt, 0),
	}
}

// ModelToProtoRole 将model角色转换为proto角色
func ModelToProtoRole(source *model.Roles) *iam.Role {
	if source == nil {
		return nil
	}

	res := &iam.Role{
		Id:        source.Id,
		Name:      source.Name,
		Code:      source.Code,
		SortOrder: int32(source.SortOrder),
		CreatedAt: source.CreatedAt.Unix(),
		UpdatedAt: source.UpdatedAt.Unix(),
	}

	// 处理可空字段
	if source.Description.Valid {
		res.Description = source.Description.String
	}

	return res
}

// ProtoToModelRole 将proto角色转换为model角色
func ProtoToModelRole(source *iam.Role) *model.Roles {
	if source == nil {
		return nil
	}

	return &model.Roles{
		Id:   source.Id,
		Name: source.Name,
		Code: source.Code,
		Description: sql.NullString{
			Valid:  source.Description != "",
			String: source.Description,
		},
		SortOrder: int64(source.SortOrder),
		CreatedAt: time.Unix(source.CreatedAt, 0),
		UpdatedAt: time.Unix(source.UpdatedAt, 0),
	}
}

// ModelToProtoPermission 将model权限转换为proto权限
func ModelToProtoPermission(source *model.Permissions) *iam.Permission {
	if source == nil {
		return nil
	}

	res := &iam.Permission{
		Id:        source.Id,
		Name:      source.Name,
		Code:      source.Code,
		Resource:  source.Resource,
		Action:    source.Action,
		CreatedAt: source.CreatedAt.Unix(),
		UpdatedAt: source.UpdatedAt.Unix(),
	}

	// 处理可空字段
	if source.Description.Valid {
		res.Description = source.Description.String
	}

	return res
}

// ProtoToModelPermission 将proto权限转换为model权限
func ProtoToModelPermission(source *iam.Permission) *model.Permissions {
	if source == nil {
		return nil
	}

	return &model.Permissions{
		Id:       source.Id,
		Name:     source.Name,
		Code:     source.Code,
		Resource: source.Resource,
		Action:   source.Action,
		Description: sql.NullString{
			Valid:  source.Description != "",
			String: source.Description,
		},
		CreatedAt: time.Unix(source.CreatedAt, 0),
		UpdatedAt: time.Unix(source.UpdatedAt, 0),
	}
}

// ModelUsersToProtoUsers 批量转换用户列表
func ModelUsersToProtoUsers(sources []*model.Users) []*iam.User {
	if sources == nil {
		return nil
	}

	result := make([]*iam.User, 0, len(sources))
	for _, source := range sources {
		if user := ModelToProtoUser(source); user != nil {
			result = append(result, user)
		}
	}
	return result
}

// ModelRolesToProtoRoles 批量转换角色列表
func ModelRolesToProtoRoles(sources []*model.Roles) []*iam.Role {
	if sources == nil {
		return nil
	}

	result := make([]*iam.Role, 0, len(sources))
	for _, source := range sources {
		if role := ModelToProtoRole(source); role != nil {
			result = append(result, role)
		}
	}
	return result
}

// ModelPermissionsToProtoPermissions 批量转换权限列表
func ModelPermissionsToProtoPermissions(sources []*model.Permissions) []*iam.Permission {
	if sources == nil {
		return nil
	}

	result := make([]*iam.Permission, 0, len(sources))
	for _, source := range sources {
		if permission := ModelToProtoPermission(source); permission != nil {
			result = append(result, permission)
		}
	}
	return result
}
