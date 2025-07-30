package svc

import (
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/zeromicro/go-zero/core/stores/sqlx"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/internal/config"
)

type ServiceContext struct {
	Config               config.Config
	PermissionsModel     model.PermissionsModel
	UsersModel           model.UsersModel
	RolesModel           model.RolesModel
	UserRolesModel       model.UserRolesModel
	RolePermissionsModel model.RolePermissionsModel
}

func NewServiceContext(c config.Config) *ServiceContext {
	conn := sqlx.NewSqlConn("postgres", c.DataSource)
	return &ServiceContext{
		Config:               c,
		UsersModel:           model.NewUsersModel(conn, c.Cache),
		RolesModel:           model.NewRolesModel(conn, c.Cache),
		PermissionsModel:     model.NewPermissionsModel(conn, c.Cache),
		UserRolesModel:       model.NewUserRolesModel(conn, c.Cache),
		RolePermissionsModel: model.NewRolePermissionsModel(conn, c.Cache),
	}
}
