package roleservicelogic

import (
	"context"
	"database/sql"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GetRolePermissionsLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetRolePermissionsLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetRolePermissionsLogic {
	return &GetRolePermissionsLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// GetRolePermissions 获取角色拥有的所有权限
func (l *GetRolePermissionsLogic) GetRolePermissions(in *iam.GetRolePermissionsRequest) (*iam.GetRolePermissionsResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[GRP001] Role ID is required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[GRP002] Role not found")
		}
		eInfo := "[GRP003] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取角色的所有权限
	rolePermissions, err := l.svcCtx.RolePermissionsModel.FindByRoleId(l.ctx, in.RoleId)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		eInfo := "[GRP004] 查询角色权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	// 获取权限详情
	var permissions []*model.Permissions
	for _, permission := range rolePermissions {
		modelPermission, err := l.svcCtx.PermissionsModel.FindOne(l.ctx, permission.PermissionId)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, modelPermission)
	}

	// 转换为proto格式
	protoPermissions := logic.ModelPermissionsToProtoPermissions(permissions)

	return &iam.GetRolePermissionsResponse{
		Permissions: protoPermissions,
	}, nil
}
