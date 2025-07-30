package roleservicelogic

import (
	"context"
	"database/sql"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeleteRoleLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewDeleteRoleLogic(ctx context.Context, svcCtx *svc.ServiceContext) *DeleteRoleLogic {
	return &DeleteRoleLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// DeleteRole 删除角色（软删除）
func (l *DeleteRoleLogic) DeleteRole(in *iam.DeleteRoleRequest) (*iam.DeleteRoleResponse, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[DR001] Role ID is required")
	}

	// 检查角色是否存在
	existingRole, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[DR002] Role not found")
		}
		eInfo := "[DR003] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查是否有用户正在使用该角色
	userRoles, err := l.svcCtx.UserRolesModel.FindUsersByRoleId(l.ctx, in.Id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		eInfo := "[DR004] 查询角色使用情况失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if len(userRoles) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "[DR005] Role is being used by users and cannot be deleted")
	}

	// 软删除角色
	err = l.svcCtx.RolesModel.SoftDelete(l.ctx, existingRole.Id)
	if err != nil {
		eInfo := "[DR006] 删除角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 删除角色的所有权限关联
	err = l.svcCtx.RolePermissionsModel.RemoveAllRolePermissions(l.ctx, in.Id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// 记录警告但不阻止删除操作
		l.Logger.Errorf("[DR007] 删除角色权限关联失败: %v", err)
	}

	return &iam.DeleteRoleResponse{
		Success: true,
	}, nil
}
