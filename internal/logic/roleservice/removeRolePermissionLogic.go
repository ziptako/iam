package roleservicelogic

import (
	"context"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RemoveRolePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewRemoveRolePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RemoveRolePermissionLogic {
	return &RemoveRolePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// RemoveRolePermission 移除角色的单个权限
func (l *RemoveRolePermissionLogic) RemoveRolePermission(in *iam.RemoveRolePermissionRequest) (*iam.RemoveRolePermissionResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RRP001] Role ID is required")
	}
	if in.PermissionId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RRP002] Permission ID is required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RRP003] Role not found")
		}
		eInfo := "[RRP004] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查权限是否存在
	_, err = l.svcCtx.PermissionsModel.FindOne(l.ctx, in.PermissionId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RRP005] Permission not found")
		}
		eInfo := "[RRP006] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查角色权限关联是否存在
	exists, err := l.svcCtx.RolePermissionsModel.HasPermission(l.ctx, in.RoleId, in.PermissionId)
	if err != nil {
		eInfo := "[RRP007] 检查角色权限关联失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if !exists {
		return nil, status.Error(codes.NotFound, "[RRP008] Role permission not found")
	}

	// 移除角色权限关联
	err = l.svcCtx.RolePermissionsModel.RemovePermission(l.ctx, in.RoleId, in.PermissionId)
	if err != nil {
		eInfo := "[RRP009] 移除角色权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.RemoveRolePermissionResponse{
		Success: true,
	}, nil
}
