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

type RemoveRolePermissionsLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewRemoveRolePermissionsLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RemoveRolePermissionsLogic {
	return &RemoveRolePermissionsLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// RemoveRolePermissions 批量移除角色的权限
func (l *RemoveRolePermissionsLogic) RemoveRolePermissions(in *iam.RemoveRolePermissionsRequest) (*iam.RemoveRolePermissionsResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RRPS001] Role ID is required")
	}
	if len(in.PermissionIds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[RRPS002] Permission IDs are required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RRPS003] Role not found")
		}
		eInfo := "[RRPS004] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 验证所有权限ID的有效性
	for _, permissionId := range in.PermissionIds {
		if permissionId <= 0 {
			return nil, status.Error(codes.InvalidArgument, "[RRPS005] Invalid permission ID")
		}
	}

	// 批量移除权限
	var successCount int64
	var failedPermissions []int64

	for _, permissionId := range in.PermissionIds {
		// 检查角色权限关联是否存在
		exists, err := l.svcCtx.RolePermissionsModel.HasPermission(l.ctx, in.RoleId, permissionId)
		if err != nil {
			l.Logger.Errorf("[RRPS006] 检查角色权限关联失败 (RoleId: %d, PermissionId: %d): %v", in.RoleId, permissionId, err)
			failedPermissions = append(failedPermissions, permissionId)
			continue
		}
		if !exists {
			// 不存在的关联跳过，不算作失败
			continue
		}

		// 移除角色权限关联
		err = l.svcCtx.RolePermissionsModel.RemovePermission(l.ctx, in.RoleId, permissionId)
		if err != nil {
			l.Logger.Errorf("[RRPS007] 移除角色权限失败 (RoleId: %d, PermissionId: %d): %v", in.RoleId, permissionId, err)
			failedPermissions = append(failedPermissions, permissionId)
			continue
		}
		successCount++
	}

	return &iam.RemoveRolePermissionsResponse{
		Success: len(failedPermissions) == 0,
	}, nil
}
