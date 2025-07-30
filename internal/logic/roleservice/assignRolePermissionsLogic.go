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

type AssignRolePermissionsLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewAssignRolePermissionsLogic(ctx context.Context, svcCtx *svc.ServiceContext) *AssignRolePermissionsLogic {
	return &AssignRolePermissionsLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// AssignRolePermissions 为角色批量分配权限
func (l *AssignRolePermissionsLogic) AssignRolePermissions(in *iam.AssignRolePermissionsRequest) (*iam.AssignRolePermissionsResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[ARPS001] Role ID is required")
	}
	if len(in.PermissionIds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[ARPS002] Permission IDs are required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[ARPS003] Role not found")
		}
		eInfo := "[ARPS004] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 验证所有权限ID的有效性
	for _, permissionId := range in.PermissionIds {
		if permissionId <= 0 {
			return nil, status.Error(codes.InvalidArgument, "[ARPS005] Invalid permission ID")
		}
		_, err := l.svcCtx.PermissionsModel.FindOne(l.ctx, permissionId)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "[ARPS006] Permission not found")
			}
			eInfo := "[ARPS007] 查询权限失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	// 批量分配权限
	var successCount int64
	var failedPermissions []int64

	for _, permissionId := range in.PermissionIds {
		// 检查角色权限关联是否已存在
		exists, err := l.svcCtx.RolePermissionsModel.HasPermission(l.ctx, in.RoleId, permissionId)
		if err != nil {
			l.Logger.Errorf("[ARPS008] 检查角色权限关联失败 (RoleId: %d, PermissionId: %d): %v", in.RoleId, permissionId, err)
			failedPermissions = append(failedPermissions, permissionId)
			continue
		}
		if exists {
			// 已存在的关联跳过，不算作失败
			continue
		}

		// 创建角色权限关联
		rolePermission := &model.RolePermissions{
			RoleId:       in.RoleId,
			PermissionId: permissionId,
		}

		_, err = l.svcCtx.RolePermissionsModel.Insert(l.ctx, rolePermission)
		if err != nil {
			l.Logger.Errorf("[ARPS009] 分配角色权限失败 (RoleId: %d, PermissionId: %d): %v", in.RoleId, permissionId, err)
			failedPermissions = append(failedPermissions, permissionId)
			continue
		}
		successCount++
	}

	return &iam.AssignRolePermissionsResponse{
		Success: len(failedPermissions) == 0,
	}, nil
}
