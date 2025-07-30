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

type AssignRolePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewAssignRolePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *AssignRolePermissionLogic {
	return &AssignRolePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// AssignRolePermission 为角色分配权限
func (l *AssignRolePermissionLogic) AssignRolePermission(in *iam.AssignRolePermissionRequest) (*iam.AssignRolePermissionResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[ARP001] Role ID is required")
	}
	if in.PermissionId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[ARP002] Permission ID is required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[ARP003] Role not found")
		}
		eInfo := "[ARP004] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查权限是否存在
	_, err = l.svcCtx.PermissionsModel.FindOne(l.ctx, in.PermissionId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[ARP005] Permission not found")
		}
		eInfo := "[ARP006] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查角色权限关联是否已存在
	exists, err := l.svcCtx.RolePermissionsModel.HasPermission(l.ctx, in.RoleId, in.PermissionId)
	if err != nil {
		eInfo := "[ARP007] 检查角色权限关联失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[ARP008] Role permission already exists")
	}

	// 创建角色权限关联
	rolePermission := &model.RolePermissions{
		RoleId:       in.RoleId,
		PermissionId: in.PermissionId,
	}

	_, err = l.svcCtx.RolePermissionsModel.Insert(l.ctx, rolePermission)
	if err != nil {
		eInfo := "[ARP009] 分配角色权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.AssignRolePermissionResponse{
		Success: true,
	}, nil
}
