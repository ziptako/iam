package userservicelogic

import (
	"context"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"
	"strings"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CheckUserPermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCheckUserPermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CheckUserPermissionLogic {
	return &CheckUserPermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CheckUserPermission 检查用户是否具备指定权限
func (l *CheckUserPermissionLogic) CheckUserPermission(in *iam.CheckUserPermissionRequest) (*iam.CheckUserPermissionResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[CUP001] User ID is required")
	}
	if strings.TrimSpace(in.PermissionCode) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CUP002] Permission code is required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CUP003] User not found")
		}
		eInfo := "[CUP004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查权限是否存在
	permission, err := l.svcCtx.PermissionsModel.FindOneByCode(l.ctx, in.PermissionCode)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CUP005] Permission not found")
		}
		eInfo := "[CUP006] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取用户的所有角色
	userRoles, err := l.svcCtx.UserRolesModel.FindRolesByUserId(l.ctx, in.UserId)
	if err != nil {
		eInfo := "[CUP007] 查询用户角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 如果用户没有任何角色，直接返回false
	if len(userRoles) == 0 {
		return &iam.CheckUserPermissionResponse{
			HasPermission: false,
		}, nil
	}

	// 提取角色ID列表
	roleIds := make([]int64, len(userRoles))
	for i, ur := range userRoles {
		roleIds[i] = ur.RoleId
	}

	// 查询这些角色是否拥有指定权限
	rolePermissions, err := l.svcCtx.RolePermissionsModel.FindByRoleIds(l.ctx, roleIds)
	if err != nil {
		eInfo := "[CUP008] 查询角色权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查是否有任何角色拥有该权限
	hasPermission := false
	for _, rp := range rolePermissions {
		if rp.PermissionId == permission.Id {
			hasPermission = true
			break
		}
	}

	return &iam.CheckUserPermissionResponse{
		HasPermission: hasPermission,
	}, nil
}
