package roleservicelogic

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

type CheckRolePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCheckRolePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CheckRolePermissionLogic {
	return &CheckRolePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CheckRolePermission 检查角色是否拥有指定权限
func (l *CheckRolePermissionLogic) CheckRolePermission(in *iam.CheckRolePermissionRequest) (*iam.CheckRolePermissionResponse, error) {
	// 参数验证
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[CRP001] Role ID is required")
	}
	if strings.TrimSpace(in.PermissionCode) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CRP002] Permission code is required")
	}

	// 检查角色是否存在
	_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CRP003] Role not found")
		}
		eInfo := "[CRP004] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 通过权限编码查找权限
	permission, err := l.svcCtx.PermissionsModel.FindOneByCode(l.ctx, in.PermissionCode)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return &iam.CheckRolePermissionResponse{
				HasPermission: false,
			}, nil
		}
		eInfo := "[CRP005] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查角色权限关联是否存在
	exists, err := l.svcCtx.RolePermissionsModel.HasPermission(l.ctx, in.RoleId, permission.Id)
	if err != nil {
		eInfo := "[CRP006] 检查角色权限关联失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.CheckRolePermissionResponse{
		HasPermission: exists,
	}, nil
}
