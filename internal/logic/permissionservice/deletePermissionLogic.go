package permissionservicelogic

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

type DeletePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewDeletePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *DeletePermissionLogic {
	return &DeletePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// DeletePermission 删除权限（硬删除）
func (l *DeletePermissionLogic) DeletePermission(in *iam.DeletePermissionRequest) (*iam.DeletePermissionResponse, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[DP001] 权限ID不能为空")
	}

	// 检查权限是否存在
	_, err := l.svcCtx.PermissionsModel.FindOne(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[DP002] 权限不存在")
		}
		eInfo := "[DP003] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查权限是否被角色使用
	count, err := l.svcCtx.RolePermissionsModel.CountRolesByPermissionId(l.ctx, in.Id)
	if err != nil {
		eInfo := "[DP004] 检查权限使用情况失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if count > 0 {
		return nil, status.Error(codes.FailedPrecondition, "[DP005] 权限正在被角色使用，无法删除")
	}

	// 删除权限
	err = l.svcCtx.PermissionsModel.Delete(l.ctx, in.Id)
	if err != nil {
		eInfo := "[DP006] 删除权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.DeletePermissionResponse{
		Success: true,
	}, nil
}
