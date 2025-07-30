package userservicelogic

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

type RemoveUserRoleLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewRemoveUserRoleLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RemoveUserRoleLogic {
	return &RemoveUserRoleLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// RemoveUserRole 移除用户的单个角色
func (l *RemoveUserRoleLogic) RemoveUserRole(in *iam.RemoveUserRoleRequest) (*iam.RemoveUserRoleResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RUR001] User ID is required")
	}
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RUR002] Role ID is required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RUR003] User not found")
		}
		eInfo := "[RUR004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查用户角色关联是否存在
	_, err = l.svcCtx.UserRolesModel.FindOneByUserIdRoleId(l.ctx, in.UserId, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RUR005] User role association not found")
		}
		eInfo := "[RUR006] 查询用户角色关联失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 移除用户角色
	err = l.svcCtx.UserRolesModel.RemoveRoles(l.ctx, in.UserId, []int64{in.RoleId})
	if err != nil {
		eInfo := "[RUR007] 移除用户角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.RemoveUserRoleResponse{
		Success: true,
	}, nil
}
