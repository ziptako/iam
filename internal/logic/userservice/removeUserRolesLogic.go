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

type RemoveUserRolesLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewRemoveUserRolesLogic(ctx context.Context, svcCtx *svc.ServiceContext) *RemoveUserRolesLogic {
	return &RemoveUserRolesLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// RemoveUserRoles 批量移除用户的角色
func (l *RemoveUserRolesLogic) RemoveUserRoles(in *iam.RemoveUserRolesRequest) (*iam.RemoveUserRolesResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[RURS001] User ID is required")
	}
	if len(in.RoleIds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[RURS002] Role IDs are required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[RURS003] User not found")
		}
		eInfo := "[RURS004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 验证角色ID
	for _, roleId := range in.RoleIds {
		if roleId <= 0 {
			return nil, status.Error(codes.InvalidArgument, "[RURS005] Invalid role ID")
		}
	}

	// 批量移除用户角色
	err = l.svcCtx.UserRolesModel.RemoveRoles(l.ctx, in.UserId, in.RoleIds)
	if err != nil {
		eInfo := "[RURS006] 批量移除用户角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.RemoveUserRolesResponse{
		Success: true,
	}, nil
}
