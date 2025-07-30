package userservicelogic

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

type DeleteUserLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewDeleteUserLogic(ctx context.Context, svcCtx *svc.ServiceContext) *DeleteUserLogic {
	return &DeleteUserLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// DeleteUser 删除用户（软删除）
func (l *DeleteUserLogic) DeleteUser(in *iam.DeleteUserRequest) (*iam.DeleteUserResponse, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[DU001] User ID is required")
	}

	// 检查用户是否存在
	existingUser, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[DU002] User not found")
		}
		eInfo := "[DU003] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 软删除用户（设置deleted_at字段）
	err = l.svcCtx.UsersModel.Delete(l.ctx, existingUser.Id)
	if err != nil {
		eInfo := "[DU004] 删除用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 删除用户的所有角色关联
	err = l.svcCtx.UserRolesModel.RemoveAllUserRoles(l.ctx, in.Id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// 记录警告但不阻止删除操作
		l.Logger.Errorf("[DU005] 删除用户角色关联失败: %v", err)
	}

	return &iam.DeleteUserResponse{
		Success: true,
	}, nil
}
