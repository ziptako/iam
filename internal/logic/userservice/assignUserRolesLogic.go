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

type AssignUserRolesLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewAssignUserRolesLogic(ctx context.Context, svcCtx *svc.ServiceContext) *AssignUserRolesLogic {
	return &AssignUserRolesLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// AssignUserRoles 为用户批量分配角色
func (l *AssignUserRolesLogic) AssignUserRoles(in *iam.AssignUserRolesRequest) (*iam.AssignUserRolesResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[AURS001] User ID is required")
	}
	if len(in.RoleIds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "[AURS002] Role IDs are required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[AURS003] User not found")
		}
		eInfo := "[AURS004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查所有角色是否存在
	for _, roleId := range in.RoleIds {
		if roleId <= 0 {
			return nil, status.Error(codes.InvalidArgument, "[AURS005] Invalid role ID")
		}
		_, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, roleId)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "[AURS006] Role not found")
			}
			eInfo := "[AURS007] 查询角色失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	// 批量分配角色
	err = l.svcCtx.UserRolesModel.AssignRoles(l.ctx, in.UserId, in.RoleIds, sql.NullInt64{})
	if err != nil {
		eInfo := "[AURS008] 批量分配角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.AssignUserRolesResponse{
		Success: true,
	}, nil
}
