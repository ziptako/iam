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

type CheckUserRoleLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCheckUserRoleLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CheckUserRoleLogic {
	return &CheckUserRoleLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CheckUserRole 检查用户是否拥有指定角色
func (l *CheckUserRoleLogic) CheckUserRole(in *iam.CheckUserRoleRequest) (*iam.CheckUserRoleResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[CUR001] User ID is required")
	}
	if in.RoleId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[CUR002] Role ID is required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CUR003] User not found")
		}
		eInfo := "[CUR004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查角色是否存在
	_, err = l.svcCtx.RolesModel.FindActiveById(l.ctx, in.RoleId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CUR005] Role not found")
		}
		eInfo := "[CUR006] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查用户角色关联是否存在
	_, err = l.svcCtx.UserRolesModel.FindOneByUserIdRoleId(l.ctx, in.UserId, in.RoleId)
	hasRole := true
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			hasRole = false
		} else {
			eInfo := "[CUR007] 查询用户角色关联失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	return &iam.CheckUserRoleResponse{
		HasRole: hasRole,
	}, nil
}
