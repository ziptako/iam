package userservicelogic

import (
	"context"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GetUserRolesLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetUserRolesLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetUserRolesLogic {
	return &GetUserRolesLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// GetUserRoles 获取用户拥有的所有角色
func (l *GetUserRolesLogic) GetUserRoles(in *iam.GetUserRolesRequest) (*iam.GetUserRolesResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[GUR001] User ID is required")
	}

	// 检查用户是否存在
	_, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[GUR002] User not found")
		}
		eInfo := "[GUR003] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取用户角色关联
	userRoles, err := l.svcCtx.UserRolesModel.FindRolesByUserId(l.ctx, in.UserId)
	if err != nil {
		eInfo := "[GUR004] 查询用户角色关联失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取角色详情
	roles := make([]*model.Roles, 0, len(userRoles))
	for _, ur := range userRoles {
		role, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, ur.RoleId)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				// 角色可能已被删除，跳过
				continue
			}
			eInfo := "[GUR005] 查询角色详情失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		roles = append(roles, role)
	}

	// 转换为proto消息
	protoRoles := logic.ModelRolesToProtoRoles(roles)

	return &iam.GetUserRolesResponse{
		Roles: protoRoles,
	}, nil
}
