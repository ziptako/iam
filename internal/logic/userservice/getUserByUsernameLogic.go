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

type GetUserByUsernameLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetUserByUsernameLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetUserByUsernameLogic {
	return &GetUserByUsernameLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// GetUserByUsername 根据用户名获取用户详情
func (l *GetUserByUsernameLogic) GetUserByUsername(in *iam.GetUserByUsernameRequest) (*iam.User, error) {
	// 参数验证
	if in.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "[GU001] 用户名不能为空")
	}

	// 根据用户名查询活跃用户
	user, err := l.svcCtx.UsersModel.FindActiveByUsername(l.ctx, in.Username)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[GU002] 用户不存在")
		}
		eInfo := "[GU003] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 转换为protobuf格式
	pbUser := &iam.User{
		Id:        user.Id,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.UnixMilli(),
		UpdatedAt: user.UpdatedAt.UnixMilli(),
	}

	// 设置可选字段
	if user.Email.Valid {
		pbUser.Email = user.Email.String
	}
	if user.Nickname.Valid {
		pbUser.Nickname = user.Nickname.String
	}
	if user.Phone.Valid {
		pbUser.Phone = user.Phone.String
	}

	return pbUser, nil
}
