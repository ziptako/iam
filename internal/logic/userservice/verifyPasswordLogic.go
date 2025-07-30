package userservicelogic

import (
	"context"
	"errors"
	"github.com/ziptako/iam/internal/utils"

	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VerifyPasswordLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewVerifyPasswordLogic(ctx context.Context, svcCtx *svc.ServiceContext) *VerifyPasswordLogic {
	return &VerifyPasswordLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// VerifyPassword 验证用户密码
func (l *VerifyPasswordLogic) VerifyPassword(in *iam.VerifyPasswordRequest) (*iam.VerifyPasswordResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[VP001] 用户ID无效")
	}
	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "[VP002] 密码不能为空")
	}

	// 根据用户ID查询活跃用户
	user, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[VP003] 用户不存在")
		}
		eInfo := "[VP004] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 验证密码
	isValid := utils.VerifyPasswordWithSalt(in.Password, user.Salt, user.PasswordHash)

	return &iam.VerifyPasswordResponse{
		Valid: isValid,
	}, nil
}
