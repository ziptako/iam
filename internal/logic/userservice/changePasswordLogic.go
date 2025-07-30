package userservicelogic

import (
	"context"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"
	"github.com/ziptako/iam/internal/utils"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ChangePasswordLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewChangePasswordLogic(ctx context.Context, svcCtx *svc.ServiceContext) *ChangePasswordLogic {
	return &ChangePasswordLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// ChangePassword 修改用户密码
func (l *ChangePasswordLogic) ChangePassword(in *iam.ChangePasswordRequest) (*iam.ChangePasswordResponse, error) {
	// 参数验证
	if in.UserId <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[CP001] 用户ID无效")
	}
	if in.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP002] 新密码不能为空")
	}
	if len(in.NewPassword) < 6 {
		return nil, status.Error(codes.InvalidArgument, "[CP003] 新密码长度不能少于6位")
	}

	// 根据用户ID查询活跃用户
	user, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.UserId)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[CP004] 用户不存在")
		}
		eInfo := "[CP005] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 生成新的盐值
	newSalt, err := utils.GenerateSalt()
	if err != nil {
		eInfo := "[CP006] 生成盐值失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 使用新盐值对新密码进行哈希处理
	newPasswordHash := utils.HashPasswordWithSalt(in.NewPassword, newSalt)

	// 更新用户密码信息
	user.PasswordHash = newPasswordHash
	user.Salt = newSalt

	// 更新数据库
	err = l.svcCtx.UsersModel.Update(l.ctx, user)
	if err != nil {
		eInfo := "[CP007] 更新密码失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.ChangePasswordResponse{
		Success: true,
	}, nil
}
