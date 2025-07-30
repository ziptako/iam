package userservicelogic

import (
	"context"
	"database/sql"
	"errors"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"
	"strings"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UpdateUserLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewUpdateUserLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UpdateUserLogic {
	return &UpdateUserLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// UpdateUser 更新用户信息
func (l *UpdateUserLogic) UpdateUser(in *iam.UpdateUserRequest) (*iam.User, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[UU001] ID is required")
	}

	// 查询现有用户
	existingUser, err := l.svcCtx.UsersModel.FindActiveById(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[UU002] User not found")
		}
		eInfo := "[UU003] 查询用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查用户名是否已被其他用户使用
	if strings.TrimSpace(in.Username) != "" && in.Username != existingUser.Username {
		exists, err := l.svcCtx.UsersModel.ExistsByUsername(l.ctx, in.Username, in.Id)
		if err != nil {
			eInfo := "[UU004] 检查用户名是否存在失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		if exists {
			return nil, status.Error(codes.AlreadyExists, "[UU005] Username already exists")
		}
		existingUser.Username = in.Username
	}

	// 检查邮箱是否已被其他用户使用
	if strings.TrimSpace(in.Email) != "" && in.Email != existingUser.Email.String {
		exists, err := l.svcCtx.UsersModel.ExistsByEmail(l.ctx, in.Email, in.Id)
		if err != nil {
			eInfo := "[UU006] 检查邮箱是否存在失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		if exists {
			return nil, status.Error(codes.AlreadyExists, "[UU007] Email already exists")
		}
		existingUser.Email = sql.NullString{
			String: in.Email,
			Valid:  in.Email != "",
		}
	}

	// 更新可选字段
	if strings.TrimSpace(in.Nickname) != "" {
		existingUser.Nickname = sql.NullString{String: in.Nickname, Valid: true}
	}
	if strings.TrimSpace(in.Phone) != "" {
		existingUser.Phone = sql.NullString{String: in.Phone, Valid: true}
	}

	// 更新数据库
	err = l.svcCtx.UsersModel.Update(l.ctx, existingUser)
	if err != nil {
		eInfo := "[UU008] 更新用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 返回更新后的用户信息
	return logic.ModelToProtoUser(existingUser), nil
}
