package userservicelogic

import (
	"context"
	"database/sql"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"
	"github.com/ziptako/iam/internal/utils"
	"strings"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CreateUserLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCreateUserLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CreateUserLogic {
	return &CreateUserLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CreateUser 创建新用户
func (l *CreateUserLogic) CreateUser(in *iam.CreateUserRequest) (*iam.CreateUserResponse, error) {
	// 参数验证
	if strings.TrimSpace(in.Username) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CU001] Username is required")
	}
	if strings.TrimSpace(in.Email) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CU002] Email is required")
	}
	if strings.TrimSpace(in.Password) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CU003] Password is required")
	}

	// 检查用户名是否已存在
	exists, err := l.svcCtx.UsersModel.ExistsByUsername(l.ctx, in.Username, 0)
	if err != nil {
		eInfo := "[CU004] 检查用户名是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CU005] Username already exists")
	}

	// 检查手机号是否存在
	exists, err = l.svcCtx.UsersModel.ExistsByPhone(l.ctx, in.Phone, 0)
	if err != nil {
		eInfo := "[CU006] 检查手机号是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CU007] Phone already exists")
	}

	// 检查邮箱是否已存在
	exists, err = l.svcCtx.UsersModel.ExistsByEmail(l.ctx, in.Email, 0)
	if err != nil {
		eInfo := "[CU008] 检查邮箱是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CU009] Email already exists")
	}

	// 生成盐值
	salt, err := utils.GenerateSalt()
	if err != nil {
		eInfo := "[CU010] 生成盐值失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 哈希密码
	passwordHash := utils.HashPasswordWithSalt(in.Password, salt)

	// 构建用户数据
	user := &model.Users{
		Username: in.Username,
		Email: sql.NullString{
			String: in.Email,
			Valid:  in.Email != "",
		},
		PasswordHash: passwordHash,
		Salt:         salt,
	}

	// 设置可选字段
	if strings.TrimSpace(in.Nickname) != "" {
		user.Nickname = sql.NullString{String: in.Nickname, Valid: true}
	}
	if strings.TrimSpace(in.Phone) != "" {
		user.Phone = sql.NullString{String: in.Phone, Valid: true}
	}

	// 插入数据库
	result, err := l.svcCtx.UsersModel.Insert(l.ctx, user)
	if err != nil {
		eInfo := "[CU011] 创建用户失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取插入的ID
	id, err := result.LastInsertId()
	if err != nil {
		eInfo := "[CU012] 获取用户ID失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.CreateUserResponse{
		Id: id,
	}, nil
}
