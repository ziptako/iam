package roleservicelogic

import (
	"context"
	"database/sql"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"

	"strings"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CreateRoleLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCreateRoleLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CreateRoleLogic {
	return &CreateRoleLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CreateRole 创建新角色
func (l *CreateRoleLogic) CreateRole(in *iam.CreateRoleRequest) (*iam.CreateRoleResponse, error) {
	// 参数验证
	if strings.TrimSpace(in.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CR001] Role name is required")
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CR002] Role code is required")
	}

	// 检查角色名称是否已存在
	exists, err := l.svcCtx.RolesModel.ExistsByName(l.ctx, in.Name, 0)
	if err != nil {
		eInfo := "[CR003] 检查角色名称是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CR004] Role name already exists")
	}

	// 检查角色编码是否已存在
	exists, err = l.svcCtx.RolesModel.ExistsByCode(l.ctx, in.Code, 0)
	if err != nil {
		eInfo := "[CR005] 检查角色编码是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CR006] Role code already exists")
	}

	// 构建角色数据
	role := &model.Roles{
		Name:      in.Name,
		Code:      in.Code,
		SortOrder: int64(in.SortOrder),
	}

	// 设置可选字段
	if strings.TrimSpace(in.Description) != "" {
		role.Description = sql.NullString{String: in.Description, Valid: true}
	}

	// 插入数据库
	result, err := l.svcCtx.RolesModel.Insert(l.ctx, role)
	if err != nil {
		eInfo := "[CR007] 创建角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 获取插入的ID
	id, err := result.LastInsertId()
	if err != nil {
		eInfo := "[CR008] 获取角色ID失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.CreateRoleResponse{
		Id: id,
	}, nil
}
