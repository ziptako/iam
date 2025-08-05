package permissionservicelogic

import (
	"context"
	"database/sql"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/svc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
)

type CreatePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewCreatePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *CreatePermissionLogic {
	return &CreatePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// CreatePermission 创建新权限
func (l *CreatePermissionLogic) CreatePermission(in *iam.CreatePermissionRequest) (*iam.CreatePermissionResponse, error) {
	// 参数验证
	if strings.TrimSpace(in.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP001] 权限名称不能为空")
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP002] 权限编码不能为空")
	}
	if strings.TrimSpace(in.Type) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP012] 权限类型不能为空")
	}
	if strings.TrimSpace(in.Resource) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP003] 资源标识不能为空")
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP004] 操作类型不能为空")
	}
	if strings.TrimSpace(in.HttpMethod) == "" {
		return nil, status.Error(codes.InvalidArgument, "[CP011] 请求方法不能为空")
	}

	// 检查权限编码是否已存在
	exists, err := l.svcCtx.PermissionsModel.ExistsByCode(l.ctx, in.Code, 0)
	if err != nil {
		eInfo := "[CP005] 检查权限编码是否存在失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "[CP006] 权限编码已存在")
	}

	// 构建权限数据
	permission := &model.Permissions{
		Name:     in.Name,
		Code:     in.Code,
		Type:     in.Type,
		Resource: in.Resource,
		Action:   in.Action,
		HttpMethod: sql.NullString{
			Valid:  true,
			String: in.HttpMethod,
		},
	}

	// 设置可选字段
	if strings.TrimSpace(in.Description) != "" {
		permission.Description = sql.NullString{String: in.Description, Valid: true}
	}

	// 插入数据库
	_, err = l.svcCtx.PermissionsModel.Insert(l.ctx, permission)
	if err != nil {
		eInfo := "[CP007] 创建权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	return &iam.CreatePermissionResponse{}, nil
}
