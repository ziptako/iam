package permissionservicelogic

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UpdatePermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewUpdatePermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UpdatePermissionLogic {
	return &UpdatePermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// UpdatePermission 更新权限信息
func (l *UpdatePermissionLogic) UpdatePermission(in *iam.UpdatePermissionRequest) (*iam.Permission, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[UP001] 权限ID不能为空")
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "[UP002] 权限名称不能为空")
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, status.Error(codes.InvalidArgument, "[UP003] 权限编码不能为空")
	}
	if strings.TrimSpace(in.Resource) == "" {
		return nil, status.Error(codes.InvalidArgument, "[UP004] 资源标识不能为空")
	}
	if strings.TrimSpace(in.Action) == "" {
		return nil, status.Error(codes.InvalidArgument, "[UP005] 操作类型不能为空")
	}

	// 查询权限是否存在
	existingPermission, err := l.svcCtx.PermissionsModel.FindOne(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[UP006] 权限不存在")
		}
		eInfo := "[UP007] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查权限编码是否已被其他权限使用
	if existingPermission.Code != in.Code {
		exists, err := l.svcCtx.PermissionsModel.ExistsByCode(l.ctx, in.Code, in.Id)
		if err != nil {
			eInfo := "[UP008] 检查权限编码是否存在失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		if exists {
			return nil, status.Error(codes.AlreadyExists, "[UP009] 权限编码已存在")
		}
	}

	// 更新权限数据
	existingPermission.Name = in.Name
	existingPermission.Code = in.Code
	existingPermission.Resource = in.Resource
	existingPermission.Action = in.Action

	// 设置可选字段
	if strings.TrimSpace(in.Description) != "" {
		existingPermission.Description = sql.NullString{String: in.Description, Valid: true}
	} else {
		existingPermission.Description = sql.NullString{Valid: false}
	}

	// 更新数据库
	err = l.svcCtx.PermissionsModel.Update(l.ctx, existingPermission)
	if err != nil {
		eInfo := "[UP010] 更新权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 转换为proto消息并返回
	return logic.ModelToProtoPermission(existingPermission), nil
}
