package permissionservicelogic

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

type GetPermissionLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewGetPermissionLogic(ctx context.Context, svcCtx *svc.ServiceContext) *GetPermissionLogic {
	return &GetPermissionLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// GetPermission 根据ID获取权限详情
func (l *GetPermissionLogic) GetPermission(in *iam.GetPermissionRequest) (*iam.Permission, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[GP001] 权限ID不能为空")
	}

	// 查询权限
	permission, err := l.svcCtx.PermissionsModel.FindOne(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[GP002] 权限不存在")
		}
		eInfo := "[GP003] 查询权限失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 转换为proto消息
	return logic.ModelToProtoPermission(permission), nil
}
