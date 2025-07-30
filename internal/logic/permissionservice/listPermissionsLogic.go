package permissionservicelogic

import (
	"context"
	"strings"

	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"

	"github.com/ziptako/common/utils"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ListPermissionsLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewListPermissionsLogic(ctx context.Context, svcCtx *svc.ServiceContext) *ListPermissionsLogic {
	return &ListPermissionsLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// ListPermissions 分页查询权限列表
func (l *ListPermissionsLogic) ListPermissions(in *iam.ListPermissionsRequest) (*iam.ListPermissionsResponse, error) {
	// 使用工具函数计算分页参数
	pagination := utils.CalculatePagination(in.Page, in.PageSize)

	search := strings.TrimSpace(in.Search)
	resource := strings.TrimSpace(in.Resource)
	action := strings.TrimSpace(in.Action)

	// 查询权限列表和总数
	var permissions []*model.Permissions
	var total int64
	var err error

	// 根据是否有过滤条件选择不同的查询方法
	if search == "" && resource == "" && action == "" {
		// 无过滤条件的分页查询
		permissions, err = l.svcCtx.PermissionsModel.FindWithPagination(l.ctx, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LP001] 查询权限列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.PermissionsModel.CountAll(l.ctx)
		if err != nil {
			eInfo := "[LP002] 查询权限总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	} else {
		// 有过滤条件的查询
		permissions, err = l.svcCtx.PermissionsModel.SearchWithFilters(l.ctx, search, resource, action, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LP003] 搜索权限列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.PermissionsModel.CountWithFilters(l.ctx, search, resource, action)
		if err != nil {
			eInfo := "[LP004] 查询搜索结果总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	// 转换为proto消息
	permissionList := logic.ModelPermissionsToProtoPermissions(permissions)

	return &iam.ListPermissionsResponse{
		Items: permissionList,
		Total: total,
	}, nil
}
