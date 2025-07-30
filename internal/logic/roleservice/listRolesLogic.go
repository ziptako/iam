package roleservicelogic

import (
	"context"
	"github.com/ziptako/iam/db/model"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/logic"
	"github.com/ziptako/iam/internal/svc"
	"strings"

	"github.com/ziptako/common/utils"

	"github.com/zeromicro/go-zero/core/logx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ListRolesLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewListRolesLogic(ctx context.Context, svcCtx *svc.ServiceContext) *ListRolesLogic {
	return &ListRolesLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// ListRoles 分页查询角色列表
func (l *ListRolesLogic) ListRoles(in *iam.ListRolesRequest) (*iam.ListRolesResponse, error) {
	// 使用工具函数计算分页参数
	pagination := utils.CalculatePagination(in.Page, in.PageSize)

	search := strings.TrimSpace(in.Search)

	// 查询角色列表和总数
	var roles []*model.Roles
	var total int64
	var err error

	if search == "" {
		// 无搜索条件的分页查询
		roles, err = l.svcCtx.RolesModel.FindActiveWithPagination(l.ctx, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LR001] 查询角色列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.RolesModel.CountActive(l.ctx)
		if err != nil {
			eInfo := "[LR002] 查询角色总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	} else {
		// 有搜索条件的分页查询
		roles, err = l.svcCtx.RolesModel.SearchActiveByKeyword(l.ctx, search, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LR003] 搜索角色列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.RolesModel.CountActiveByKeyword(l.ctx, search)
		if err != nil {
			eInfo := "[LR004] 查询搜索结果总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	// 转换为proto消息
	roleList := logic.ModelRolesToProtoRoles(roles)

	return &iam.ListRolesResponse{
		Items: roleList,
		Total: total,
	}, nil
}
