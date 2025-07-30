package userservicelogic

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

type ListUsersLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewListUsersLogic(ctx context.Context, svcCtx *svc.ServiceContext) *ListUsersLogic {
	return &ListUsersLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// ListUsers 分页查询用户列表
func (l *ListUsersLogic) ListUsers(in *iam.ListUsersRequest) (*iam.ListUsersResponse, error) {
	// 使用工具函数计算分页参数
	pagination := utils.CalculatePagination(in.Page, in.PageSize)

	search := strings.TrimSpace(in.Search)

	// 查询用户列表和总数
	var users []*model.Users
	var total int64
	var err error

	if search == "" {
		// 无搜索条件的分页查询
		users, err = l.svcCtx.UsersModel.FindActiveWithPagination(l.ctx, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LU001] 查询用户列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.UsersModel.CountActive(l.ctx)
		if err != nil {
			eInfo := "[LU002] 查询用户总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	} else {
		// 有搜索条件的分页查询
		users, err = l.svcCtx.UsersModel.SearchActiveByKeyword(l.ctx, search, pagination.Limit, pagination.Offset)
		if err != nil {
			eInfo := "[LU003] 搜索用户列表失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}

		total, err = l.svcCtx.UsersModel.CountActiveByKeyword(l.ctx, search)
		if err != nil {
			eInfo := "[LU004] 查询搜索结果总数失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
	}

	// 转换为proto消息
	userList := logic.ModelUsersToProtoUsers(users)

	return &iam.ListUsersResponse{
		Items: userList,
		Total: total,
	}, nil
}
