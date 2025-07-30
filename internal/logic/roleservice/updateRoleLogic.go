package roleservicelogic

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

type UpdateRoleLogic struct {
	ctx    context.Context
	svcCtx *svc.ServiceContext
	logx.Logger
}

func NewUpdateRoleLogic(ctx context.Context, svcCtx *svc.ServiceContext) *UpdateRoleLogic {
	return &UpdateRoleLogic{
		ctx:    ctx,
		svcCtx: svcCtx,
		Logger: logx.WithContext(ctx),
	}
}

// UpdateRole 更新角色信息
func (l *UpdateRoleLogic) UpdateRole(in *iam.UpdateRoleRequest) (*iam.Role, error) {
	// 参数验证
	if in.Id <= 0 {
		return nil, status.Error(codes.InvalidArgument, "[UR001] Role ID is required")
	}

	// 查询现有角色
	existingRole, err := l.svcCtx.RolesModel.FindActiveById(l.ctx, in.Id)
	if err != nil {
		if errors.Is(err, model.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "[UR002] Role not found")
		}
		eInfo := "[UR003] 查询角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 检查角色名称是否已被其他角色使用
	if strings.TrimSpace(in.Name) != "" && in.Name != existingRole.Name {
		exists, err := l.svcCtx.RolesModel.ExistsByName(l.ctx, in.Name, in.Id)
		if err != nil {
			eInfo := "[UR004] 检查角色名称是否存在失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		if exists {
			return nil, status.Error(codes.AlreadyExists, "[UR005] Role name already exists")
		}
		existingRole.Name = in.Name
	}

	// 检查角色编码是否已被其他角色使用
	if strings.TrimSpace(in.Code) != "" && in.Code != existingRole.Code {
		exists, err := l.svcCtx.RolesModel.ExistsByCode(l.ctx, in.Code, in.Id)
		if err != nil {
			eInfo := "[UR006] 检查角色编码是否存在失败"
			l.Logger.Errorf("%v: %v", eInfo, err)
			return nil, status.Error(codes.Internal, eInfo)
		}
		if exists {
			return nil, status.Error(codes.AlreadyExists, "[UR007] Role code already exists")
		}
		existingRole.Code = in.Code
	}

	// 更新可选字段
	if strings.TrimSpace(in.Description) != "" {
		existingRole.Description = sql.NullString{String: in.Description, Valid: true}
	}
	if in.SortOrder >= 0 {
		existingRole.SortOrder = int64(in.SortOrder)
	}

	// 更新数据库
	err = l.svcCtx.RolesModel.Update(l.ctx, existingRole)
	if err != nil {
		eInfo := "[UR008] 更新角色失败"
		l.Logger.Errorf("%v: %v", eInfo, err)
		return nil, status.Error(codes.Internal, eInfo)
	}

	// 返回更新后的角色信息
	return logic.ModelToProtoRole(existingRole), nil
}
