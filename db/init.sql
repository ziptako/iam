CREATE SCHEMA IF NOT EXISTS iam;

-- =========================================================
-- 1. IAM Service 表 - RBAC1 模型
-- =========================================================

-- 用户表
CREATE TABLE iam.users
(
    id            BIGSERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE CHECK (LENGTH(TRIM(username)) > 0),
    email         VARCHAR(255) UNIQUE CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    password_hash VARCHAR(255) NOT NULL,
    salt          VARCHAR(64)  NOT NULL,
    nickname      VARCHAR(100),
    phone         VARCHAR(20) UNIQUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    disabled_at   TIMESTAMPTZ,
    deleted_at    TIMESTAMPTZ,
    
    -- 添加约束确保逻辑删除的数据不能被禁用
    CONSTRAINT chk_users_deleted_not_disabled CHECK (
        (deleted_at IS NULL) OR (disabled_at IS NULL)
    ),
    
    -- 确保时间戳的逻辑性
    CONSTRAINT chk_users_timestamps CHECK (
        created_at <= updated_at AND
        (disabled_at IS NULL OR disabled_at >= created_at) AND
        (deleted_at IS NULL OR deleted_at >= created_at)
    )
);

-- 角色表
CREATE TABLE iam.roles
(
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL UNIQUE CHECK (LENGTH(TRIM(name)) > 0),
    code        VARCHAR(50)  NOT NULL UNIQUE CHECK (LENGTH(TRIM(code)) > 0),
    description VARCHAR(255),
    sort_order  INTEGER      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ,
    deleted_at  TIMESTAMPTZ,
    
    -- 添加约束确保逻辑删除的数据不能被禁用
    CONSTRAINT chk_roles_deleted_not_disabled CHECK (
        (deleted_at IS NULL) OR (disabled_at IS NULL)
    ),
    
    -- 确保时间戳的逻辑性
    CONSTRAINT chk_roles_timestamps CHECK (
        created_at <= updated_at AND
        (disabled_at IS NULL OR disabled_at >= created_at) AND
        (deleted_at IS NULL OR deleted_at >= created_at)
    )
);

-- 权限表
CREATE TABLE iam.permissions
(
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL CHECK (LENGTH(TRIM(name)) > 0),
    code        VARCHAR(100) NOT NULL UNIQUE CHECK (LENGTH(TRIM(code)) > 0),
    type        VARCHAR(20)  NOT NULL CHECK (type IN ('path', 'button', 'menu')),
    resource    VARCHAR(100) NOT NULL CHECK (LENGTH(TRIM(resource)) > 0),
    action      VARCHAR(50)  NOT NULL CHECK (LENGTH(TRIM(action)) > 0),
    http_method VARCHAR(10)  CHECK (http_method IN ('GET', 'POST', 'PUT', 'DELETE') OR http_method IS NULL),
    description VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    
    -- 确保时间戳的逻辑性
    CONSTRAINT chk_permissions_timestamps CHECK (
        created_at <= updated_at
    ),
    
    -- 确保path类型必须有http_method，其他类型不能有http_method
    CONSTRAINT chk_permissions_http_method CHECK (
        (type = 'path' AND http_method IS NOT NULL) OR
        (type IN ('button', 'menu') AND http_method IS NULL)
    )
    
    -- 确保资源、操作和类型的组合唯一性
    --CONSTRAINT uk_permissions_resource_action_type UNIQUE (resource, action, type, http_method)
);

-- 用户角色关联表
CREATE TABLE iam.user_roles
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES iam.users (id) ON DELETE CASCADE,
    role_id    BIGINT      NOT NULL REFERENCES iam.roles (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by BIGINT      REFERENCES iam.users (id),
    
    -- 确保用户角色关联的唯一性
    CONSTRAINT uk_user_roles UNIQUE (user_id, role_id)
);

-- 角色权限关联表
CREATE TABLE iam.role_permissions
(
    id            BIGSERIAL PRIMARY KEY,
    role_id       BIGINT      NOT NULL REFERENCES iam.roles (id) ON DELETE CASCADE,
    permission_id BIGINT      NOT NULL REFERENCES iam.permissions (id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    BIGINT      REFERENCES iam.users (id),
    
    -- 确保角色权限关联的唯一性
    CONSTRAINT uk_role_permissions UNIQUE (role_id, permission_id)
);

-- =========================================================
-- 2. 触发器函数
-- =========================================================

-- 创建触发器函数自动更新updated_at字段
CREATE OR REPLACE FUNCTION iam.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- =========================================================
-- 3. 触发器
-- =========================================================

-- 用户表触发器
CREATE TRIGGER trigger_update_users_updated_at
    BEFORE UPDATE ON iam.users
    FOR EACH ROW
    EXECUTE FUNCTION iam.update_updated_at_column();

-- 角色表触发器
CREATE TRIGGER trigger_update_roles_updated_at
    BEFORE UPDATE ON iam.roles
    FOR EACH ROW
    EXECUTE FUNCTION iam.update_updated_at_column();

-- 权限表触发器
CREATE TRIGGER trigger_update_permissions_updated_at
    BEFORE UPDATE ON iam.permissions
    FOR EACH ROW
    EXECUTE FUNCTION iam.update_updated_at_column();

-- =========================================================
-- 4. 索引优化
-- =========================================================

-- 用户表索引
CREATE INDEX idx_users_username ON iam.users (username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON iam.users (email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_active ON iam.users (id) WHERE deleted_at IS NULL AND disabled_at IS NULL;
CREATE INDEX idx_users_created_at ON iam.users (created_at);
CREATE INDEX idx_users_updated_at ON iam.users (updated_at);
CREATE INDEX idx_users_deleted_at ON iam.users (deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_users_disabled_at ON iam.users (disabled_at) WHERE disabled_at IS NOT NULL;

-- 角色表索引
CREATE INDEX idx_roles_name ON iam.roles (name) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_code ON iam.roles (code) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_sort_order ON iam.roles (sort_order) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_active ON iam.roles (id) WHERE deleted_at IS NULL AND disabled_at IS NULL;
CREATE INDEX idx_roles_created_at ON iam.roles (created_at);
CREATE INDEX idx_roles_updated_at ON iam.roles (updated_at);
CREATE INDEX idx_roles_deleted_at ON iam.roles (deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_roles_disabled_at ON iam.roles (disabled_at) WHERE disabled_at IS NOT NULL;

-- 权限表索引
CREATE INDEX idx_permissions_code ON iam.permissions (code);
CREATE INDEX idx_permissions_type ON iam.permissions (type);
CREATE INDEX idx_permissions_resource ON iam.permissions (resource);
CREATE INDEX idx_permissions_action ON iam.permissions (action);
CREATE INDEX idx_permissions_http_method ON iam.permissions (http_method) WHERE http_method IS NOT NULL;
CREATE INDEX idx_permissions_resource_action ON iam.permissions (resource, action);
CREATE INDEX idx_permissions_type_resource ON iam.permissions (type, resource);
CREATE INDEX idx_permissions_path_method ON iam.permissions (resource, http_method) WHERE type = 'path';
CREATE INDEX idx_permissions_created_at ON iam.permissions (created_at);
CREATE INDEX idx_permissions_updated_at ON iam.permissions (updated_at);

-- 用户角色关联表索引
CREATE INDEX idx_user_roles_user_id ON iam.user_roles (user_id);
CREATE INDEX idx_user_roles_role_id ON iam.user_roles (role_id);
CREATE INDEX idx_user_roles_created_at ON iam.user_roles (created_at);

-- 角色权限关联表索引
CREATE INDEX idx_role_permissions_role_id ON iam.role_permissions (role_id);
CREATE INDEX idx_role_permissions_permission_id ON iam.role_permissions (permission_id);
CREATE INDEX idx_role_permissions_created_at ON iam.role_permissions (created_at);

-- =========================================================
-- 5. 表和字段注释
-- =========================================================

-- 用户表注释
COMMENT ON TABLE iam.users IS '用户表，存储系统用户基本信息';
COMMENT ON COLUMN iam.users.id IS '主键ID';
COMMENT ON COLUMN iam.users.username IS '用户名，唯一标识';
COMMENT ON COLUMN iam.users.email IS '邮箱地址，唯一标识';
COMMENT ON COLUMN iam.users.password_hash IS '密码哈希值，使用加盐哈希算法存储';
COMMENT ON COLUMN iam.users.salt IS '密码加盐值，用于增强密码安全性';
COMMENT ON COLUMN iam.users.nickname IS '用户昵称';
COMMENT ON COLUMN iam.users.phone IS '手机号码';
COMMENT ON COLUMN iam.users.created_at IS '创建时间';
COMMENT ON COLUMN iam.users.updated_at IS '更新时间，通过触发器自动维护';
COMMENT ON COLUMN iam.users.disabled_at IS '禁用时间，NULL表示未禁用';
COMMENT ON COLUMN iam.users.deleted_at IS '软删除时间，NULL表示未删除';

-- 角色表注释
COMMENT ON TABLE iam.roles IS '角色表，定义系统角色';
COMMENT ON COLUMN iam.roles.id IS '主键ID';
COMMENT ON COLUMN iam.roles.name IS '角色名称';
COMMENT ON COLUMN iam.roles.code IS '角色编码，唯一标识';
COMMENT ON COLUMN iam.roles.description IS '角色描述';
COMMENT ON COLUMN iam.roles.sort_order IS '排序顺序';
COMMENT ON COLUMN iam.roles.created_at IS '创建时间';
COMMENT ON COLUMN iam.roles.updated_at IS '更新时间，通过触发器自动维护';
COMMENT ON COLUMN iam.roles.disabled_at IS '禁用时间，NULL表示未禁用';
COMMENT ON COLUMN iam.roles.deleted_at IS '软删除时间，NULL表示未删除';

-- 权限表注释
COMMENT ON TABLE iam.permissions IS '权限表，定义系统权限';
COMMENT ON COLUMN iam.permissions.id IS '主键ID';
COMMENT ON COLUMN iam.permissions.name IS '权限名称';
COMMENT ON COLUMN iam.permissions.code IS '权限编码，唯一标识';
COMMENT ON COLUMN iam.permissions.type IS '权限类型：path-API路径权限，button-按钮权限，menu-菜单权限';
COMMENT ON COLUMN iam.permissions.resource IS '资源标识';
COMMENT ON COLUMN iam.permissions.action IS '操作类型';
COMMENT ON COLUMN iam.permissions.http_method IS 'HTTP方法：GET、POST、PUT、DELETE，仅path类型权限需要';
COMMENT ON COLUMN iam.permissions.description IS '权限描述';
COMMENT ON COLUMN iam.permissions.created_at IS '创建时间';
COMMENT ON COLUMN iam.permissions.updated_at IS '更新时间，通过触发器自动维护';

-- 用户角色关联表注释
COMMENT ON TABLE iam.user_roles IS '用户角色关联表，实现用户与角色的多对多关系';
COMMENT ON COLUMN iam.user_roles.id IS '主键ID';
COMMENT ON COLUMN iam.user_roles.user_id IS '用户ID，外键关联users表';
COMMENT ON COLUMN iam.user_roles.role_id IS '角色ID，外键关联roles表';
COMMENT ON COLUMN iam.user_roles.created_at IS '关联创建时间';
COMMENT ON COLUMN iam.user_roles.created_by IS '创建人ID';

-- 角色权限关联表注释
COMMENT ON TABLE iam.role_permissions IS '角色权限关联表，实现角色与权限的多对多关系';
COMMENT ON COLUMN iam.role_permissions.id IS '主键ID';
COMMENT ON COLUMN iam.role_permissions.role_id IS '角色ID，外键关联roles表';
COMMENT ON COLUMN iam.role_permissions.permission_id IS '权限ID，外键关联permissions表';
COMMENT ON COLUMN iam.role_permissions.created_at IS '关联创建时间';
COMMENT ON COLUMN iam.role_permissions.created_by IS '创建人ID';

-- =========================================================
-- 6. 初始化数据
-- =========================================================

-- 插入默认权限
-- Path类型权限（API路径权限）
-- 用户管理相关API权限
INSERT INTO iam.permissions (name, code, type, resource, action, http_method, description) VALUES
('分页查询用户列表', 'GET:/user', 'path', 'user', 'read', 'GET', '分页查询用户列表的API权限'),
('查询指定用户详情', 'GET:/user/:id', 'path', 'user', 'read', 'GET', '查询指定用户详情的API权限'),
('创建用户', 'POST:/user', 'path', 'user', 'write', 'POST', '创建用户的API权限'),
('批量创建用户', 'POST:/user/batch', 'path', 'user', 'write', 'POST', '批量创建用户的API权限'),
('更新用户信息', 'PUT:/user/:id', 'path', 'user', 'write', 'PUT', '更新用户基础信息的API权限'),
('重置用户密码', 'POST:/user/reset-password', 'path', 'user', 'write', 'POST', '管理员重置用户密码的API权限'),
('删除用户', 'DELETE:/user/:id', 'path', 'user', 'delete', 'DELETE', '删除用户的API权限'),
('查询用户角色', 'GET:/user/:id/roles', 'path', 'user', 'read', 'GET', '查询用户所有角色的API权限'),
('分配用户角色', 'PUT:/user/:id/roles', 'path', 'user', 'write', 'PUT', '为用户分配或移除角色的API权限'),
('切换用户状态', 'PUT:/user/user/status/toggle', 'path', 'user', 'write', 'PUT', '启用或禁用用户的API权限'),
('修改用户密码', 'PUT:/user/:id/password', 'path', 'user', 'write', 'PUT', '用户修改自己密码的API权限'),
('获取当前用户信息', 'GET:/user/me', 'path', 'user', 'read', 'GET', '获取当前用户信息的API权限'),

-- 角色管理相关API权限
('查询角色列表', 'GET:/role', 'path', 'role', 'read', 'GET', '查询角色列表的API权限'),
('查询角色详情', 'GET:/role/:id', 'path', 'role', 'read', 'GET', '查询角色详情的API权限'),
('查询角色权限', 'GET:/role/:id/permissions', 'path', 'role', 'read', 'GET', '查询角色权限的API权限'),
('分配角色权限', 'POST:/role/:id/permissions', 'path', 'role', 'write', 'POST', '为角色分配或移除权限的API权限'),
('创建角色', 'POST:/role', 'path', 'role', 'write', 'POST', '创建新角色的API权限'),
('更新角色信息', 'PUT:/role/:id', 'path', 'role', 'write', 'PUT', '更新角色信息的API权限'),
('删除角色', 'DELETE:/role/:id', 'path', 'role', 'delete', 'DELETE', '删除角色的API权限'),
('角色继承', 'PUT:/role/:id/inherit', 'path', 'role', 'write', 'PUT', '为角色添加父角色继承的API权限'),
('移除角色继承', 'DELETE:/role/:id/inherit/:parentId', 'path', 'role', 'write', 'DELETE', '移除角色父角色继承的API权限'),

-- 权限管理相关API权限
('查询权限列表', 'GET:/permission', 'path', 'permission', 'read', 'GET', '查询所有可分配权限的API权限'),
('查询权限详情', 'GET:/permission/:id', 'path', 'permission', 'read', 'GET', '查询某个权限详情的API权限'),
('创建权限', 'POST:/permission', 'path', 'permission', 'write', 'POST', '新增权限的API权限'),
('更新权限信息', 'PUT:/permission/:id', 'path', 'permission', 'write', 'PUT', '更新权限信息的API权限'),
('删除权限', 'DELETE:/permission/:id', 'path', 'permission', 'delete', 'DELETE', '删除权限的API权限'),

-- 组织管理相关API权限
('创建组织节点', 'POST:/organization', 'path', 'organization', 'write', 'POST', '创建组织节点的API权限'),
('获取组织节点', 'GET:/organization/:id', 'path', 'organization', 'read', 'GET', '获取组织节点的API权限'),
('更新组织节点', 'PUT:/organization/:id', 'path', 'organization', 'write', 'PUT', '更新组织节点名称的API权限'),
('删除组织节点', 'DELETE:/organization/:id', 'path', 'organization', 'delete', 'DELETE', '删除组织节点的API权限'),
('查询组织子节点', 'GET:/organization', 'path', 'organization', 'read', 'GET', '分页查询组织子节点的API权限'),
('获取组织祖先链', 'GET:/organization/:id/ancestors', 'path', 'organization', 'read', 'GET', '获取组织祖先链的API权限'),
('获取组织后代树', 'GET:/organization/:id/descendants', 'path', 'organization', 'read', 'GET', '获取组织后代树的API权限'),

-- 认证相关API权限
('用户登录', 'POST:/auth/login', 'path', 'auth', 'write', 'POST', '用户登录的API权限'),

-- 审计相关API权限
('查询用户审计日志', 'GET:/audit', 'path', 'audit', 'read', 'GET', '查询用户审计日志的API权限'),

-- 高级功能相关API权限
('查询用户最终权限', 'GET:/advanced/users/:id/permissions', 'path', 'advanced', 'read', 'GET', '查询用户最终权限的API权限'),
('校验用户权限', 'POST:/advanced/auth/check-permission', 'path', 'advanced', 'read', 'POST', '校验用户是否拥有指定权限的API权限');

-- Button类型权限（按钮权限）
INSERT INTO iam.permissions (name, code, type, resource, action, description) VALUES
('用户新增按钮', 'user:create:button', 'button', 'user', 'create', '用户管理页面新增按钮权限');

-- Menu类型权限（菜单权限）
INSERT INTO iam.permissions (name, code, type, resource, action, description) VALUES
('用户管理菜单', 'user:menu', 'menu', 'user', 'view', '用户管理菜单显示权限');

-- 插入默认角色
INSERT INTO iam.roles (name, code, description, sort_order) VALUES
('管理员', 'admin', '系统管理员，拥有系统管理权限', 1),
('教师', 'teacher', '教师角色，拥有教师管理权限', 2),
('学生', 'student', '学生角色，拥有学生管理权限', 3),
('访客', 'guest', '访客角色，拥有访客权限', 3);

-- 为管理员角色分配所有权限
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.code = 'admin';


-- 创建默认超级管理员用户
-- 默认密码: 123123，salt: randomsalt123456789012345678901，password_hash使用bcrypt算法
INSERT INTO iam.users (username, password_hash, salt, nickname) VALUES
('admin', '02c022088ee4c9012d0503dbcbb45bac90b0555755f3be0b8f2e11a8968cd40a', '107944d6b89da7f0f9fc2098cc0c372a7cab7a53059e33930c5cec0d0b7961d5', '管理员');

-- 为默认用户分配超级管理员角色
INSERT INTO iam.user_roles (user_id, role_id)
SELECT u.id, r.id
FROM iam.users u, iam.roles r
WHERE u.username = 'admin' AND r.code = 'admin';