package main

import (
	"flag"
	"fmt"
	"github.com/ziptako/iam/iam"
	"github.com/ziptako/iam/internal/config"
	"github.com/ziptako/iam/internal/svc"

	permissionserviceServer "github.com/ziptako/iam/internal/server/permissionservice"
	roleserviceServer "github.com/ziptako/iam/internal/server/roleservice"
	userserviceServer "github.com/ziptako/iam/internal/server/userservice"

	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/service"
	"github.com/zeromicro/go-zero/zrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var configFile = flag.String("f", "etc/iam.yaml", "the config file")

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)
	ctx := svc.NewServiceContext(c)

	s := zrpc.MustNewServer(c.RpcServerConf, func(grpcServer *grpc.Server) {
		// 注册用户服务
		iam.RegisterUserServiceServer(grpcServer, userserviceServer.NewUserServiceServer(ctx))
		// 注册角色服务
		iam.RegisterRoleServiceServer(grpcServer, roleserviceServer.NewRoleServiceServer(ctx))
		// 注册权限服务
		iam.RegisterPermissionServiceServer(grpcServer, permissionserviceServer.NewPermissionServiceServer(ctx))

		if c.Mode == service.DevMode || c.Mode == service.TestMode {
			reflection.Register(grpcServer)
		}
	})
	defer s.Stop()

	fmt.Printf("Starting rpc server at %s...\n", c.ListenOn)
	s.Start()
}
