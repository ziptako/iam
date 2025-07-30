```shell
  goctl rpc protoc .\iam.proto -m --style goZero --zrpc_out . --go-grpc_out . --go_out .
```

```shell
  go build -o ./build/main.exe .
```

```shell
  build/main.exe
```