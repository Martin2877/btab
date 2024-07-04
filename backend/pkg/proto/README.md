# gRPC 联动

## 安装

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

export PATH="$PATH:$(go env GOPATH)/bin"

pip3 install grpcio
pip3 install grpcio-tools

sudo apt  install protobuf-compiler
sudo apt  install golang-goprotobuf-dev
```

## 生成依赖

protoc -I=./ --go_out=./go --python_out=./python ./msg.proto

protoc --proto_path=src --go_out=out --go_opt=paths=source_relative search.proto msg.proto

protoc --go_out=. --proto_path=./ --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./search.proto ./msg.proto

```
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./btab.proto
python3 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. ./btab.proto

protoc --go_out=. --proto_path=./ --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./search.proto
python3 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. ./search.proto

protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./engines.proto
python3 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. ./engines.proto

protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./msg.proto
python3 -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. ./msg.proto
```


protoc --go_out=. --go_opt=paths=source_relative \
--go-grpc_out=. --go-grpc_opt=paths=source_relative \
./search.proto

## 需要更改内容

生成的  pb2_grpc.py 文件，需要修改 import 路径，否则从其它位置加载会报错

```python
from . import btab_pb2 as btab__pb2
```

对 go 文件需要改接口