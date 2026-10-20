# btab backend

BTAB 后端服务（Go 1.21），Gin Web API + go:embed 内嵌前端 + SQLite 存储，同时提供命令行与 gRPC 接口。

## 目录结构

```
backend/
├── main.go              # 入口，调用 entry.Run()
├── entry/btab.go        # CLI 定义（server / engine / wf 子命令）、配置加载、服务启动
├── api/
│   ├── routers/         # 路由注册与静态资源（/ui）
│   │   └── v2/          # 业务接口：analyze / risk / engine / stores / tools / system / investigation
│   ├── middleware/      # license 等中间件
│   └── msg/             # 统一响应封装
├── engine/
│   ├── local/           # 本地检测引擎：sqli / xss / webshell / bash / inject / urldetect /
│   │                    #   weblog(日志解析) / http_parse / btt(冰蝎/哥斯拉/shiro/log4j2) / pcapgen
│   ├── nuclei/          # nuclei v3 引擎封装
│   ├── vuln/            # 漏洞模板管理（nuclei YAML 解析/校验/导入）
│   ├── pcapjs/          # JS 行为检测引擎（goja），strategies/ 为内置策略脚本
│   ├── session/         # 跨会话关联分析
│   ├── workflow/        # 联调工作流（pcapcheck / sqli 等）
│   ├── options/         # 引擎选项与 DSL 解析
│   └── plugin/          # 插件模块（jq / pcap / SerializationDumper / pcapcheck 等）
├── pkg/
│   ├── conf/            # 配置（config.yaml + 默认值）
│   ├── db/              # gorm + sqlite：威胁仓库、任务、模板、URL 规则、内置种子数据
│   ├── pcap/            # tshark 路径探测与调用
│   ├── pocloader/       # nuclei 引擎加载（含 DB 模板物化）
│   ├── proto/           # gRPC 服务（jupyter 调查分析）
│   └── ...              # file / logging / net / table / util
├── web/                 # go:embed 前端产物（dist/ 由 pack.sh 同步）与内嵌 cyberchef
├── tools/import_nuclei/ # 官方 nuclei-templates 导入工具（见根 AGENTS.md）
├── stores/              # 运行时样本/上传文件目录
└── config.yaml(.sample) # 运行配置
```

## 运行

```bash
go build -o btab.exe
./btab.exe server            # Web 服务，默认 :8001
./btab.exe server --grpc     # 仅 gRPC 模式（jupyter 调查分析）
./btab.exe engine -l         # 列出检测引擎
./btab.exe wf -l             # 列出工作流模板
```

首次启动自动初始化 `btab.sqlite`（内置 nuclei 模板、URL 规则集、示例样本一次性导入）。

## 打包

不在本目录手动拷贝前端产物，统一使用根目录约定的一键脚本：

```bash
bash backend/pack.sh           # dev：release/btab_dev/
bash backend/pack.sh release   # 完整包：release/btab_windows_amd64.zip
bash backend/pack.sh dev --skip-frontend   # 仅改了 Go 代码时
```

`pack.bat` 已废弃（cmd 下拷贝不执行），跨平台编译参考 `build.sh` / `build_*.bat`。

## 测试

```bash
go test ./...
```

主要测试集中在 `engine/`（各检测引擎、http_parse、pcapjs）与 `pkg/`（conf、pocloader、tshark）。
