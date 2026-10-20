# BTAB × Wireshark 集成插件

`btab.lua` 是 Wireshark 的 Lua 插件，通过 REST API 调用 BTAB 后端服务，
为 Wireshark 补齐其本身不具备的「攻击检测、攻击过程梳理、漏洞分析、payload 解密」能力。

## 架构

```
Wireshark (GUI, 用户主操作界面)
   └── btab.lua 插件
          │  ┌── Lua tap 提取当前捕获的 HTTP 流（无需文件路径）
          │  ├── 右键菜单提取选中数据包字段
          │  └── HTTP REST  /api/analyze/*
          ▼
btab server（服务形式常驻，默认 :8001）
   ├── 检测引擎：SQLi / XSS / Bash(远程)
   ├── HTTP 报文解析
   ├── Payload 解码：base64 / base64url / url / hex / java 序列化
   ├── 流攻击梳理（结构化流 → 逐流检测）
   ├── pcap 文件分析（tshark，服务端本地文件）
   └── DSL 引擎（jq / SerializationDumper / pcap 插件链）
```

**设计原则**：Wireshark 负责协议解析（它的最强能力），BTAB 只做安全判定。
当前捕获的攻击梳理通过 Lua tap 直接提取已打开的数据——**不要求保存文件、
不要求 BTAB 与 Wireshark 同机**。

## 前置条件

| 组件 | 要求 |
|---|---|
| Wireshark | >= 4.2（`register_packet_menu` 需 4.2+；4.2 以下仅有 Tools 菜单可用） |
| BTAB | `btab server` 运行中，HTTP 端口可达（默认 8001） |
| curl | Windows 10+ 自带 `curl.exe`；无 curl 时自动回退 PowerShell |
| tshark | pcap 梳理功能需要，在 `config.yaml` 的 `pcapAnalyseConfig.tsharkpath` 配置 |

## 启动 BTAB 服务

```bash
cd backend
./btab server            # 默认 :8001
./btab server -p 8001    # 指定端口
```

健康检查：

```bash
curl http://127.0.0.1:8001/api/analyze/health
```

## 安装插件

把 `btab.lua` 复制到 Wireshark 个人插件目录：

| 平台 | 路径 |
|---|---|
| Windows | `%APPDATA%\Wireshark\plugins\btab.lua` |
| Linux | `~/.local/lib/wireshark/plugins/btab.lua` |
| macOS | `~/.config/wireshark/plugins/btab.lua` |

可在 Wireshark `Help -> About -> Folders -> Personal Plugins` 确认目录。重启 Wireshark 生效。

### 配置 BTAB 地址

- `Edit -> Preferences -> Protocols -> BTAB -> BTAB API 地址`（默认 `http://127.0.0.1:8001`）
- 或环境变量 `BTAB_URL`（优先于偏好设置）

## 功能

### 1. 数据包右键菜单（按选中粒度）

在 Packet List 中右键数据包 → `BTAB` 子菜单，按"帧 / 会话"分组：

| 菜单项 | 说明 |
|---|---|
| `一键分析` | 对选中帧自动执行全部适用分析：URI/Header 攻击检测、HTTP 深度解析、Payload 检测+解码；若属于含 HTTP 的 TCP 会话，再对**整条流**做综合分析（nuclei + webshell 关联）。所有结果合入同一窗口，命中帧写入告警标注 |
| `帧/攻击检测` | 提取 HTTP URI/Host/UA 与 TCP payload，调 `/api/analyze/detect`，展示 SQLi/XSS/Bash 命中 |
| `帧/HTTP 深度解析` | 重组 HTTP 请求送 `/api/analyze/http_parse`，展示 URL/Body 参数提取结果 |
| `帧/Payload 解码` | 取 `http.file_data`/`tcp.payload`，送 `/api/analyze/decode` 自动尝试多种解码 |
| `会话/HTTP 流攻击梳理` | 取选中包的 `tcp.stream`，tap 重扫该流的全部 HTTP 请求，送 `/api/analyze/flows` 逐流检测；命中帧可一键应用 display filter |
| `会话/综合分析 (nuclei)` | 同上取 `tcp.stream`，但该流全部请求/响应配对后送 `/api/analyze/session`：nuclei 规则命中 + webshell 跨帧关联，结果写入「BTAB 检测告警」树与 Expert Information |

> 会话级菜单项等价于把"Tools → 分析当前捕获 / 综合分析"的作用域收窄到选中包所在的 TCP 流，
> 适合先定位可疑会话再深挖的场景；帧级菜单项只分析当前数据包。

### 2. Tools → BTAB 菜单

| 菜单项 | 说明 |
|---|---|
| `综合分析 (nuclei + 跨会话)` | **v1.1 新增**：重扫当前捕获，提取全部 HTTP 请求/响应并配对，送 `/api/analyze/session`：① 用 nuclei 模板（数据库中启用的）检测攻击；② 跨帧/跨会话关联检测（冰蝎/蚁剑/菜刀 webshell：从前置会话提取口令/协商密钥，解密后续请求与响应）。结果写入数据包详情「BTAB 检测告警」树、Expert Information 与 Info 列，可用 `btab.severity` / `btab.kind` / `btab.rule` 过滤 |
| `清除告警标注` | 清空 BTAB 告警标注并刷新 |
| `分析当前捕获` | **核心功能**：Lua tap 重扫当前打开的捕获（含未保存抓包），提取全部 HTTP 请求送 `/api/analyze/flows` 逐流检测；结果窗口列出命中帧与详情，点击 `仅显示攻击帧` 一键应用 display filter 定位攻击流量 |
| `服务状态` | GET `/api/analyze/health`，查看引擎/插件/tshark 可用性 |
| `文本分析` | 粘贴任意文本/hex，选择分析项 `all/detect/decode/http_parse` 执行（Lua 无法读取字节窗格选中的文本，分析选中文本时先复制粘贴至此） |
| `Payload 解码` | 手动输入文本/hex，选择编码解码 |
| `DSL 引擎查询` | 输入 `.btab` DSL 脚本文件路径 → `/api/analyze/engine` 执行插件链 |
| `pcap 服务端文件` | 高级用法：直接指定 BTAB 服务端本地 pcap 路径 → `/api/analyze/pcap`（一般不需要，用"分析当前捕获"即可） |

> `分析当前捕获` 的典型工作流：打开 pcap → Tools → BTAB → 分析当前捕获
> → 弹窗看到"HTTP 请求流 N 条，命中 M 条"及每条命中详情 → 点击
> `仅显示攻击帧` 回到 Packet List 只剩攻击流量，继续正常分析。

## nuclei 检测与跨会话分析（v1.1）

- nuclei 模板在「数据存储 → nuclei」上传并启用即可使用；btab 内置解析器与检测引擎（`backend/engine/nuclei`），
  不依赖 nuclei 主动发包：先匹配请求（method/path/query/raw/body），再用 matchers（word/regex/status/size/binary/dsl）校验响应，
  `internal: true` 的辅助 matcher 与整条路径均为变量的请求会被忽略以避免误报。
- 跨会话检测（`backend/engine/session`）：按「主机 + 脚本路径」聚合整个捕获：
  - 冰蝎：取前置 GET 会话响应中的 16 位协商密钥（或默认密钥 `e45e329feb5d925b`），AES-128-ECB / XOR 解密后续 POST 与响应，识别 Java class / 明文载荷；
  - 蚁剑/菜刀：识别各请求共有的“口令参数”（如 `pass=@eval(...)`），并 base64 还原其余参数中的真实命令。
- 过滤示例：`btab.severity == "critical"`、`btab.kind contains "webshell"`、`btab.rule == "CVE-2021-44228"`。
- 服务端接口：`POST /api/analyze/nuclei`（pcap 文件或 exchanges）、`POST /api/analyze/session`（nuclei + 跨会话 + 逐帧 annotations）、`GET /api/analyze/nuclei/templates`。

## API 契约（`/api/analyze/*`）

标准响应：`{"code":200,"message":"ok","type":"success","result":{...}}`

| 端点 | 方法 | 请求体 | 返回 result |
|---|---|---|---|
| `/api/analyze/health` | GET | - | `{version, uptime_sec, tshark_path, tshark_ok, engines[], plugins[]}` |
| `/api/analyze/detect` | POST | `{content, url_decode?, input_format?"raw|hex", engines?[]}` | `{risk, summary, sqli?, xss?, bash?}` 各含 `{found,code,message,result,available}` |
| `/api/analyze/http_parse` | POST | `{req_data?, res_data?}` | `{request:{summary,url_args,body_args,form_data}, response}` |
| `/api/analyze/decode` | POST | `{content, encoding?"auto|base64|base64url|url|hex|java", input_format?"raw|hex"}` | `{results:[{encoding,success,output,note}]}` |
| `/api/analyze/pcap` | POST | JSON `{file, filter?, fields?, detect?}` 或 multipart `-F file=@x.pcap` | `{summary:{total_flows,detected_flows,attack_types}, flows:[{frame,src_ip,...,uri,body,detections[]}]}` |
| `/api/analyze/flows` | POST | `{flows:[{frame,src_ip,src_port,dst_ip,dst_port,stream,method,host,uri,user_agent,body?,body_hex?}], detect?}`（单批 ≤10000） | `{summary:{total_flows,detected_flows,attack_types,hit_frames}, flows:[...,detections[]]}` |
| `/api/analyze/nuclei` | POST | multipart `-F file=@x.pcap [-F min_severity=high] [-F tags=rce]`，或 JSON `{file? , exchanges?, templates?, templates_dir?, use_store?, min_severity?, tags?}` | `{summary, findings[], errors[]}` |
| `/api/analyze/session` | POST | 同上 | `{summary, nuclei[], sessions[], annotations[{frame,severity,kind,rule,title,detail}], errors[]}` |
| `/api/analyze/engine` | POST | `{query}` DSL 文本 | `{result:{final, steps[]}}` |

### DSL 速览

```
: a  <文本/JSON>
: b  {...}

| jq
|: filter .foo.bar
|: content {{b}}

| sqli
|: content {{R}}
```

## 故障排查

- 弹窗提示 `HTTP 请求失败`：确认 `btab server` 运行、端口可通、curl 存在（`curl --version`）。
- `tshark_ok: false`：检查 `config.yaml` `pcapAnalyseConfig.tsharkpath`。
- 右键菜单没有 BTAB 项：Wireshark 版本需 >= 4.2，且数据包需匹配对应过滤器（如 http/tcp.payload）。
- Lua 报错查看：`Help -> About -> Wireshark` 或命令行 `wireshark -X lua_script:...` 加载测试。
