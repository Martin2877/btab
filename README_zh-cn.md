# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) 是一个蓝队分析工具箱，专注于攻击特征分析与告警研判。可辅助安全运营人员完成流量包分析、HTTP 报文研判、Web 访问日志分析、攻击载荷识别、加密流量解密等场景。本版本内置 nuclei 漏洞规则引擎、正则 URL 规则引擎与可扩展的 JS 行为检测脚本引擎，提供 Web 界面、命令行两种使用方式，并可通过内置的 `btab.lua` 插件在 Wireshark 中直接调用。

<a href="./README.md">English</a> -
<a>简体中文</a>

## 目录

- [btab](#btab)
  - [目录](#目录)
  - [文档跳转](#文档跳转)
  - [功能](#功能)
  - [功能界面截图](#功能界面截图)
  - [开始使用](#开始使用)
    - [命令行使用](#命令行使用)
  - [开发编译说明](#开发编译说明)
    - [前端开发](#前端开发)
    - [后端开发](#后端开发)
  - [插件化模块开发说明](#插件化模块开发说明)
    - [插件结构接口](#插件结构接口)
  - [技术栈](#技术栈)
  - [Q\&A](#qa)
  - [交流](#交流)
  - [更新日志](#更新日志)
    - [v1.1.0](#v110)
    - [v0.5.x](#v05x)
    - [v0.3.x](#v03x)
  - [趋势](#趋势)

## 文档跳转

- 关键内容

[开发编译说明](#开发编译说明)

[插件化模块开发说明](#插件化模块开发说明)

[调查分析模块与 jupyter说明](./investigation/doc/README_zh-cn.md)

[Wireshark 插件（btab.lua）使用说明](./wireshark/README.md)

- 议题分享文档

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)


## 功能

当前版本包含以下七类功能模块：

### 1. 一键分析

统一分析入口：粘贴任意文本载荷、上传 pcap 流量包或 Web 访问日志（nginx/apache combined/common 格式），系统自动归档样本至威胁仓库，并编排适用的检测方式（流量会话梳理、行为检测脚本、nuclei 漏洞规则、URL 规则、跨会话关联等）异步执行，产出结构化分析报告（攻击链路图、检出明细、逐步骤耗时）。

### 2. 威胁仓库

流量包、payload、webshell、web 访问日志、nuclei 模板的统一存储与管理，全部入库 SQLite，按 sha1 去重，支持在线查看文件内容。随包内置示例样本（webshell / 攻击载荷字典 / 访问日志）与官方 nuclei-templates 模板库，首次启动一次性导入。

### 3. 风险检测

- **流量包检测**：基于 tshark 提取会话，多策略并行检测（JS 行为脚本、nuclei 模板、SQLi/XSS 等本地引擎），异步任务 + 实时进度 + 检出详情；
- **HTTP 深度解析**：支持原始报文 / Wireshark httpstream / hex 多种输入，自动拆分多组请求响应对，提取参数特征并完成风险识别，还可将报文合成 pcap 文件导出；
- **攻击载荷检测**：粘贴任意载荷智能识别攻击类别，联动 SQLi、XSS、Webshell、Bash 命令、Log4j2 JNDI、nuclei 规则特征等各引擎给出明细结果。

### 4. 检测引擎

- **漏洞检测引擎**：nuclei YAML 模板在线管理，支持单文件上传、zip 模板包导入（自动识别字典 / workflows 等资源）、在线编辑与校验、批量启停、规则调试；
- **行为检测引擎**：检测逻辑以 JavaScript 编写（goja 运行时执行），内置 21 种检测策略——16 种针对 pcap 流量（蚁剑上传恶意软件、CORS 配置不当、CVE-2020-1957、CVE-2022-21907、目录暴破、FTP 暴力破解、HTTP 分块传输、ICMP 扫描、log4j 攻击、SYN 端口扫描、3389 通信、shiro550、源码/备份文件泄露、SQL 注入、Telnet 弱口令、webshell 上传等），5 种针对 web 访问日志（目录爆破、爆破后登录后台、注入载荷喷洒、敏感文件探测、可疑脚本/webshell 访问），支持上传自定义脚本覆盖同名内置版本、在线调试；
- **URL 检测引擎**：基于正则的 URL / User-Agent / Referer 特征规则，分 info~critical 五个等级。内置源自 webloghunter 的规则集（攻击特征、扫描器 UA 识别、其他特征），支持在线编辑、正则校验、批量启停、rules.yaml 导入与单值调试。

### 5. 辅助工具

jq、SerializationDumper 反序列化解析、冰蝎流量解密、哥斯拉流量解密、Shiro rememberMe 密钥检测（内置常用密钥字典爆破）、Log4j2 lookup 解析与 payload 变体生成、内嵌 CyberChef。

### 6. 调查分析能力

基于 jupyter + grpc 的扩展能力，可编写 python 脚本调用引擎插件进行分析，理论上可无限扩展（详见[调查分析模块文档](./investigation/doc/README_zh-cn.md)）。

### 7. Wireshark 集成

`wireshark/btab.lua` 是 Wireshark Lua 插件，通过 REST API 调用 BTAB 后端，为 Wireshark 补齐其不具备的安全检测能力：数据包右键菜单（攻击检测、HTTP 深度解析、Payload 解码）、整包 HTTP 流梳理、会话级 nuclei 检测与跨帧 webshell 解密（冰蝎/蚁剑/菜刀），检测结果写入数据包详情树、Expert Information 与 `btab.*` 显示过滤器。详见 [Wireshark 插件使用说明](./wireshark/README.md)。

## 功能界面截图

- 一键分析（统一入口 / 分析报告 / 任务列表）

![统一分析入口](./docs/screenshots/analyze-home.png)

![分析报告](./docs/screenshots/analyze-report.png)

![分析任务](./docs/screenshots/analyze-tasks.png)

- 风险检测（流量包检测 / HTTP 深度解析 / 攻击载荷检测）

![流量包检测](./docs/screenshots/risk-paonline.png)

![检测结果](./docs/screenshots/risk-paonline-result.png)

![HTTP深度解析](./docs/screenshots/risk-http-parse.png)

![攻击载荷检测](./docs/screenshots/risk-payload.png)

- 检测引擎（漏洞检测引擎 / 行为检测引擎）

![漏洞检测引擎概览](./docs/screenshots/engine-vuln.png)

![nuclei规则模板](./docs/screenshots/engine-vuln-templates.png)

![行为检测引擎概览](./docs/screenshots/engine-logic.png)

![行为检测脚本](./docs/screenshots/engine-logic-scripts.png)

- 威胁仓库与辅助工具

![流量包列表](./docs/screenshots/stores-pcap.png)

![冰蝎流量解密](./docs/screenshots/tools-behinder.png)

![Shiro密钥检测](./docs/screenshots/tools-shiro.png)

![jq](./docs/screenshots/tools-jq.png)

- jupyter 分析

![分析](./investigation/doc/Snipaste_2024-07-03_19-18-35.jpg)

## 开始使用

- 下载

[前往releases下载](https://github.com/Martin2877/btab/releases)

- 配置

1. 需要有 tshark 依赖，配置 `config.yaml` 文件中指定 tshark 路径，如下（也可在 Web 界面"系统设置"中在线修改，系统会自动探测常见安装路径）：

```
pcapAnalyseConfig:
    # tsharkPath: tshark  # unix 环境
    tsharkPath: C:\Program Files\Wireshark\tshark.exe # win 环境
```

2. (可选) java 环境，部分功能需要系统有 java 环境。

3. (可选) 使用 jupyter notebook 的相关依赖

```bash
pip install jupyterlab
pip install grpcio-tools
```

4. (可选) Wireshark 集成：将 `wireshark/btab.lua` 复制到 Wireshark 个人插件目录，即可在 Wireshark 中直接分析流量（需 Wireshark >= 4.2）。详见 [wireshark/README.md](./wireshark/README.md)。

- 执行

双击执行即可。启动后访问本地的 8001 端口： http://localhost:8001

### 命令行使用

```shell
# 启动为 web 服务（默认 8001 端口）
btab server
btab server -p 8001      # 指定端口
btab server --grpc       # 仅 grpc 模式

# 指定引擎进行分析
## 查看检测类引擎列表
btab engine -l
## 流量包解析
btab engine -e pcap -f file.pcap

# 工作流
## 查看 workflow 模板列表
btab wf -l
## 流量包检测流程（提取 HTTP 会话并逐条进行 SQLi 检测）
btab wf -t pcapcheck -f xxx.pcap
btab wf -t pc -f xxx.pcap        # pc 为 pcapcheck 的别名
## SQL 注入检测
btab wf -t sqli -c "' and 1+1"
```

## 开发编译说明

### 前端开发

- 安装依赖

```bash
cd frontend

yarn install
```

- 运行

```bash
yarn dev
```

- 打包

```bash
yarn build
```

- 将前端嵌入到后端

前端通过 `go:embed` 内嵌进二进制，需要将 `./frontend/dist/` 目录拷贝到 `./backend/web/dist`，然后在 `./backend/` 下执行 `go build` 即可。

也可以直接使用一键打包脚本（自动完成前端构建、dist 同步与 go build）：

```bash
bash backend/pack.sh           # dev 模式：增量构建，输出 release/btab_dev/
bash backend/pack.sh release   # 完整构建，输出 release/btab_windows_amd64.zip
```

### 后端开发

- 安装模块

```bash
cd ./backend
go mod tidy
go mod vendor
```

- 打包

```bash
go build
```

## 插件化模块开发说明

通过标准的接口实现统一的插件化模块规范，方便后续添加新的插件模块，目前有 `jq`、`pcap`、`SerializationDumper` 等模块, 只要遇到有新的场景，均可以增加进来。

并且，这些插件都可以被引擎调用，作为调查分析过程中的分析工具使用，理论上，可以无限扩展能力。

代码详细见 [plugin](./backend/engine/plugin/)

### 插件结构接口

```go
type Plugin interface {
	Init()  // 初始化
	Set(key string, value interface{})  // 设置插件所需变量
	Check() error  // 检查设置变量值
	Exec() error // 执行此插件
	GetState() int // 获取插件任务进度
	GetFinalStatus() int // 获取最终结果
	GetResult() string // 获取输出结果
}
```

## 技术栈

| 模块 | 技术 | 备注 |
| ----- | ----- | ----- |
| 前端框架 | vue3 + vite |  |
| 前端UI框架 | naive ui |  |
| 后端语言 | golang |  |
| 后端 Web | gin |  |
| 数据存储 | gorm + sqlite | 威胁仓库、检测任务、模板脚本均入库 |
| 漏洞检测引擎 | nuclei v3 | 加载 YAML 模板识别 pcap / http 报文中的攻击 |
| 行为检测引擎 | goja | JavaScript 编写的检测脚本，可在线扩展 |
| URL 检测引擎 | go regexp | 内置 webloghunter 衍生规则集，在线管理 |
| 流量包解析 | tshark + gopacket | 需配置 tshark 路径 |
| Wireshark 集成 | Lua 插件 + REST API | `wireshark/btab.lua`，需 Wireshark >= 4.2 |
| 调查分析 | python | grpc / jupyter |

## Q&A

<details>
  <summary>本工具的开发背景是什么？</summary>
  <p> 笔者从事安全行业以来，一直专注于流量安全分析领域，同时也对软件研发感兴趣。
  本项目一方面是分享平时的研究成果，促进交流学习，另一方面是国内对于蓝队这方面的交流太少了，现在都是红队方面较多，希望可以通过这个方式组建一个在蓝队方面研究的交流群体
  </p>
</details>

<details>
  <summary>本工具会开源吗？</summary>
  <p> 至多只能做到部分开源。因为涉及商业问题，有一些公司内部的核心检测项不方便开源，但其中一些非敏感的功能模块可以以单独的项目开源供学习参考。 </p>
</details>

## 交流

可以加入群聊或加我[Ali0th](https://github.com/Martin2877)好友进入群聊。

<img src="https://user-images.githubusercontent.com/26109420/233271729-b0d8644f-2538-40ae-8bde-abeb1187c5bb.jpg" alt=" Edge" width="180px" height="230px" /><img src="https://user-images.githubusercontent.com/26109420/233271942-aeccc557-da89-4e6e-9e4b-60cc885e141e.jpg" alt=" Edge" width="180px" height="230px" />

## 更新日志

### v1.1.0

大版本优化：整体 UI 重构，检测能力由"单点工具"升级为"引擎 + 策略 + 任务"体系。

- [x] 统一分析入口：粘贴载荷 / 上传 pcap / 上传 web 访问日志一键分析，自动归档样本并生成结构化分析报告（攻击链路、检出明细）
- [x] 加载 nuclei yaml 模板识别 pcap 中的攻击，模板可在线管理、调试、批量启停，支持 zip 模板包导入，随包内置官方 nuclei-templates
- [x] JS 行为检测脚本引擎（goja 运行时）：内置 21 种检测策略，覆盖 pcap 流量与 web 访问日志两类数据源，支持上传自定义脚本扩展，可在线调试
- [x] URL 规则检测引擎：正则匹配 URL / UA / Referer，内置 webloghunter 衍生规则集，支持在线编辑、校验、批量启停与 rules.yaml 导入
- [x] Web 访问日志分析：nginx/apache 日志上传入库，联动 URL 规则与日志行为策略检出目录爆破、注入喷洒、webshell 访问等行为
- [x] Wireshark Lua 插件（`btab.lua`）：数据包右键菜单与整包梳理、会话级 nuclei 检测、跨帧 webshell 解密、Expert Information / `btab.*` 告警标注
- [x] 流量包检测策略化：多策略并行执行、实时进度、检出详情展示
- [x] HTTP 深度解析：原始报文 / httpstream / hex 输入，自动拆分请求响应对并识别风险，支持合成 pcap 导出
- [x] 攻击载荷智能识别：自动分类并联动 SQLi / XSS / Webshell / Bash / Log4j2 / nuclei 特征各引擎
- [x] 冰蝎、哥斯拉流量解密，Shiro 密钥检测，Log4j2 解析与生成等辅助工具
- [x] 各类样本、模板、任务均存储到数据库（sqlite），而非文件
- [x] 命令行版本：`server` / `engine` / `workflow` 子命令
- [x] 系统设置在线化：配置在线查看与修改、tshark 自动探测

### v0.5.x

第一版本实现大体的框架，但为了实现无依赖导致整体打包困难、体积较大，且扩展能力不足等问题，第二部版本需要进行优化。通过 DSL 语法和 python jupyter 增加分析能力，通过 grpc 实现扩展能力。

- [x] 插件化模块
- [x] 通用联调引擎，实现多模块串联处理
- [x] DSL语法查询功能
- [x] jupyter分析流量包功能
- [x] grpc 实现

### v0.3.x

- [x] 基本框架实现

## 趋势

[![Stargazers over time](https://starchart.cc/Martin2877/btab.svg)](https://starchart.cc/Martin2877/btab)

