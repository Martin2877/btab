# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

Blue team analyisis box is a tool for blue team security analyisis.

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) 是一个蓝队分析工具箱，专注于攻击特征分析。可以辅助安全运营人员的流量包分析、木马分析等场景，目前已集成流量包检测、SQL注入检测、Webshell检测、bash命令执行检测，以及解码序列化等工具。

<a href="./README.md">English</a> -
<a>简体中文</a>

## 目录

- [btab](#btab)
  - [目录](#目录)
  - [文档跳转](#文档跳转)
  - [功能](#功能)
  - [功能界面截图](#功能界面截图)
  - [开始使用](#开始使用)
  - [开发编译说明](#开发编译说明)
    - [前端开发](#前端开发)
    - [后端开发](#后端开发)
  - [插件化模块开发说明](#插件化模块开发说明)
    - [插件结构接口](#插件结构接口)
  - [技术栈](#技术栈)
  - [Q\&A](#qa)
  - [交流](#交流)
  - [更新日志](#更新日志)
    - [第二版本](#第二版本)
    - [第一版本](#第一版本)
  - [趋势](#趋势)

## 文档跳转

- 关键内容

[开发编译说明](#开发编译说明)

[插件化模块开发说明](#插件化模块开发说明)

[调查分析模块与 jupyter说明](./investigation/doc/README_zh-cn.md)

- 议题分享文档

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)


## 功能

初版本主要实现基本的功能和整体流程，主要包含以下三类功能：

1. 威胁仓库：

用于存储流量包、payload文件、webshell文件的列表；

2. 风险检测：

包括流量包检测、HTTP深度解析、SQLi检测、XSS检测等检测项；

3. 辅助工具：

包括 jq 、反序列化解析、数据加解密等处理工具；

4. 调查分析能力

使用基于 jupyter 的能力，可以编写 python 脚本进行分析;

## 功能界面截图

- web 功能

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

- jupyter 分析

![分析](./investigation/doc/Snipaste_2024-07-03_19-18-35.jpg)

## 开始使用

- 下载

[前往releases下载](https://github.com/Martin2877/btab/releases)

- 配置

1. 需要有 tshark 依赖，配置 `config.yaml` 文件中指定 tshark 路径，如下：

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

- 执行

双击执行即可。启动后访问本地的 8001 端口： http://localhost:8001

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

需要将 `./frontend/dist/` 目录，拷贝到 `./backend/web/dist`，然后在 `./backend/` 下执行，对前端进行打包成 go 文件

```bash
go-bindata-assetfs -o web/bindata.go -pkg web web/dist/...
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
cd ./backend
go mod tidy
go mod vendor
go build
```

## 插件化模块开发说明

通过标准的接口实现统一的插件化模块规范，方便后续添加新的插件模块，目前有三个模块，`jq`、`pcap`、`SerializationDumper`, 只要遇到有新的场景，均可以增加进来。

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
| 前端框架 | vue |  |
| 前端UI框架 | naive ui |  |
| 后端语言 | golang |  |
| 后端 Web | gin |  |
| 流量包检测逻辑 | python | grpc / jupyter |
| java类检测引擎 | java | 使用 go embed 嵌入实现 |

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


