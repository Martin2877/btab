# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

Blue team analyisis box is a tool for blue team security analyisis.

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) 是一个蓝队分析工具箱，专注于攻击特征分析。可以辅助安全运营人员在客户现场较苛刻环境下(无网、无python环境)的流量包分析、木马分析等场景，目前已集成流量包检测、SQL注入检测、Webshell检测、bash命令执行检测，以及解码序列化等工具。

<a href="./README.md">English</a> -
<a>简体中文</a>

## 议题分享文档

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## 下载与使用

[前往releases下载](https://github.com/Martin2877/btab/releases)，双击执行即可。启动后访问本地的 8001 端口： http://localhost:8001

注意：部分功能需要 java 环境依赖。

## 功能

初版本主要实现基本的功能和整体流程，主要包含以下三块功能：

1. 威胁仓库：
用于存储流量包、payload文件、webshell文件的列表；

2. 风险检测：
包括流量包检测、HTTP深度解析、SQLi检测、XSS检测等检测项；

3. 辅助工具：
包括 jq 、反序列化解析、数据加解密等处理工具；

## 功能使用说明

### 流量包检测功能

需要有 tshark 依赖，注意需要配置 `config.yaml` 文件中指定 tshark 路径，如下：

```
pcapAnalyseConfig:
    # tsharkPath: tshark  # unix 环境
    tsharkPath: C:\Program Files\Wireshark\tshark.exe # win 环境
```

### webshell 检测功能

需要有 java 依赖。

## 功能界面截图

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

## 技术栈

| 模块 | 技术 | 备注 |
| ----- | ----- | ----- |
| 前端框架 | vue |  |
| 前端UI框架 | naive ui |  |
| 后端语言 | golang |  |
| 后端API | gin |  |
| 流量包检测逻辑 | python | 使用 go embed 嵌入实现 |
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

## 赞助

如果你觉得这个项目帮助到了你，你可以帮作者买一杯果汁表示鼓励 🍹。

<img src="https://user-images.githubusercontent.com/26109420/233270399-57c74ce3-a093-4321-8d1c-1cd701702ed6.jpg" alt=" Edge" width="180px" height="230px" /><img src="https://user-images.githubusercontent.com/26109420/233270423-d3e859b0-c3eb-4b90-88b7-74e523e84984.jpg" alt=" Edge" width="180px" height="230px" />

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Martin2877/btab.svg)](https://starchart.cc/Martin2877/btab)


