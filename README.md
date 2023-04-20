# btab

Blue team analyisis box is a tool for blue team security analyisis.

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) 是一个蓝队分析工具箱，专注于攻击特征分析。可以辅助安全运营人员在客户现场较苛刻环境下(无网、无python环境)的流量包分析、木马分析等场景，目前已集成流量包检测、SQL注入检测、Webshell检测、bash命令执行检测，以及解码序列化等工具。

> 版本: v0.3.0

## 下载与使用

[前往releases下载](https://github.com/Martin2877/btab/releases)，双击执行即可。启动后访问本地的 8001 端口： http://localhost:8001

## 功能

初版本主要实现基本的功能和整体流程，主要包含以下三块功能：

1. 威胁仓库：
用于存储流量包、payload文件、webshell文件的列表；

2. 风险检测：
包括流量包检测、HTTP深度解析、SQLi检测、XSS检测等检测项；

3. 辅助工具：
包括 jq 、反序列化解析、数据加解密等处理工具；

## 议题分享文档

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## 功能界面截图

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

## 交流

可以加入群聊或加我[Ali0th](https://github.com/Martin2877)好友进入群聊。

<img src="https://user-images.githubusercontent.com/26109420/233271729-b0d8644f-2538-40ae-8bde-abeb1187c5bb.jpg" alt=" Edge" width="180px" height="230px" /><img src="https://user-images.githubusercontent.com/26109420/233271942-aeccc557-da89-4e6e-9e4b-60cc885e141e.jpg" alt=" Edge" width="180px" height="230px" />

## 赞助

如果你觉得这个项目帮助到了你，你可以帮作者买一杯果汁表示鼓励 🍹。

<img src="https://user-images.githubusercontent.com/26109420/233270399-57c74ce3-a093-4321-8d1c-1cd701702ed6.jpg" alt=" Edge" width="180px" height="230px" /><img src="https://user-images.githubusercontent.com/26109420/233270423-d3e859b0-c3eb-4b90-88b7-74e523e84984.jpg" alt=" Edge" width="180px" height="230px" />


