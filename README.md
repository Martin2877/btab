# btab

Blue team analyisis box is a tool for blue team security analyisis.

BTAB (Blue Team Analyisis Box) 是一个蓝队分析工具箱，专注于攻击特征分析。可以辅助安全运营人员的流量包分析、木马分析等场景，目前已集成流量包检测、SQL注入检测、Webshell检测、bash命令执行检测，以及解码序列化等工具。

> 下载

[前往releases下载](https://github.com/Martin2877/btab/releases)

## 功能

初版本主要实现基本的功能和整体流程，主要包含以下三块功能：

威胁仓库：
用于存储流量包、payload文件、webshell文件的列表；

风险检测：
包括流量包检测、HTTP深度解析、SQLi检测、XSS检测等检测项；

辅助工具：
包括 jq 、反序列化解析、数据加解密等处理工具；

## 议题分享

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## 功能界面截图

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

