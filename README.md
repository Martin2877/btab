# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

Blue team analyisis box is a tool for blue team security analyisis.

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) is a Blue team analyisis box，focusing on attack signature analysis。It can assist security operation personnel in scenarios such as traffic packet analysis and Trojan horse analysis in the harsh environment of the customer site (no network, no python environment). Currently, it has integrated traffic packet detection, SQL injection detection, Webshell detection, bash command execution detection, and Decoding serialization and other tools.

<a>English</a> - 
<a href="./README_zh-cn.md">简体中文</a>

## slides

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## download

[ahead for releases](https://github.com/Martin2877/btab/releases)，Double-click to execute. Access the local port 8001 after startup： http://localhost:8001

Note: Some functions require `java environment` dependencies.

## functions

The initial version mainly implements basic functions and overall process, mainly including the following three functions:

1. Threat Warehouse:
A list for storing traffic packets, payload files, and webshell files;

2. Risk detection:
Including traffic packet detection, HTTP deep analysis, SQLi detection, XSS detection and other detection items;

3. Auxiliary tools:
Including jq, deserialization analysis, data encryption and decryption and other processing tools;

## function instructions

### traffic packet detection function

Need to have tshark dependency, note that you need to specify the tshark path in the `config.yaml` file, as follows:

```
pcapAnalyseConfig:
    # tsharkPath: tshark  # unix env
    tsharkPath: C:\Program Files\Wireshark\tshark.exe # win env
```

### webshell detection function

Requires java dependency.

## screenshot of functional interface

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

## technology stack

| Modules | Technology | Remarks |
| ----- | ----- | ----- |
| front-end framework | vue | |
| Front-end UI framework | naive ui | |
| backend language | golang | |
| Backend API | gin | |
| Traffic packet detection logic | python | go embed |
| java class detection engine | java | embedding implementation using go embed |

## Q&A

<details>
   <summary>What is the background of the development of this tool? </summary>
   <p> Since the author has been engaged in the security industry, he has been focusing on the field of traffic security analysis, and is also interested in software research and development.
   On the one hand, this project is to share the usual research results and promote exchanges and learning. On the other hand, there is too little communication with the blue team in China. Now there are more red teams. I hope this way can be used to form a blue team. communication group
   </p>
</details>

<details>
   <summary>Will this tool be open source? </summary>
   <p> At best, it can only partially open source. Because of the commercial issues involved, some core detection items within the company are not convenient to open source, but some non-sensitive functional modules can be open sourced as separate projects for learning reference. </p>
</details>

## comminicate

You can join the group chat or add my [Ali0th](https://github.com/Martin2877) friend to enter the group chat.

<img src="https://user-images.githubusercontent.com/26109420/233271729-b0d8644f-2538-40ae-8bde-abeb1187c5bb.jpg" alt=" Edge" width="180px" height="230px" /><img src="https://user-images.githubusercontent.com/26109420/233271942-aeccc557-da89-4e6e-9e4b-60cc885e141e.jpg" alt=" Edge" width="180px" height="230px" />

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Martin2877/btab.svg)](https://starchart.cc/Martin2877/btab)
