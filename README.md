# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

Blue team analyisis box is a tool for blue team security analyisis.

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) is a Blue team analyisis box，focusing on attack signature analysis。It can assist security operation personnel in scenarios such as traffic packet analysis and Trojan horse analysis. Currently, it has integrated traffic packet detection, SQL injection detection, Webshell detection, bash command execution detection, and Decoding serialization and other tools.

<a>English</a> - 
<a href="./README_zh-cn.md">简体中文</a>

## contents

- [btab](#btab)
  - [contents](#contents)
  - [items](#items)
  - [Function](#function)
  - [screenshot of functional interface](#screenshot-of-functional-interface)
  - [Get started](#get-started)
  - [Development and compilation instructions](#development-and-compilation-instructions)
    - [Front-end development](#front-end-development)
    - [Back-end development](#back-end-development)
  - [Plug-in module development instructions](#plug-in-module-development-instructions)
    - [Plug-in structure interface](#plug-in-structure-interface)
  - [technology stack](#technology-stack)
  - [Q\&A](#qa)
  - [comminicate](#comminicate)
  - [Update log](#update-log)
    - [Second version](#second-version)
    - [First version](#first-version)
  - [Stargazers over time](#stargazers-over-time)

## items

- key contents

[Development and compilation instructions](#development-and-compilation-instructions)

[Plug-in module development instructions](#plug-in-module-development-instructions)

[Investigation and Analysis Function Description](./investigation/doc/README.md)

- slides

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## Function

The initial version mainly implements basic functions and overall processes, mainly including the following three types of functions:

1. Threat warehouse:

Used to store lists of traffic packets, payload files, and webshell files;

2. Risk detection:

Including traffic packet detection, HTTP deep analysis, SQLi detection, XSS detection and other detection items;

3. Auxiliary tools:

Including jq, deserialization analysis, data encryption and decryption and other processing tools;

4. Investigation and analysis capabilities

Using jupyter-based capabilities, you can write python scripts for analysis;

## screenshot of functional interface

- web server

<img width="1667" alt="image" src="https://user-images.githubusercontent.com/26109420/201511711-b395343b-e403-468e-9534-29abb1993247.png">

<img width="1679" alt="image" src="https://user-images.githubusercontent.com/26109420/201511731-01943065-a9ac-46b0-96ce-f8626f1a231f.png">

<img width="1671" alt="image" src="https://user-images.githubusercontent.com/26109420/201511741-4ba91fd4-0890-44b5-a069-1660f1d5cd81.png">

- juyter analyse

![analyse](./investigation/doc/Snipaste_2024-07-03_19-18-35.jpg)

## Get started

- Download

[Go to releases to download](https://github.com/Martin2877/btab/releases)

- Configuration

1. Requires tshark dependency, specify the tshark path in the `config.yaml` file, as follows:

```
pcapAnalyseConfig:
# tsharkPath: tshark # unix environment
tsharkPath: C:\Program Files\Wireshark\tshark.exe # win environment
```

2. (Optional) Java environment, some functions require the system to have a Java environment.

3. (Optional) Use jupyter notebook related dependencies

```bash
pip install jupyterlab
pip install grpcio-tools
```

- Execute

Double-click to execute. After startup, visit the local port 8001: http://localhost:8001

## Development and compilation instructions

### Front-end development

- Install dependencies

```bash
cd frontend

yarn install

```

- Run

```bash
yarn dev
```

- Packaging

```bash
yarn build
```

- Embed the front-end into the back-end

You need to copy the `./frontend/dist/` directory to `./backend/web/dist`, and then execute it under `./backend/` to package the front-end into a go file

```bash
go-bindata-assetfs -o web/bindata.go -pkg web web/dist/...
```

### Back-end development

- Install modules

```bash
cd ./backend
go mod tidy
go mod vendor
```

- Packaging

```bash
cd ./backend
go mod tidy
go mod vendor
go build
```

## Plug-in module development instructions

Using standard interfaces to implement unified plug-in module specifications, it is convenient to add new plug-in modules in the future. There are currently three modules, `jq`, `pcap`, and `SerializationDumper`. As long as there are new scenarios, they can be added.

In addition, these plug-ins can be called by the engine and used as analysis tools in the investigation and analysis process. In theory, the capabilities can be expanded infinitely.

For detailed code, see [plugin](./backend/engine/plugin/)

### Plug-in structure interface

```go
type Plugin interface {
   Init() // Initialization
   Set(key string, value interface{}) // Set the variables required by the plug-in
   Check() error // Check the value of the set variable
   Exec() error // Execute this plug-in
   GetState() int // Get the plug-in task progress
   GetFinalStatus() int // Get the final result
   GetResult() string // Get the output result
}
```

## technology stack

| Modules | Technology | Remarks |
| ----- | ----- | ----- |
| front-end framework | vue | |
| Front-end UI framework | naive ui | |
| backend language | golang | |
| Backend Web | gin | |
| Traffic packet detection logic | python | grpc / jupyter |
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

## Update log

### v0.5.x

The first version implements the general framework, but in order to achieve no dependency, the overall packaging is difficult, the volume is large, and the expansion capability is insufficient. The second version needs to be optimized. The analysis capability is increased through DSL syntax and python jupyter, and the expansion capability is achieved through grpc.

- [x] Plug-in module
- [x] General joint debugging engine to achieve multi-module serial processing
- [x] DSL syntax query function
- [x] Jupyter traffic packet analysis function
- [x] grpc implementation

### v0.3.x

- [x] Basic framework implementation

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Martin2877/btab.svg)](https://starchart.cc/Martin2877/btab)
