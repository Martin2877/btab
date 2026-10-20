# btab

![Github Release](https://img.shields.io/github/v/release/Martin2877/btab.svg)
![Github Downloads](https://img.shields.io/github/downloads/martin2877/btab/total)

[BTAB (Blue Team Analyisis Box)](https://github.com/Martin2877/btab) is a blue team analysis toolbox focused on attack signature analysis and alert triage. It assists security operators with pcap analysis, HTTP message inspection, web access log analysis, attack payload identification, encrypted traffic decryption and more. The current version ships with a built-in nuclei vulnerability rule engine, a regex-based URL rule engine and an extensible JavaScript behavior-detection script engine. It can be used via the Web UI, the command line, or directly inside Wireshark through the bundled `btab.lua` plugin.

<a>English</a> - 
<a href="./README_zh-cn.md">简体中文</a>

## contents

- [btab](#btab)
  - [contents](#contents)
  - [items](#items)
  - [Function](#function)
  - [screenshot of functional interface](#screenshot-of-functional-interface)
  - [Get started](#get-started)
    - [Command line usage](#command-line-usage)
  - [Development and compilation instructions](#development-and-compilation-instructions)
    - [Front-end development](#front-end-development)
    - [Back-end development](#back-end-development)
  - [Plug-in module development instructions](#plug-in-module-development-instructions)
    - [Plug-in structure interface](#plug-in-structure-interface)
  - [technology stack](#technology-stack)
  - [Q\&A](#qa)
  - [comminicate](#comminicate)
  - [Update log](#update-log)
    - [v1.1.0](#v110)
    - [v0.5.x](#v05x)
    - [v0.3.x](#v03x)
  - [Stargazers over time](#stargazers-over-time)

## items

- key contents

[Development and compilation instructions](#development-and-compilation-instructions)

[Plug-in module development instructions](#plug-in-module-development-instructions)

[Investigation and Analysis Function Description](./investigation/doc/README.md)

[Wireshark Plugin (btab.lua) Usage](./wireshark/README.md)

- slides

[btab蓝队分析工具箱-ali0th-v1.0.pdf](btab蓝队分析工具箱-ali0th-v1.0.pdf)

## Function

The current version includes the following seven functional modules:

### 1. One-click analysis

A unified analysis entry: paste any payload text, upload a pcap file or a web access log (nginx/apache combined/common format). The sample is automatically archived into the threat warehouse, and applicable detection methods (HTTP session reconstruction, behavior detection scripts, nuclei rules, URL rules, cross-session correlation, etc.) are orchestrated and executed asynchronously, producing a structured analysis report (attack chain graph, hit details, per-step timing).

### 2. Threat warehouse

Unified storage and management of pcap files, payloads, webshells, web access logs and nuclei templates. Everything is stored in SQLite, deduplicated by sha1, and file contents can be viewed online. The package ships with built-in example samples (webshell / payload dictionary / access log) and the official nuclei-templates set, imported once on first startup.

### 3. Risk detection

- **Pcap detection**: extracts sessions with tshark and runs multiple detection strategies in parallel (JS behavior scripts, nuclei templates, local engines such as SQLi/XSS), as async tasks with real-time progress and hit details;
- **HTTP deep analysis**: accepts raw HTTP messages, Wireshark httpstream dumps or hex input, automatically splits multiple request/response pairs, extracts parameter features and identifies risks; it can also synthesize the traffic back into a downloadable pcap file;
- **Payload detection**: paste any payload and let the system classify the attack type, then run the SQLi, XSS, Webshell, Bash command, Log4j2 JNDI and nuclei signature engines with per-engine details.

### 4. Detection engines

- **Vulnerability detection engine**: online management of nuclei YAML templates — single file upload, zip package import (with automatic recognition of dictionaries, workflows and other resources), online editing and validation, batch enable/disable, and rule debugging;
- **Behavior detection engine**: detection logic written in JavaScript (executed by the embedded goja runtime). 21 built-in detection strategies — 16 for pcap traffic (antsword malicious upload, CORS misconfiguration, CVE-2020-1957, CVE-2022-21907, directory brute force, FTP brute force, HTTP chunked transfer, ICMP scan, log4j attack, SYN port scan, RDP/3389 communication, shiro550, source code/backup leak, SQL injection, Telnet weak password, webshell upload) and 5 for web access logs (directory brute force, post-scan admin login, injection payload spraying, sensitive file probing, suspicious script/webshell access). Custom scripts can be uploaded to override built-ins, with online debugging support;
- **URL detection engine**: regex rules matched against URL / User-Agent / Referer with five severity levels. Ships with a built-in ruleset derived from webloghunter (attack signatures, scanner UA detection, misc), and supports online editing, regex validation, batch enable/disable, rules.yaml import and single-value debugging.

### 5. Auxiliary tools

jq, SerializationDumper (Java deserialization dump), Behinder traffic decryption, Godzilla traffic decryption, Shiro rememberMe key detection (with built-in common-key dictionary), Log4j2 lookup parsing and payload variant generation, and an embedded CyberChef.

### 6. Investigation and analysis capabilities

Jupyter + gRPC based extensibility: write python scripts that call engine plugins for analysis — the capabilities can be expanded infinitely (see [Investigation and Analysis Function Description](./investigation/doc/README.md)).

### 7. Wireshark integration

`wireshark/btab.lua` is a Wireshark Lua plugin that calls the BTAB backend over REST API, adding the security detection capabilities Wireshark lacks: per-packet right-click menus (attack detection, HTTP deep parse, payload decoding), whole-capture HTTP flow triage, session-level nuclei detection with cross-frame webshell decryption (Behinder/Antsword/Chopper), and alert annotations written to the packet details tree, Expert Information and `btab.*` display filters. See [Wireshark Plugin Usage](./wireshark/README.md).

## screenshot of functional interface

- One-click analysis (unified entry / analysis report / task list)

![analyze home](./docs/screenshots/analyze-home.png)

![analysis report](./docs/screenshots/analyze-report.png)

![analysis tasks](./docs/screenshots/analyze-tasks.png)

- Risk detection (pcap detection / HTTP deep analysis / payload detection)

![pcap detection](./docs/screenshots/risk-paonline.png)

![detection result](./docs/screenshots/risk-paonline-result.png)

![http deep analysis](./docs/screenshots/risk-http-parse.png)

![payload detection](./docs/screenshots/risk-payload.png)

- Detection engines (vulnerability engine / behavior engine)

![vulnerability engine overview](./docs/screenshots/engine-vuln.png)

![nuclei templates](./docs/screenshots/engine-vuln-templates.png)

![behavior engine overview](./docs/screenshots/engine-logic.png)

![behavior detection scripts](./docs/screenshots/engine-logic-scripts.png)

- Threat warehouse and auxiliary tools

![pcap list](./docs/screenshots/stores-pcap.png)

![behinder decryption](./docs/screenshots/tools-behinder.png)

![shiro key detection](./docs/screenshots/tools-shiro.png)

![jq](./docs/screenshots/tools-jq.png)

- jupyter analyse

![analyse](./investigation/doc/Snipaste_2024-07-03_19-18-35.jpg)

## Get started

- Download

[Go to releases to download](https://github.com/Martin2877/btab/releases)

- Configuration

1. Requires tshark dependency, specify the tshark path in the `config.yaml` file, as follows (it can also be edited online in "System Settings", where common install paths are auto-detected):

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

4. (Optional) Wireshark integration: copy `wireshark/btab.lua` into the Wireshark personal plugins directory to analyze captures directly from Wireshark (requires Wireshark >= 4.2). See [wireshark/README.md](./wireshark/README.md).

- Execute

Double-click to execute. After startup, visit the local port 8001: http://localhost:8001

### Command line usage

```shell
# run as a web server (default port 8001)
btab server
btab server -p 8001      # specify the port
btab server --grpc       # grpc only mode

# execute a detection engine
## list the engine names
btab engine -l
## pcap parsing
btab engine -e pcap -f file.pcap

# workflow
## list the workflow templates
btab wf -l
## pcap check workflow (extract HTTP sessions and run SQLi detection on each)
btab wf -t pcapcheck -f xxx.pcap
btab wf -t pc -f xxx.pcap        # pc is an alias of pcapcheck
## SQL injection detection
btab wf -t sqli -c "' and 1+1"
```

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

The front-end is embedded into the binary via `go:embed`. Copy the `./frontend/dist/` directory to `./backend/web/dist`, then run `go build` under `./backend/`.

Or simply use the one-step packaging script (which builds the front-end, syncs dist and runs go build automatically):

```bash
bash backend/pack.sh           # dev mode: incremental build, output to release/btab_dev/
bash backend/pack.sh release   # full build, output to release/btab_windows_amd64.zip
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
go build
```

## Plug-in module development instructions

Using standard interfaces to implement unified plug-in module specifications, it is convenient to add new plug-in modules in the future. There are currently modules such as `jq`, `pcap` and `SerializationDumper`. As long as there are new scenarios, they can be added.

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
| front-end framework | vue3 + vite | |
| Front-end UI framework | naive ui | |
| backend language | golang | |
| Backend Web | gin | |
| Data storage | gorm + sqlite | samples, tasks, templates and scripts are all stored in DB |
| Vulnerability detection engine | nuclei v3 | load YAML templates to identify attacks in pcap / HTTP messages |
| Behavior detection engine | goja | detection scripts written in JavaScript, extensible online |
| URL detection engine | go regexp | built-in webloghunter-derived ruleset, managed online |
| Traffic packet parsing | tshark + gopacket | tshark path required |
| Wireshark integration | Lua plugin + REST API | `wireshark/btab.lua`, requires Wireshark >= 4.2 |
| Investigation and analysis | python | grpc / jupyter |

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

### v1.1.0

A major version overhaul: the UI is rebuilt and detection evolves from "single-purpose tools" to an "engine + strategy + task" system.

- [x] Unified analysis entry: paste a payload, upload a pcap or a web access log for one-click analysis; samples are auto-archived and a structured report is produced (attack chain, hit details)
- [x] Load nuclei YAML templates to identify attacks in pcap; templates can be managed, debugged, batch enabled/disabled online, with zip template package import; the official nuclei-templates ship built-in
- [x] JavaScript behavior detection engine (goja runtime): 21 built-in strategies covering both pcap traffic and web access logs; custom scripts can be uploaded for extension, with online debugging
- [x] URL rule detection engine: regex rules over URL / UA / Referer with a built-in webloghunter-derived ruleset; online editing, validation, batch enable/disable and rules.yaml import
- [x] Web access log analysis: upload nginx/apache logs to the threat warehouse, run URL rules and log behavior strategies to surface dir brute force, injection spraying, webshell access and more
- [x] Wireshark Lua plugin (`btab.lua`): packet context menus and whole-capture triage, session-level nuclei detection, cross-frame webshell decryption, Expert Information / `btab.*` alert annotations
- [x] Strategy-based pcap detection: parallel strategies, real-time progress, hit details
- [x] HTTP deep analysis: raw / httpstream / hex input, auto-splitting of request/response pairs with risk identification, and pcap synthesis for export
- [x] Smart payload identification: auto-classification with per-engine results from SQLi / XSS / Webshell / Bash / Log4j2 / nuclei signatures
- [x] Auxiliary tools: Behinder / Godzilla traffic decryption, Shiro key detection, Log4j2 parsing & generation, embedded CyberChef
- [x] Samples, templates and tasks are all stored in the database (sqlite) instead of files
- [x] CLI version: `server` / `engine` / `workflow` subcommands
- [x] Online system settings: view & edit configuration, tshark auto-detection

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
