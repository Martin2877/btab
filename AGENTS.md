# BTAB

Go 后端（`backend/`，go:embed 内嵌前端）+ Vue3 前端（`frontend/`）。

## 打包

```bash
bash backend/pack.sh           # dev 模式（默认）：增量构建，输出 release/btab_dev/，直接运行其中的 btab.exe 检查
bash backend/pack.sh release   # 完整构建，输出 release/btab_windows_amd64.zip
bash backend/pack.sh dev --skip-frontend   # 跳过前端构建（仅改了 Go 代码时用）
```

流程：前端 `npm run build` → 同步 `frontend/dist` 到 `backend/web/dist`（含 `web/cyberchef` → `dist/assets/cyberchef`）→ `go build -o btab.exe` → 组装 `btab.exe + config.yaml + btab.sqlite + README.md + stores/ + wireshark/`。

`config.yaml` 中 `pcapAnalyseConfig.tsharkpath` 保留开发者本机路径供 dev 使用；release 打包时脚本按目标平台重写为系统默认路径（Windows `C:\Program Files\Wireshark\tshark.exe`、darwin `/Applications/Wireshark.app/...`、linux `/usr/bin/tshark`），运行时 `pkg/pcap.ResolveTsharkPath` 还会按 配置→TSHARK 环境变量→PATH/常见目录 回退探测。

注意：`backend/pack.bat` 已废弃——在 cmd 下解析异常，文件拷贝命令不会执行，请使用 `pack.sh`。

## 内置 nuclei 模板库更新

随包发布的 `backend/btab.sqlite` 内置官方 nuclei-templates。更新方式（在 `backend/` 下执行）：

```bash
go run ./tools/import_nuclei -dir ../tmp/nt/nuclei-templates-main
```

全量同步：目录树中的 yaml 经 `engine/vuln` 管线（解析元信息、按默认策略启用 http 模板）入库，并删除库中不存在于目录树的旧模板；随后执行 `bash backend/pack.sh dev` 重新打包。

## 内置示例样本

`backend/pkg/db/samples/` 中的文件经 `go:embed` 编译进二进制，启动时由 `pkg/db/stores_seed.go` 的 `SeedBuiltinSamples()` 一次性导入样本仓库（webshell / payload 表）。按 sha1 在 `nuclei_settings` 记 `builtin_sample:*` 标记，用户删除后不会回补。新增内置样本：把文件放入 `samples/` 并在 `builtinSamples` 列表登记。

## 工作流约定

- **每次代码优化/修改完成后，默认执行 `bash backend/pack.sh dev` 打包 Windows dev 版本**，供使用者在 `release/btab_dev/` 直接运行检查。
- 仅当改动涉及前端代码时脚本才会自动重建前端（按 `frontend/src` 与 `dist/index.html` 时间戳判断）。
