# btab frontend

BTAB Web 前端，基于 [naive-ui-admin](https://github.com/jekip/naive-ui-admin) 二次开发：Vue3 + Vite + TypeScript + Naive UI + Pinia + vue-i18n（中/英文）。

构建产物经 `go:embed` 内嵌进后端二进制，用户无需单独部署前端。

## 目录结构

```
frontend/src/
├── api/             # 后端接口封装（analyze / engine / risk / stores / system ...）
├── assets/          # 静态资源（含内嵌 CyberChef，打包到 dist/assets/cyberchef）
├── components/      # 通用组件（CodeView 等）
├── layout/          # 布局（Menu / Header / TagsView）
├── locales/         # i18n：zh-CN / en-US
├── router/modules/  # 菜单路由：analyze / risk / engine / stores / tools / setting
├── store/           # Pinia
└── views/           # 页面
    ├── analyze/     # 一键分析（统一入口 / 任务列表 / 分析报告）
    ├── risk/        # 风险检测（paonline 流量包 / http_parse / payload）
    ├── engine/      # 检测引擎（vuln 漏洞 / logic 行为 / urlrule URL规则）
    ├── stores/      # 威胁仓库（pcap / payload / webshell / weblog / nuclei 模板）
    ├── tools/       # 辅助工具（jq / SerializationDumper / btt：冰蝎、哥斯拉、shiro、log4j2）
    └── setting/     # 系统设置（在线查看修改配置、tshark 自动探测）
```

## 开发

```bash
yarn install    # 或 npm install
yarn dev        # vite 开发服务器
yarn build      # 产物输出到 dist/
```

后端联调：先启动 `btab server`，vite 开发服务器将 `/api` 代理到 `vite.config.ts` 中配置的后端地址（默认 `http://localhost:6667`，可按需改为实际端口）。

## 打包进后端

不需要手动拷贝，统一用根目录一键脚本（自动执行 `npm run build` 并同步 `dist` → `backend/web/dist`，含 `web/cyberchef` → `dist/assets/cyberchef`）：

```bash
bash backend/pack.sh           # dev：release/btab_dev/
bash backend/pack.sh release   # 完整包
```

详见根目录 [AGENTS.md](../AGENTS.md) 与 [README](../README_zh-cn.md)。
