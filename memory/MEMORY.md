# Grok-Register Memory

## Standing rules (user)

- 每次任务完成后必须：
  1. `git commit` + `git push origin main`（代码/配置/文档改动）
  2. 把结论写入本文件 `memory/MEMORY.md`（小而准，禁止密钥/账号密码）
- 本地备份目录 `BK/`、研究笔记 `焚绝/` 已进 `.gitignore`，不要提交。
- Docker Compose **服务名是 `grok`**，容器名才是 `grok-reg`：
  - `docker compose build grok`
  - `docker compose up -d grok`
  - `docker exec grok-reg grok ...`

## CPA 入库（当前正确路径）

- **默认自动入库**（用户要的）：
  1. 注册拿 SSO
  2. 本机 device OAuth（SSO 自动确认）换 access/refresh
  3. 写本地 `CPA/*.json`
  4. `CPA_UPLOAD_ENABLED=1` 时 **同步** 上传 Management `/auth-files`
  5. 上传成功才计 `CPA 已入库`（计入 `-t`）
- **不要**默认走 CPA `/xai-auth-url` 人工链接；那条链路只能等人点，不能全自动。
- CPA 侧自动 confirm device code 曾出现 `invalid_grant: Access denied`，已放弃作为默认路径。
- 可选人工模式：`CPA_DEVICE_AUTH_MODE=manual`（一般不需要）。
- 相关配置：
  - `CPA_UPLOAD_ENABLED=1`
  - `CPA_MANAGEMENT_BASE=.../v0/management`
  - `CPA_MANAGEMENT_KEY=...`
  - `CPA_DEVICE_AUTH_MODE=`（空 = 自动）

## Recent commits

- `8bd3ae6` restore automatic CPA入库 via local OAuth + /auth-files upload
- `b3d69a7` (历史) manual device auth 实验；已被自动路径取代为默认
- `9169ada` `.gitignore` 忽略 `BK/` 与 `焚绝/`

## Deploy checklist (宝塔)

```bash
cd /www/server/panel/data/compose/grok-register
git pull origin main
# 确认 config：CPA_UPLOAD_ENABLED=1，KEY/BASE 正确，CPA_DEVICE_AUTH_MODE 为空
docker exec grok-reg grok stop || true
docker compose build grok --no-cache
docker compose up -d grok
docker exec -it grok-reg grok start -t 1 --thread 1
docker exec -it grok-reg grok logs -f
```

成功日志应含：
- `CPA auto 入库 enabled ... (local OAuth → /auth-files upload)`
- `OAuth ok ...`
- `[cpa] 开始上传 ...`
- `CPA 已入库 #1/1 ...`

## Notes

- 本文件是项目长期记忆入口；改代码/配置后默认追加短记录。
- 不记录密钥、token、密码、隐私数据。

## Log

- [2026-07-27] 建立 `memory/MEMORY.md`；确认自动 CPA 入库为默认；`.gitignore` 已忽略 BK/焚绝；收尾流程=提交仓+写本文件。