# Strix Lite 路由速查表

## 先用工具还是先打漏洞？

### 先用工具类 skill
如果你还没搞清楚：
- 站点活不活
- 有哪些路径
- 有哪些参数
- JS 里还有没有隐藏接口

先用：
- `strix-httpx`
- `strix-katana`
- `strix-ffuf`
- `strix-nuclei`

### 先用漏洞专项 skill
如果你已经有明确怀疑：
- 参数可能 SQLi -> `strix-sql-injection` 或 `strix-sqlmap`
- 页面可注入脚本 -> `strix-xss`
- 服务端拉 URL -> `strix-ssrf`
- 能执行系统命令 / 模板注入 -> `strix-rce`
- token / JWT 可疑 -> `strix-authentication-jwt`
- 越权读别人资源 -> `strix-idor`
- 上传点可疑 -> `strix-insecure-file-uploads`
- 报错 / debug / metadata 暴露 -> `strix-information-disclosure`

## 新手默认组合

- 活性探测：`strix-httpx`
- 抓路由：`strix-katana`
- 跑字典：`strix-ffuf`
- 快扫：`strix-nuclei`
- SQL 验证：`strix-sqlmap`
