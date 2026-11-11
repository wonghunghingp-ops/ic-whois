# 01. ICP 数据收集清洗与单线程 Linux WHOIS 核验核心经验总结

本文档沉淀了项目多轮省份批次扫描、数据回填以及单线程 Linux 环境稳定运行的实战经验，所有规则已直接固化进 [`common.py`](../agent_workflow/common.py)、[`icp_cleaner.py`](../agent_workflow/icp_cleaner.py) 与 [`whois_single.py`](../agent_workflow/whois_single.py)。

---

## 一、 ICP 备案数据处理的核心经验

### 1. 数据卫生底线：严禁垃圾域名混入下游
- **必须过滤纯 IP 地址**：快照导出常见服务器 IP（如 `101.227.52.182` 或 `[::1]`），需在清洗期直接剔除，禁止送入 WHOIS。
- **必须过滤汉字及非 ASCII 域名**：如 `中文域名测试.中国`，默认仅保留纯英数合规主机名；同时默认剔除 `xn--` Punycode（可通过参数按需放行）。
- **URL 与子域名折叠**：原始表格常混杂 `https://www.sub.example.cn/index.html`、`example.com:8080/login` 等脏格式。
  - `normalize_host` 先剥离协议、账号口令、端口、路径、查询串、`www.` 与尾部点号；
  - `to_registrable_domain` 结合完整的中国二级省域后缀（如 `.com.cn`、`.gd.cn`、`.jx.cn` 等）与常见国际二级后缀（`.co.uk`、`.com.hk`、`.co.jp` 等）折叠为可查询 WHOIS 的**注册根域名**（如 `example.cn`）。因为直接拿 `sub.example.cn` 去查 Verisign RDAP 或 CNNIC 43 端口会返回“无记录”，极易酿成**子域名假未注册（假 404）**。

### 2. 分清 `666`（有网站分号）与 `665`（纯主体/无分号）
- **`666` 记录**：`service_license` 带有明确网站分号（如 `沪ICP备2020000001号-1`、`B2-20090007-1`），代表该主体下真实挂载了网站域名，WHOIS 命中过期或临期资产的概率远高于无分号记录。
- **`665` 记录**：仅有 `main_license` 而无 `service_license`（或缺少 `-N` 网站分号）。实战中这类记录大量来自 **APP、微信小程序或已注销空壳主体**。
- **关键避坑**：
  - `clean-icp` 自动计算 `has_service_subid`（`1` vs `0`）并严格把 `666` 排在前面优先处理；传 `--require-666` 可只导出 `666` 子集。
  - 需特别注意避免把 `B2-20090007` 中的年份数字误识别成 `-N` 分号。
  - **严禁盲猜**：不得自动把 `665` 主备案号硬拼 `-1` 或依据主办单位名称去无边界爬取关联主体。

### 3. 省份与日期格式的规范化与去重
- **省份兜底推断**：当源表省份列为空或填写 `"未知"`、`"-"` 时，`normalize_province()` 会提取主体备案号/网站备案号首字（如 `湘ICP备2021000002号` -> `湖南省`、`沪` -> `上海市`）自动补全全部 34 个省级行政区标准名称。
- **严格日期合规**：`Domain Hub /v1/intake` 严格要求 `filed_on`、`updated_on` 为 `YYYY-MM-DD`。清洗阶段会将 `2021/03/15`、`2026-01-10 08:30:00` 自动规范化为 `YYYY-MM-DD`，无法解析时置空而不导致整行被拒绝。
- **字符编码兼容**：国内历史导出 CSV 常混用 GB18030 / GBK / UTF-8-SIG BOM，必须按 `utf-8-sig -> utf-8 -> gb18030 -> gbk` 顺序自动解码，导出最终分析 CSV 时统一写 **UTF-8 with BOM (`utf-8-sig` + `\r\n`)**，防止 Excel 打开中文乱码。
- **`fact_hash` 与去重口径**：通过与 Hub 服务端 `icpFactHash` 完全一致的 SHA-256 算法（基于 `[domain, subject, main_license, service_license, filed_on, updated_on]` 紧凑 JSON）在本地先去重再上传，既减少带宽又为每条记录生成幂等 `event_id`。

### 4. 可选 LLM 联网补充的约束经验
- 仅在缺失官方备案线索且用户自行配置合规 OpenAI 兼容联网查询 API（`ICP_LLM_API_URL` / `ICP_LLM_API_KEY`）时使用 `enrich-icp-llm`。
- **单线程小批原则**：每次请求控制在 **1~3 个域名**（默认 2），过大并发与大批量会直接触发搜索工具超时或截断。
- **清理引文噪声**：返回文本必须剥离 `[citation:N]` 与 Markdown 代码块围栏，且明确标注为非官方来源 `llm_web_search`，不得冒充 MIIT 官方证据。

---

## 二、 单线程 Linux WHOIS / RDAP 核验的核心经验

针对单机 Agent 的 Linux 环境，**不采用多线程并发风暴、不依赖多台 VPS 代理池轮询**，稳定性来自协议精准分流、礼貌节拍控制和严格的抗误报逻辑。

### 1. 官方协议分流规则（已内置路由）

| 后缀 | 指定 `provider` | 权威查询入口 | 协议细节与注意事项 |
| :--- | :--- | :--- | :--- |
| `.com` / `.net` | `verisign_rdap` | `https://rdap.verisign.com/{tld}/v1/domain/{domain}` | HTTPS JSON；HTTP 200 或真实 JSON 404 |
| `.cc` | `verisign_rdap` | `https://tld-rdap.verisign.com/cc/v1/domain/{domain}` | **历史踩坑点**：`.cc` 必须走 `tld-rdap.verisign.com`，走 `rdap.verisign.com/cc/...` 会报错 |
| `*.cn` | `cnnic_whois` | `whois.cnnic.cn:43` | TCP 43 端口明文；**Evidence 必须省略 `http_status`**，且两侧必须一致为无值 |
| 其他通用后缀 | `registry_rdap` | IANA `dns.json` 本地 24h 缓存表 + 内置后缀表 | 例如 `.org`/`.io`/`.co.uk`/`.xyz` 等优先走官方 RDAP |
| 无 RDAP 的小众后缀 | `registry_whois` | `whois.iana.org:43` 提取 `refer:` 后连注册局 43 端口 | 兜底保证小众后缀可查询 |

### 2. 防止“假 404 误报”的铁律
域名的“未注册 (`not_found`)”属于高敏感状态，绝不能因为网络抖动或被限流而误报：
1. **Verisign / Registry RDAP**：仅当 HTTP 状态码为 `404` **且** 响应体是合法 JSON **且** 包含 `"errorCode": 404`（或明确 `"Not Found"` JSON 对象）时才判定 `not_found`。若 CDN 返回 HTML 404 页面或空响应，一律降级为 `unavailable` 触发重试。
2. **CNNIC 43 端口**：先检查限流/封禁关键词（`too many`, `rate limit`, `exceeded`, `try again later`, `quota`, `access denied`, `blocked`, `server is busy` 等）——**只要命中限流字样直接判 `unavailable` 退避重试**；随后仅当正文不含 `Domain Name:` 且明确出现 `"no matching record"` / `"the domain you requested is not exist"` / `"does not exist"` 时才判 `not_found`。对于 `"can not be registered"` 保留域名也不会误标为可注册。
3. **超时/断流/429/403/5xx**：全部记录为 `unavailable`（供断点重试），**永远禁止转写成 `not_found`**。

### 3. CNNIC 缺失时区与多到期时间冲突处理
- **CNNIC 无时区问题**：CNNIC 43 端口经常返回 `Expiration Time: 2026-12-01 23:59:59`（无 `Z` 或 `+08:00` 后缀的北京时间）。
  - 本工具本地解析会按 `Asia/Shanghai (+08:00)` 正确换算成标准 UTC 毫秒格式，同时保留 `raw_expiration_date` 与 `expiration_timezone_explicit: false`；
  - 上传到 Domain Hub 时的 JSONL 原件必须保留**逐字节原样原文 (`response_text`)**，服务端会按 `official_response_missing_timezone` 规范入库并同样纳入官方证据计数与工单完成认定。
- **RDAP 冲突时间**：当个别 RDAP 返回多个不一致的 `expiration` 事件时间时，`parse_rdap_json` 会标记 `conflicting_expirations: true` 并将状态降为 `partial`，避免盲目覆盖。

### 4. 单线程 Linux 节拍、WAF 防护与断点设计
- **自定义 `User-Agent` 必填**：Domain Hub 边缘防护与部分 RDAP 节点会直接拦截 Python 默认 `Python-urllib/3.x`（返回 403）。`hub_client.py` 与 `whois_single.py` 所有请求均强制携带明确的 `User-Agent`。
- **单线程礼貌延迟**：
  - Verisign / Registry RDAP 每次间隔随机 `0.7 ~ 1.2s`
  - CNNIC 43 端口每次间隔随机 `1.4 ~ 2.2s`
  - 若遇 429 / 临时限流，启动退避阶梯 `5s -> 15s -> 35s -> 60s`（加随机抖动），并略微抬高本轮会话后续冷却时间；若需要出口 IP 切换，支持通过环境变量或 `--socks5-proxy` 指定**单个** SOCKS5 代理（由代理远端解析 DNS），但默认推荐直接单机直连。
- **Hub 检索冷缓存超时**：对全库 50 万级域名的 `evidence_scope: "all"` 搜索，小内存节点冷查询耗时可达 `3~16s/页`，因此 Hub HTTP 超时默认设为 **`60s`**。
- **SQLite WAL + `SIGINT`/`SIGTERM` 安全退出**：每核验完 1 个域名立即写入 SQLite WAL 断点库（默认有效期 `24h`，可 `--force` 强制重查）；按 `Ctrl+C` 或收到 Linux `SIGTERM` 时会等当前单个请求落盘完毕再生成 JSONL/CSV，支持随时断点恢复续跑。
- **不可购买后缀排除与紧急度排序**：导出 CSV 默认剔除 `gov.cn`/`edu.cn` 等受限后缀，并严格按照**上海自然日 (`UTC+8`)** 归类排序：`已过期/pendingDelete/redemption (urgency=0)` -> `今日到期 (0天, urgency=1)` -> `明日到期 (1天, urgency=2)` -> `30天内 (2~30天, urgency=3)`。
