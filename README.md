# Domain Hub Single-Threaded Linux Agent Workflow (`ic-whois`)

一套面向 **Linux Agent 单线程运行环境** 的 ICP 备案清洗、官方 WHOIS/RDAP 核验与 Domain Hub 数据回传标准工具链。

- **零第三方依赖**：仅依赖 Python 3.9+ 标准库（无需 `pip install`、无需虚拟环境编译）
- **严格单线程（非多代理池）**：全链路顺序执行，内置礼貌随机抖动、限流自适应退避、SQLite WAL 断点续传、`SIGINT`/`SIGTERM` 安全落盘
- **双向严格对齐 Domain Hub v2**：原生适配匿名入口 `POST /v1/intake`（方案 A）与授权证据归档通道 `batches -> files -> PUT -> observations:batch`（方案 B）
- **严格防误报**：Verisign 404 校验 `errorCode=404`，CNNIC 43 端口校验精确未注册短语且隔离限流字样，超时/限流/空包绝不误判 `not_found`
- **合规有序归档**：支持一键拷贝原始资料至 `result/raw_inputs/`，并按过期与删除紧迫程度升序导出 UTF-8 BOM Excel 友好 CSV

---

## 目录结构

```text
agent-workflow/
├── README.md                              # 本说明文档
├── run.sh                                 # Linux 单线程 CLI 启动脚本 (chmod +x)
├── .env.example                           # 环境变量模板（复制为 .env 使用，严禁提交真实密钥）
├── .gitignore                             # 忽略 .env / runtime_state / result / *.db*
├── agent_workflow/
│   ├── __init__.py                        # 版本信息
│   ├── common.py                          # 域名/省份/时间归一化、icpFactHash、lifecycle、CSV 导出
│   ├── hub_client.py                      # Hub HTTP/SOCKS5 客户端、SQLite Outbox、方案 A/B 上传与游标查询
│   ├── icp_cleaner.py                     # 多编码 ICP 清洗、666/665 分级、去重与可选 LLM 补充
│   ├── whois_single.py                    # 单线程官方 RDAP/CNNIC 43 核验引擎与 SQLite WAL 断点续传
│   └── cli.py                             # 统一 CLI 子命令入口
├── docs/
│   ├── 01_ICP_AND_WHOIS_EXPERIENCE.md     # 查 ICP 与单线程 WHOIS 核心工程经验总结
│   ├── 02_UPLOAD_STANDARD_AND_API.md      # Domain Hub v2 上传接口规范、v1->v2 差异、去重与错误处理
│   └── 03_AGENT_OPERATIONS_SOP.md         # Linux Agent 端到端实操手册（可直接复制执行）
├── examples/
│   ├── credentials.example.json           # Collector 凭证示例
│   ├── sample_icp.csv                     # 含 URL、666/665、未知省份、IP、中文域名的测试样例
│   └── sample_domains.txt                 # WHOIS 测试域名样例
└── tests/
    └── test_workflow.py                   # 离线单测与本地 Mock Server 端到端集成测试
```

---

## 快速开始（Linux 环境）

### 1. 准备配置

```bash
cp .env.example .env
# 按需编辑 .env：填入 DOMAIN_HUB_URL 与 DOMAIN_HUB_TOKEN（若仅用匿名通道可留空 Token）
./run.sh verify
```

### 2. 标准执行流程示例

```bash
# ① 清洗省份备案快照，过滤纯 IP 与汉字域名，优先排序 666 网站分号记录，并同步归档原件
./run.sh clean-icp \
  --input examples/sample_icp.csv \
  --archive-raw --seq 01 --province 样例省份 --desc 备案快照

# ② 上传清洗后的 ICP 数据至 Domain Hub（有 Token 自动走授权归档，无 Token 自动走匿名 /v1/intake）
./run.sh ingest-icp \
  --input examples/sample_icp.csv \
  --province 样例省份 --desc "样例批次ICP导入"

# ③ 从 Domain Hub 游标分页拉取缺失或过期太久的待核验域名（支持 >5,000 全量分页）
./run.sh pull-missing \
  --coverage missing_official \
  --tld com,net,cn,cc \
  --limit 2000 \
  --output runtime_state/missing_domains.txt

# ④ 单线程顺序查询官方 Verisign RDAP / CNNIC 43 / IANA RDAP，支持 Ctrl+C 断点续传
./run.sh probe-whois \
  --input runtime_state/cleaned_domains.txt \
  --output-dir runtime_state/whois_run

# ⑤ 上传 WHOIS 原件证据与解析观测至 Domain Hub（自动按 <900 KiB 切片对齐 JSONL）
./run.sh sync-whois --topic "样例省份_WHOIS核验"

# ⑥ 导出符合 GEMINI.md 紧迫排序的 UTF-8 BOM 结果表
./run.sh export-csv \
  --icp-file examples/sample_icp.csv \
  --output result/01_样例省份_过期与临期资产_有序结果.csv
```

---

## 子命令总览

| 子命令 | 用途说明 |
| :--- | :--- |
| `verify` | 检测 `DOMAIN_HUB_URL` 连通性、延迟及 Token 节点权限范围 |
| `clean-icp` | 清洗 CSV/TSV/TXT/JSON/JSONL，归一化域名/省份/日期，`666` 优先排序 |
| `ingest-icp` | 一键清洗并上传 ICP 数据至 Hub（支持 `authorized` / `intake` / `auto`） |
| `pull-missing` | 通过 `POST /v1/candidates/search` 游标拉取缺失官方 WHOIS 或需刷新域名 |
| `probe-whois` | Linux 单线程顺序核验官方 RDAP / CNNIC 43 端口，结果写入 SQLite WAL 与 JSONL |
| `sync-whois` | 上传断点库或 JSONL 中的 WHOIS 原件证据与观测记录，回执成功后自动标记已同步 |
| `job-worker` | 单线程循环领取 `POST /v1/jobs:claim` 队列任务并回传原件观测回执 |
| `export-csv` | 从本地结果或 Hub 拉取并导出按到期紧迫度升序排列的 UTF-8 BOM CSV |
| `enrich-icp-llm` | （可选）使用用户配置的 OpenAI 兼容联网查询 API 小批（1~3 条）补充备案线索 |

---

## 详细文档导航

1. [ICP 清洗与单线程 WHOIS 核心工程经验总结](docs/01_ICP_AND_WHOIS_EXPERIENCE.md)
2. [Domain Hub v2 上传接口标准、版本差异与错误处理矩阵](docs/02_UPLOAD_STANDARD_AND_API.md)
3. [Linux Agent 标准化作业指导书 (SOP)](docs/03_AGENT_OPERATIONS_SOP.md)

---

## 安全与仓库红线

- 本仓库面向公共环境设计，**严禁将 `.env`、Collector Token、代理账号密码、服务器内网地址或原始隐私数据提交进 Git**。
- 所有工具均只对接公开合规协议（Verisign 官方 RDAP、CNNIC 官方 43 端口、IANA 官方引导表、Domain Hub 标准 API 及用户自配 OpenAI 兼容接口），不包含任何验证码识别或绕过逻辑。
