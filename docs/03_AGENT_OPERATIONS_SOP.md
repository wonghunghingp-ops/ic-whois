# 03. Linux Agent 单线程全流程实操手册 (SOP)

本手册面向在 Linux 主机上执行的自动化 Agent 或运维脚本，所有命令均为单线程顺序执行，可直接按场景复制运行。

---

## 阶段一：环境检查与初始化

```bash
# 1. 进入工作目录（或从 git clone 后的目录）
cd agent-workflow

# 2. 检查 Python 版本（要求 >= 3.9，纯标准库零 pip 安装）
python3 --version

# 3. 初始化配置文件
cp .env.example .env
# 编辑 .env 填入 DOMAIN_HUB_URL=https://hub.llmhubone.net 以及（可选）DOMAIN_HUB_TOKEN

# 4. 运行连通性与身份自检
./run.sh verify
```

> **预期结果**：
> - 若配置了 Token：打印 `Domain Hub 就绪检查通过` 以及 `Collector 身份认证通过: id=... scopes=... providers=...`，全量上传、游标检索、导出与抢单均可用。
> - 若未配置 Token：提示已就绪使用**免令牌全量批量上传通道**（`batches -> files -> PUT -> observations:batch`），可直接执行 `clean-icp`、`ingest-icp`、`probe-whois`、`sync-whois`；仅 `pull-missing` / `--from-hub` / `job-worker` 仍需 Token。

---

## 阶段二：处理本地新获取的 ICP 资料并入库

适用于每次从外部拿到新的省份备案 CSV/TXT/JSON 文件时（自动执行 `GEMINI.md` 归档铁律）：

```bash
# 第一步：本地清洗、规范化、666优先排序并同步备份原件到 result/raw_inputs/
./run.sh clean-icp \
  --input /path/to/province_raw.csv \
  --archive-raw \
  --seq 46 \
  --province 湖南省 \
  --desc 备案域名快照 \
  --output runtime_state/46_hunan_cleaned.jsonl \
  --domains-out runtime_state/46_hunan_domains.txt

# 如希望只提取高价值 666 网站分号记录，追加 --require-666

# 第二步：将清洗后 ICP 数据上传至 Domain Hub
# - 默认（--mode auto / batch）免 Token 也可走完整批次原件归档（batches -> files -> PUT -> observations:batch）
# - 若只想轻量入库不留原件文件，可显式指定 --mode intake（单批最多 800 条、无间隔延迟）
./run.sh ingest-icp \
  --input /path/to/province_raw.csv \
  --province 湖南省 \
  --desc "第46批湖南省ICP入库" \
  --source-kind miit_snapshot \
  --client-batch-ref "batch46_hunan_icp"
```

---

## 阶段三：从全库拉取缺口并单线程核验 WHOIS（推荐增量主循环）

无论是本地刚清洗出的 `46_hunan_domains.txt`，还是需要全库“拾遗补缺”，均按下面循环推进：

### A. 从 Domain Hub 游标拉取待核验/待刷新域名

```bash
# 拉取缺失官方 WHOIS 证据的域名（支持超过 5,000 条全量游标分页；设 --limit 0 代表全量拉取）
./run.sh pull-missing \
  --coverage missing_official \
  --evidence-scope all \
  --tld com,net,cn,cc \
  --has-service-subid true \
  --limit 5000 \
  --output runtime_state/missing_domains.txt
```

### B. Linux 单线程顺序核验 WHOIS/RDAP（支持断点续传）

```bash
# 默认直连运行：RDAP 0.7~1.2s/条，CNNIC 1.4~2.2s/条
# 如遇特殊内网需单节点代理，追加 --socks5-proxy socks5://user:pass@host:port
./run.sh probe-whois \
  --input runtime_state/missing_domains.txt \
  --output-dir runtime_state/whois_run \
  --checkpoint runtime_state/whois_checkpoint.db \
  --max-cache-age-hours 24 \
  --log-file logs/whois_probe.log
```

> **中断与恢复说明**：
> - 运行中随时可按 `Ctrl+C` 或发送 `SIGTERM`。程序会在完成当前正在执行的这 1 次域名查询并刷写 SQLite WAL 断点库后安全退出。
> - 再次执行完全相同的 `probe-whois` 命令，24 小时内已有终态 (`success`/`not_found`) 的域名会自动走本地 `CACHE` 跳过，仅继续查询未完成和上次 `unavailable` 限流超时的域名。

### C. 回传官方 WHOIS 原件与观测至 Hub

```bash
./run.sh sync-whois \
  --checkpoint runtime_state/whois_checkpoint.db \
  --topic "全库WHOIS补充核验" \
  --desc "Single-thread Verisign/CNNIC official verification"
```

### D. 导出按到期紧迫程度升序排列的结果表

```bash
# 方式 1：结合本地 WHOIS 与 ICP 导出
./run.sh export-csv \
  --checkpoint runtime_state/whois_checkpoint.db \
  --icp-file runtime_state/46_hunan_cleaned.jsonl \
  --max-days 30 \
  --output result/46_湖南省_过期与临期资产_有序结果.csv

# 方式 2：直接从 Hub 全库筛选（按省份、后缀、30天内）导出
./run.sh export-csv \
  --from-hub \
  --province 湖南省 \
  --tld com,net,cn,cc \
  --max-days 30 \
  --output result/46_湖南省_Hub全量临期资产_有序结果.csv
```

> **导出顺序校验**：第 1 段为已过期 / `pendingDelete` / `redemptionPeriod`，第 2 段为 `days_left = 0`，第 3 段为 `days_left = 1`，第 4 段为 `days_left = 2..30` 升序；默认自动排除 `gov.cn`/`edu.cn`；UTF-8 BOM 格式确保 Excel 双击不乱码。

---

## 阶段四：单线程队列 Worker 常驻模式

如果希望 Linux Agent 自动消费服务端下发的过期/缺失刷新任务：

```bash
# 单次领取测试
./run.sh job-worker --once

# 后台常驻（单线程顺序领取 -> 查官方 WHOIS -> 上传 JSONL 原件 -> 回执入库 -> complete）
nohup ./run.sh job-worker \
  --providers verisign_rdap,cnnic_whois,registry_rdap \
  --idle-sleep 15 \
  --log-file logs/job_worker.log \
  > logs/job_worker_stdout.log 2>&1 &
```

---

## 阶段五（可选）：无备案域名使用兼容检索 API 补充线索

仅当你在 `.env` 中自行填写了合规的 `ICP_LLM_API_URL` 与 `ICP_LLM_API_KEY` 时运行：

```bash
./run.sh enrich-icp-llm \
  --input runtime_state/no_icp_domains.txt \
  --batch-size 2 \
  --delay 2.0 \
  --output runtime_state/enriched_icp_llm.jsonl
```

---

## 常见问题自查清单

1. **为什么遇到 `403`？**
   - 检查是否是直接用 `curl` 没带 `User-Agent` 测试，或当前 Collector Token 没有配置对应 `provider` 权限（通过 `./run.sh verify` 核对 `providers` 字段）。
2. **上传大量记录还要配置 Token 吗？如果走 `--mode intake` 还限流吗？**
   - 批量上传（`ingest-icp`、`sync-whois`）现已全面免除 Token 限制，不配 Token 也能直走完整批次归档并获得 `authoritative = 1` 官方证明；`POST /v1/intake` 也已提升至单次最多 800 条且取消间隔延迟。只有 `pull-missing`、`export-csv --from-hub`、`job-worker` 需要 Token。
3. **为什么查完的 `.cn` / `.top` / `.vip` 域名也能直接进入官方主表？**
   - Hub 现已支持 `cnnic_whois` 北京无时区文本（自动按 `+08:00` 转 UTC 并记为 `official_response_missing_timezone`）与 IANA 官方引导表认证的 `registry_rdap`（含 `200` 成功与标准 `404 errorCode=404` 权威未注册证明）直接晋升 `domain_current`，且 `imported`/`legacy_catalog` 永不遮蔽官方结果。
4. **公共 Git 提交前注意什么？**
   - `git status` 确保看不到 `.env`、真实 `credentials.json`、`runtime_state/` 和 `result/`；`.gitignore` 已默认屏蔽上述目录与密钥后缀。
