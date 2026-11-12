# 02. Domain Hub v2 上传标准、接口规范与错误处理

本文档精确对应生产服务 (`https://hub.llmhubone.net`) 当前线上代码契约，确保采集 Agent 一次对接即可长期稳定入库。

---

## 一、 v2 相比上一版 (v1) 的核心变化

| 维度 | 上一版 (v1) | 当前线上版 (v2) | 对 Agent 实操的影响 |
| :--- | :--- | :--- | :--- |
| **开放上传模式 (`/v1/intake`)** | 单一松散接收（原限 1..20 条、5次/分/IP） | 放开大批量投递上限（**单次 `1..800` 条、取消限频**）且与严格 `.strict()` 校验并存 | 无需等待即可高吞吐补录线索；未知字段仍会整批 `422` 拒收，需用 `validate_intake_record()` 预校验 |
| **字段精准命名 (`/v1/intake`)** | 部分脚本混用 `nature`、`statuses`、`provider` | `/v1/intake` 的 `icp` 对象必须用 `subject_type`（非 `nature`），`whois` 对象必须用 `status`（字符串，非数组），顶层不接受 `provider`/`kind` | 强烈建议使用本仓库 `validate_intake_record()` 预校验再发送 |
| **部分拒收隔离 (`/v1/intake`)** | 报错常整批失败 | 单行格式/时间错误返回部分成功 `{accepted_records, accepted_observations, rejected: [{index, code, message}]}` | 客户端无需因个别脏行重传全批，仅需将 `rejected` 落盘待修正 |
| **批量原件归档免 Token (方案 B)** | 方案 B 必须携带 Bearer Token | `batches -> files -> PUT -> observations:batch -> complete` 整条批量写链路支持**免 Token 匿名直传**（路由至 `__open_batch__`）；若带 Bearer Token 则按授权节点归属 | `ingest-icp` 与 `sync-whois` 无需 Token 即可直接归档原件、提交官方 WHOIS 并晋升主表；读/查/导/抢单接口仍受 Token 保护 |
| **官方证据全后缀直通 (`domain_current`)** | 仅 `verisign_rdap` 晋升主表，且 `cnnic_whois` 无时区/未知后缀常留历史库 | `verisign_rdap`、`cnnic_whois`（补齐无后缀北京时间 `+08:00` 及 `not_found`）与 IANA 官方引导表校验通过的 `registry_rdap`（HTTP `200`/`404`）均直接晋升 `authoritative=1` 主表 | `.cn` / `.top` / `.vip` / `.xyz` 等通用后缀一次上传即完成权威入库；`evidence_scope=all` 下 `imported`/`legacy_catalog` 永不遮蔽官方主记录 |
| **原件校验与 CNNIC 无时区** | 部分状态直接采信 | `POST /v1/observations:batch` 对官方 WHOIS 严格比对 JSONL 原件 `endpoint`、`http_status`、`observed_at` 毫秒字符串和 `response_sha256` | CNNIC 43 端口无 HTTP 状态码，**JSONL 与 observation 两边都必须省略 `http_status`**；无时区北京文本服务端按 `+08:00` 转 UTC 并记为 `official_response_missing_timezone` |
| **全量缺口检索** | 受 5,000 上限或浅分页制约 | `POST /v1/candidates/search` 支持快照游标分页 `cursor`（`next_cursor`）及全套 `whois_coverage` / `evidence_scope` / `has_service_subid` 过滤 | 支持大于 5,000 条缺口域名的无遗漏全量拉取（推荐客户端 `timeout >= 60s`） |
| **边缘 WAF 校验** | 默认透传 | 边缘防护屏蔽空/默认 `Python-urllib` UA（直接返回 `403`） | 所有请求必须显式携带自定义 `User-Agent` |

---

## 二、 双上传通道接口标准

> **通用请求头要求**：
> - `User-Agent`: 必填非默认值（本工具统一使用 `agent-workflow/2.0 (...)`）
> - `Content-Type`: `application/json; charset=utf-8`（`PUT /v1/files/{id}/content` 上传原件字节除外）
> - `Idempotency-Key`: 所有 `POST` 写操作建议携带唯一且稳定的幂等键（同键同包重放安全；同键异包触发 `409`）
> - `Authorization`: `Bearer <DOMAIN_HUB_TOKEN>`（**批量上传通道 A/B 均已免 Token，可选填写**；仅检索/导出/队列/原件下载等受保护接口必填；注意若带入无效/格式错误 Bearer 头仍会返回 `401`）

### 方案 A：免密大批量轻量入口 (`POST /v1/intake`)

适合仅持有结构化 ICP/基础线索、无需额外上传原始 JSONL 原件的快速补录场景。

- **吞吐上限**：
  - 单次请求 `records` 数组长度 **`1 ~ 800` 条**（本工具默认 `chunk_size=500, delay_sec=0.0`）；
  - **禁止**传 `batch_id` 与 `file_id`（开放入口不接原件归档）；
  - 已解除单 IP `5次/分` 限频，可按需求连续顺序上传。
- **请求体严格结构 (`rowSchema.strict()`)**：
  ```json
  {
    "records": [
      {
        "domain": "example.com",
        "observed_at": "2026-11-11T03:20:00.123Z",
        "icp": {
          "subject": "上海示例科技有限公司",
          "subject_type": "企业",
          "main_license": "沪ICP备2020000001号",
          "service_license": "沪ICP备2020000001号-1",
          "province": "上海市",
          "filed_on": "2020-05-12",
          "updated_on": "2025-11-01"
        },
        "whois": {
          "expiration_date": "2026-12-01T00:00:00.000Z",
          "status": "clientTransferProhibited",
          "registrar": "Example Registrar"
        },
        "sheet": "sample_batch",
        "row_number": 2
      }
    ]
  }
  ```
- **字段规则**：
  - `icp` 与 `whois` 至少需提供一个有效块；
  - `icp` 有效条件：`subject`、`main_license`、`service_license` 至少有一个非空；`filed_on`/`updated_on` 必须为严格 `YYYY-MM-DD`；
  - `whois` 有效条件：`expiration_date`、`status`（字符串）、`registrar` 至少有一个非空；
  - `observed_at`：不得比服务端当前时间超前超过 5 分钟（否则触发 `422 future_observation`）。
- **返回结构**：
  ```json
  {
    "id": "uuid-receipt-id",
    "state": "processed | partial",
    "accepted_records": 19,
    "accepted_observations": 38,
    "rejected": [
      {"index": 4, "code": "invalid_domain", "message": "..."}
    ]
  }
  ```

---

### 方案 B：全量批次证据归档通道（默认启用，免 Token 即可使用）

**现在无需预先申请 `DOMAIN_HUB_TOKEN` 即可跑通完整 5 步原件归档流水线**（未传 `Authorization` 时自动归属内部免密采集槽位 `__open_batch__`；若配置了 Token 则按所属 Collector 归档并同时解锁查询/导出/抢单）。凡带有效公式原件的 `verisign_rdap` / `cnnic_whois` / 受 IANA 官方引导认证的 `registry_rdap` 结果，均可直接获得 **`authoritative = 1` 官方证明** 并晋升主表 `domain_current`。

#### 标准 5 步流水线
1. **建批次**：`POST /v1/batches`
   ```json
   {
     "schema_version": "1.0",
     "province_or_topic": "湖南省",
     "description": "Batch 46 WHOIS verification",
     "source_kind": "whois_verification",
     "client_batch_ref": "optional-stable-ref"
   }
   ```
2. **注册原件元数据**：`POST /v1/files`
   - `role`: `"source_input"`（原始表格/名单）| `"query_response"`（JSONL 原始查询响应）| `"manifest"`
   - 单文件不超过 `20 MiB`（建议 `query_response` JSONL 按 **`<= 900 KiB` 或 `<= 500` 行**自动分片，严禁超过 Hub 验证读取上限 `1 MiB`）。
3. **上传原件字节流**：`PUT /v1/files/{file_id}/content`
   - 发送文件原始字节，校验与 `POST /v1/files` 声明的 `sha256`、`byte_size` 一致后状态变为 `verified`。若重传已核验文件遇 `409`，查询 `GET /v1/files/{file_id}` 验证 `state == 'verified' && sha256 == digest` 即可安全复用。
4. **分片提交结构化观测**：`POST /v1/observations:batch`
   - 协议外包：`{"schema_version": "1.0", "batch_id": "...", "records": [...]}`
   - 体积与条数控制：服务端硬上限 500 条 / 1 MiB；**本工具严格按 `<= 100` 条且 `<= 850 KiB`（单条 `< 60 KiB`）分片**。
   - **JSONL `evidence` 对齐四要素**（缺一即报错 `evidence_metadata` / `evidence_hash`）：
     1. JSONL 第 `record_index` 行必须是合法 JSON，包含 `endpoint`、`observed_at`、`response_text`；
     2. `entry.observed_at` 与 `record.observed_at` 经标准化后的 UTC ISO 字符串（`.mmmZ`）必须完全一致；
     3. 若为 HTTPS RDAP（`verisign_rdap` / `registry_rdap`），`entry.http_status` 与 `record.evidence.http_status` 必须同为整数（如 `200` 或 `404`）；若为端口 43 WHOIS（`cnnic_whois`），**两边必须同时省略或设为 null**；
     4. `record.evidence.response_sha256` 必须等于 `SHA256_HEX(utf8(entry.response_text))`。
5. **等待异步回执终态并闭环批次**：
   - `POST /v1/observations:batch` 返回 HTTP `202` 与 `receipt_id`（服务端按每 3 条一微批异步消化）；
   - 轮询 `GET /v1/ingest-receipts/{receipt_id}` 直至 `state in ("processed", "partial")` 且 `pending == 0`；
   - 通过 `GET /v1/ingest-receipts/{receipt_id}/items?cursor=0` 核查每条的 `accepted` / `duplicate` / `rejected` 明细；
   - 最后可调用 `POST /v1/batches/{batch_id}/complete` 将批次标记为完结。

---

## 三、 域名/数据重复与冲突处理的科学原则

向服务端持续增量补全至全量时，不可避免地会遇到**重复提交相同域名或新旧状态变更**，Hub 采用四层科学机制避免“重复污染”与“错删老数据”：

1. **请求层防重 (`Idempotency-Key`)**：
   - 本工具通过 `OutboxStore` 将 `(op_key, body_sha256)` 映射为稳定 `Idempotency-Key`。网络超时原样重试返回原回执；若意外更改了请求体却复用旧 Key，服务端会返 `409 idempotency_conflict` 保护账本不被覆盖。
2. **观测事件层去重 (`event_id` -> `duplicate`)**：
   - `icp` 记录使用基于 `fact_hash` 派生的稳定 `event_id`（`icp_<sha256前32位>`）；
   - `registration` 记录使用基于 `provider + domain + 秒级时间戳 + response_sha256` 派生的唯一 `event_id`。
   - 同一 `event_id` 带着相同内容再次送达时，回执明细自动标记 **`duplicate`** 并安全跳过，**绝不算报错，也不消耗有效变更**；仅当同 `event_id` 内容却被篡改时才拒绝为 `event_payload_conflict`。
3. **ICP 事实集合并 (`icp_links ON CONFLICT(fact_hash)`)**：
   - 同一个域名可以历史上或不同批次关联多份不同主办方/备案号快照。相同 6 元组通过 `fact_hash` 去重（仅在原空字段有补充或新批关联时增量完善），不同备案主体自动并存归档。
4. **WHOIS 主表覆盖保护 (`domain_current`)**：
   - **同级刷新**：每次带着新 `observed_at` 与新证据的 `authoritative=1` 官方观测会合理刷新 `domain_current` 的到期时间与状态；
   - **权级保护**：匿名 `/v1/intake` 或非官方来源观测不会覆盖已存在的官方核验主记录 (`authoritative=1`)；`unavailable`/`error` 瞬态失败只会追加日志或刷新失败记录，**不会抹除历史已查到的真实到期日期**。

---

## 四、 错误分级与 Agent 自动处理标准

本工具遵循“开发日志详尽可追溯、用户/Agent 反馈可读可执行”原则，所有错误按如下 5 类处置：

| HTTP 状态 / 场景 | 分类 | 常见错误码 | 工具默认策略与 Agent 下一步行动 |
| :--- | :--- | :--- | :--- |
| **401 Unauthorized** | `permission_error` | `unauthorized` / `missing_token` | 立即停止（不可重试）；仅检索/导出/队列接口或携带了错误 Bearer 头时触发；批量上传可清空无效 Token 直接免密提交 |
| **403 Forbidden** | `permission_error` | `provider_forbidden` / WAF 拦截 | 立即停止；检查是否缺少自定义 `User-Agent`，或联系管理员给节点授权对应 `provider` |
| **409 Conflict** | `input_error` | `idempotency_conflict` | `PUT /files/{id}/content` 遇到时会自动核查远端 SHA-256；其他接口需更换 `client_batch_ref` 或新 `event_id` |
| **400 / 413 / 415 / 422** | `input_error` | `invalid_input` / `evidence_metadata` / `future_observation` / `record_too_large` | 本地预校验已拦截 95% 异常；如被服务端退回 `/v1/intake rejected` 列表，自动保存 `runtime_state/intake_rejected.jsonl` 不丢数据 |
| **429 Too Many Requests** | `service_error` | `public_intake_rate` / `rate_limited` | **自动等待 `Retry-After`（默认 60s + 抖动）后单线程原地重试** |
| **500 / 502 / 503 / 超时** | `service_error` / `network_error` | `service_unavailable` / SocketTimeout | 使用原 `Idempotency-Key` 指数退避重试最多 4 次；全部失败时安全退出，保留 `outbox.db` 与 `whois_checkpoint.db` 下次续传 |
