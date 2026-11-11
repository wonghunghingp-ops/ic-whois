"""Unified single-threaded Linux CLI entrypoint for agent-workflow."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from .common import (
    DEFAULT_USER_AGENT,
    archive_raw_input,
    atomic_write_text,
    clean_id,
    clean_text,
    export_ordered_csv,
    load_env_file,
    ms_iso_utc,
    normalize_domain,
    normalize_province,
    strip_empty,
    utc_now_iso_ms,
)
from .hub_client import DomainHubClient, HubClientError, parse_proxy_url
from .icp_cleaner import (
    clean_icp_file,
    enrich_icp_with_llm,
    load_raw_rows,
    to_authorized_icp_observations,
    to_intake_records,
)
from .whois_single import (
    SingleThreadWhoisEngine,
    WhoisCheckpointStore,
    WhoisQueryConfig,
    to_hub_evidence_items,
)

LOGGER = logging.getLogger("agent_workflow.cli")


def _setup_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        lp = Path(log_file)
        lp.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(lp, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def _env_float(name: str, default: float) -> float:
    raw = clean_text(os.environ.get(name))
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _build_hub_client(args: argparse.Namespace) -> DomainHubClient:
    base_url = clean_text(getattr(args, "hub_url", None) or os.environ.get("DOMAIN_HUB_URL") or "https://hub.llmhubone.net")
    token = clean_text(getattr(args, "token", None) or os.environ.get("DOMAIN_HUB_TOKEN") or "")
    proxy = clean_text(getattr(args, "hub_proxy", None) or os.environ.get("HTTP_PROXY_URL") or "")
    timeout = float(getattr(args, "timeout", None) or _env_float("HUB_HTTP_TIMEOUT", 60.0))
    state_dir = Path(getattr(args, "state_dir", None) or "runtime_state")
    return DomainHubClient(
        base_url,
        token=token,
        proxy_url=proxy,
        timeout_sec=timeout,
        user_agent=DEFAULT_USER_AGENT,
        outbox_path=state_dir / "outbox.db",
    )


def _load_domains_from_file(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"域名输入文件不存在: {path}")
    suffix = path.suffix.lower()
    if suffix in (".json", ".jsonl", ".ndjson", ".csv", ".tsv"):
        rows, _ = load_raw_rows(path)
        domains: list[str] = []
        seen: set[str] = set()
        for r in rows:
            d = normalize_domain(
                r.get("domain") or r.get("域名") or r.get("domain_name") or r.get("host"),
                collapse_subdomain=True,
            )
            if d and d not in seen:
                seen.add(d)
                domains.append(d)
        return domains
    domains = []
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        first_col = s.split(",")[0].split("\t")[0].strip()
        d = normalize_domain(first_col, collapse_subdomain=True)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


def cmd_verify(args: argparse.Namespace) -> int:
    hub = _build_hub_client(args)
    health = hub.health_ready()
    print(f"[成功] Domain Hub 就绪检查通过：{hub.base_url}（延迟 {health['latency_ms']} ms）")
    proxy_str = clean_text(getattr(args, "socks5_proxy", None) or os.environ.get("WHOIS_SOCKS5_PROXY") or "")
    if proxy_str:
        cfg = parse_proxy_url(proxy_str)
        assert cfg is not None
        print(f"[配置] WHOIS 可选单节点代理已验证格式：{cfg.scheme}://{cfg.host}:{cfg.port}")
    else:
        print("[配置] WHOIS 查询模式：单线程直连（未启用代理）")

    if hub.token:
        me = hub.collector_me()
        print(
            f"[成功] Collector 身份认证通过：id={me.get('id')} name={me.get('name')} "
            f"scopes={me.get('scopes')} providers={me.get('providers')}"
        )
        print("下一步建议：可使用 clean-icp / ingest-icp（授权方案 B）、pull-missing、probe-whois、sync-whois、job-worker。")
    else:
        print("[提示] 未配置 DOMAIN_HUB_TOKEN，将采用匿名公开通道（方案 A: POST /v1/intake，单次最多 20 条，5 次/分钟/IP）。")
        print("下一步建议：可使用 clean-icp、probe-whois，并通过 --mode intake 提交数据；如需批量归档与拉取全量缺口，请配置 DOMAIN_HUB_TOKEN。")
    return 0


def cmd_clean_icp(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if args.archive_raw:
        archived = archive_raw_input(
            input_path,
            seq=args.seq or "00",
            province=args.province or "全国",
            description=args.desc or input_path.stem,
            result_dir=Path(args.result_dir),
        )
        print(f"[归档] 原始资料已复制到: {archived}")

    rows, stats = clean_icp_file(
        input_path,
        require_666=args.require_666,
        collapse_subdomain=not args.keep_subdomain,
        dedup_mode=args.dedup_mode,
        default_province=args.default_province or "",
    )

    out_jsonl = Path(args.output)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    jsonl_body = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + ("\n" if rows else "")
    atomic_write_text(out_jsonl, jsonl_body)

    domains_out = Path(args.domains_out)
    seen: set[str] = set()
    unique_domains: list[str] = []
    for r in rows:
        d = r["domain"]
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)
    atomic_write_text(domains_out, "\n".join(unique_domains) + ("\n" if unique_domains else ""))

    print(
        f"[成功] ICP 清洗完成（编码 {stats.detected_encoding}）："
        f"原始 {stats.total_rows} 行 -> 有效 {stats.accepted_rows} 条 / 唯一域名 {stats.unique_domains} 个 "
        f"（666有网站分号: {stats.count_666_sublicense}，665纯主体/无分号: {stats.count_665_mainonly}）。"
    )
    print(
        f"[过滤统计] 纯IP={stats.skipped_ip}，中文/非ASCII={stats.skipped_non_ascii}，"
        f"非法域名={stats.skipped_invalid_domain}，重复fact_hash={stats.deduped_facts}，"
        f"过滤665={stats.skipped_665_filtered}"
    )
    for w in stats.warnings:
        print(f"[提示] {w}")
    print(f"[输出] 清洗明细: {out_jsonl} | 域名清单: {domains_out}")
    return 0


def cmd_ingest_icp(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    hub = _build_hub_client(args)
    mode = args.mode
    if mode == "auto":
        mode = "authorized" if hub.token else "intake"

    if mode == "authorized" and not hub.token:
        raise HubClientError(
            "选择 authorized 授权批量上传模式，但未配置 DOMAIN_HUB_TOKEN。",
            category="permission_error",
            code="missing_token",
            next_step="请设置 DOMAIN_HUB_TOKEN，或改用 --mode intake 走匿名公开通道。",
        )

    rows, stats = clean_icp_file(
        input_path,
        require_666=args.require_666,
        dedup_mode=args.dedup_mode,
        default_province=args.default_province or "",
    )
    if not rows:
        print("[阻塞] 清洗后没有任何合法可上传的备案记录，请先检查输入文件内容。")
        return 2

    if args.archive_raw:
        archived = archive_raw_input(
            input_path,
            seq=args.seq or "00",
            province=args.province or "全国",
            description=args.desc or input_path.stem,
            result_dir=Path(args.result_dir),
        )
        print(f"[归档] 本地原始输入已归档: {archived}")

    if mode == "intake":
        delay_sec = float(args.intake_delay if args.intake_delay is not None else _env_float("INTAKE_DELAY_SEC", 16.0))
        intake_records = to_intake_records(rows)
        print(f"[进行中] 即将通过匿名通道 POST /v1/intake 上传 {len(intake_records)} 条备案记录（每批 <=20 条，间隔 {delay_sec}s）...")
        res = hub.submit_intake(intake_records, chunk_size=20, delay_sec=delay_sec)
        rejected_all = res["locally_invalid"] + res["server_rejected"]
        if rejected_all:
            rej_path = Path(args.state_dir) / "intake_rejected.jsonl"
            rej_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(rej_path, "\n".join(json.dumps(x, ensure_ascii=False) for x in rejected_all) + "\n")
            print(f"[警告] 有 {len(rejected_all)} 条记录被本地或服务端拒绝，已保存至 {rej_path} 供修正重提。")
        print(
            f"[成功] 匿名备案投递完成：提交 {res['sent_valid']} 条，接收记录 {res['accepted_records']} 条，"
            f"写入观测 {res['accepted_observations']} 条，拒绝 {len(rejected_all)} 条。"
        )
        return 0

    # Authorized Plan B pipeline
    topic = clean_text(args.province or args.topic) or "全国"
    desc = clean_text(args.desc) or f"ICP snapshot upload from {input_path.name}"
    batch = hub.create_batch(
        topic,
        desc,
        args.source_kind or "miit_snapshot",
        client_batch_ref=args.client_batch_ref,
    )
    batch_id = batch.get("batch_id") or batch.get("id")
    print(f"[批次] 已创建/复用批次: batch_id={batch_id} display_seq={batch.get('display_seq')}")

    src_bytes = input_path.read_bytes()
    file_info = hub.upload_file_bytes(
        batch_id,
        input_path.name,
        "source_input",
        desc[:150],
        src_bytes,
    )
    source_file_id = file_info["file_id"]
    print(f"[原件] 原始文件已核验归档: file_id={source_file_id} sha256={file_info.get('sha256')[:12]}...")

    obs = to_authorized_icp_observations(
        rows,
        source_file_id=source_file_id,
        provider=args.provider or "miit_snapshot",
    )
    summary = hub.submit_observations_batch(batch_id, obs, wait_receipts=not args.no_wait)
    print(
        f"[成功] 授权 ICP 批量入库完成（原始 {stats.total_rows} 行，有效 {len(obs)} 条）："
        f"新增接收={summary['accepted']}，幂等去重={summary['duplicates']}，拒绝={summary['rejected']}。"
    )
    return 0 if summary["rejected"] == 0 else 1


def cmd_pull_missing(args: argparse.Namespace) -> int:
    hub = _build_hub_client(args)
    filters: dict[str, Any] = {
        "evidence_scope": args.evidence_scope,
        "whois_coverage": args.coverage,
        "require_official_expiration": False,
    }
    if args.tld:
        filters["registrable_suffix_in"] = [t.strip().lstrip(".").lower() for t in args.tld.split(",") if t.strip()]
    if args.province:
        filters["province_in"] = [
            normalize_province(p.strip()) or p.strip()
            for p in args.province.split(",")
            if p.strip()
        ]
    if args.max_age_hours is not None:
        filters["max_registration_observation_age_hours"] = float(args.max_age_hours)
    if args.has_service_subid is not None:
        filters["has_service_subid"] = args.has_service_subid == "true"

    max_items = None if (args.limit is not None and args.limit <= 0) else (args.limit or 5000)
    print(f"[进行中] 正在通过游标分页拉取缺口域名（coverage={args.coverage}, scope={args.evidence_scope}, max_items={max_items or '全量'}）...")

    items = list(hub.iter_candidates(filters, page_size=args.page_size, max_items=max_items))
    seen: set[str] = set()
    domains: list[str] = []
    for item in items:
        d = normalize_domain(item.get("domain"), collapse_subdomain=True)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)

    out_path = Path(args.output)
    atomic_write_text(out_path, "\n".join(domains) + ("\n" if domains else ""))
    if args.json_out:
        atomic_write_text(
            Path(args.json_out),
            "\n".join(json.dumps(it, ensure_ascii=False) for it in items) + ("\n" if items else ""),
        )
    print(f"[成功] 已拉取 {len(items)} 条候选，提取去重后域名 {len(domains)} 个，写入 {out_path}。")
    return 0


def cmd_probe_whois(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    domains = _load_domains_from_file(input_path)
    if args.limit and args.limit > 0:
        domains = domains[: args.limit]
    if not domains:
        print("[阻塞] 未在输入文件中找到有效 ASCII 域名（已忽略纯 IP 与中文域名）。")
        return 2

    state_dir = Path(args.state_dir)
    ckpt_path = Path(args.checkpoint) if args.checkpoint else (state_dir / "whois_checkpoint.db")
    checkpoint = WhoisCheckpointStore(ckpt_path)

    cfg = WhoisQueryConfig(
        rdap_delay_min=float(args.rdap_min if args.rdap_min is not None else _env_float("WHOIS_RDAP_DELAY_MIN", 0.7)),
        rdap_delay_max=float(args.rdap_max if args.rdap_max is not None else _env_float("WHOIS_RDAP_DELAY_MAX", 1.2)),
        cnnic_delay_min=float(args.cnnic_min if args.cnnic_min is not None else _env_float("WHOIS_CNNIC_DELAY_MIN", 1.4)),
        cnnic_delay_max=float(args.cnnic_max if args.cnnic_max is not None else _env_float("WHOIS_CNNIC_DELAY_MAX", 2.2)),
        timeout_sec=float(args.timeout or 20.0),
        max_retries=int(args.max_retries or 3),
        socks5_proxy=clean_text(args.socks5_proxy or os.environ.get("WHOIS_SOCKS5_PROXY") or ""),
        bootstrap_cache_path=state_dir / "iana_rdap_dns.json",
    )

    engine = SingleThreadWhoisEngine(cfg, checkpoint=checkpoint)
    print(f"[进行中] 开始单线程顺序 WHOIS/RDAP 核验，共 {len(domains)} 个唯一域名（断点库: {ckpt_path}）...")

    def _on_item(idx: int, total: int, item: dict[str, Any]) -> None:
        tag = "CACHE" if item.get("from_cache") else "LIVE"
        print(
            f"[{idx}/{total}][{tag}] {item['domain']} -> provider={item['provider']} "
            f"outcome={item['outcome']} exp={item.get('expiration_date') or '-'} days_left={item.get('days_left')}"
        )

    results = engine.query_batch(
        domains,
        max_cache_age_hours=float(args.max_cache_age_hours),
        force=args.force,
        progress_cb=_on_item,
    )

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        out_dir / "whois_results.jsonl",
        "\n".join(json.dumps(r, ensure_ascii=False) for r in results) + ("\n" if results else ""),
    )

    bundles = to_hub_evidence_items(results)
    atomic_write_text(
        out_dir / "whois_evidence.jsonl",
        "\n".join(json.dumps(b["evidence_entry"], ensure_ascii=False) for b in bundles) + ("\n" if bundles else ""),
    )

    counts = {
        "success": sum(1 for r in results if r["outcome"] == "success"),
        "not_found": sum(1 for r in results if r["outcome"] == "not_found"),
        "partial": sum(1 for r in results if r["outcome"] == "partial"),
        "unavailable": sum(1 for r in results if r["outcome"] == "unavailable"),
    }
    print(
        f"[成功] 单线程 WHOIS 核验完成（共处理 {len(results)} 个）："
        f"success={counts['success']}, not_found={counts['not_found']}, partial={counts['partial']}, unavailable={counts['unavailable']}"
    )

    if args.export_csv:
        icp_map = _load_icp_lookup(Path(args.icp_file)) if args.icp_file else {}
        merged = _merge_whois_and_icp(results, icp_map)
        n_csv = export_ordered_csv(
            merged,
            Path(args.export_csv),
            max_days=None if args.all_days else args.max_days,
            exclude_restricted=not args.include_restricted,
        )
        print(f"[导出] 有序资产 CSV 已写入 {args.export_csv}（共 {n_csv} 行）")
    return 0


def cmd_sync_whois(args: argparse.Namespace) -> int:
    hub = _build_hub_client(args)
    mode = args.mode
    if mode == "auto":
        mode = "authorized" if hub.token else "intake"

    state_dir = Path(args.state_dir)
    checkpoint: WhoisCheckpointStore | None = None
    if args.input:
        records = [
            json.loads(line)
            for line in Path(args.input).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        ckpt_path = Path(args.checkpoint) if args.checkpoint else (state_dir / "whois_checkpoint.db")
        checkpoint = WhoisCheckpointStore(ckpt_path)
        records = checkpoint.list_results(only_unuploaded=not args.all_cached)

    # Do not upload transient unavailable placeholders unless explicitly requested
    uploadable = [r for r in records if r.get("outcome") in ("success", "not_found", "partial")]
    if not uploadable:
        print("[提示] 没有待上传的新 WHOIS 核验结果（如之前已全部上传，可传 --all-cached 重新重放或先跑 probe-whois）。")
        return 0

    if mode == "intake":
        print("[警告] 正在使用匿名 /v1/intake 上报 WHOIS（无官方原件文件附件，服务端将记为未核验线索）。正式核验强烈建议配置 DOMAIN_HUB_TOKEN！")
        intake_rows = []
        for r in uploadable:
            if not (r.get("expiration_date") or r.get("statuses") or r.get("registrar")):
                continue
            intake_rows.append(
                {
                    "domain": r["domain"],
                    "observed_at": ms_iso_utc(r.get("observed_at")) or utc_now_iso_ms(),
                    "whois": strip_empty(
                        {
                            "expiration_date": r.get("expiration_date"),
                            "status": ", ".join(r.get("statuses") or []),
                            "registrar": r.get("registrar"),
                        }
                    ),
                }
            )
        if not intake_rows:
            print("[提示] 当前没有包含到期时间/状态/注册商的有效 WHOIS 记录可通过匿名 /v1/intake 上报。")
            return 0
        delay_sec = float(args.intake_delay if args.intake_delay is not None else _env_float("INTAKE_DELAY_SEC", 16.0))
        res = hub.submit_intake(intake_rows, chunk_size=20, delay_sec=delay_sec)
        print(
            f"[成功] 匿名 WHOIS 投递完成：提交 {res['sent_valid']} 条，接收 {res['accepted_records']} 条，拒绝 {len(res['server_rejected']) + len(res['locally_invalid'])} 条。"
        )
        return 0

    topic = clean_text(args.topic or args.province) or "WHOIS官方核验"
    desc = clean_text(args.desc) or f"Single-thread WHOIS verification ({len(uploadable)} domains)"
    batch = hub.create_batch(
        topic,
        desc,
        args.source_kind or "whois_verification",
        client_batch_ref=args.client_batch_ref,
    )
    batch_id = batch.get("batch_id") or batch.get("id")
    print(f"[批次] WHOIS 上传批次就绪: batch_id={batch_id} display_seq={batch.get('display_seq')}")

    bundles = to_hub_evidence_items(uploadable)
    res = hub.upload_evidence_jsonl_and_observations(
        batch_id,
        bundles,
        file_prefix=args.file_prefix or "whois_evidence",
        description=desc[:120],
        wait_receipts=not args.no_wait,
    )
    if checkpoint and res.get("rejected", 0) == 0:
        checkpoint.mark_uploaded([r["domain"] for r in uploadable])

    print(
        f"[成功] 官方 WHOIS 原件与观测上传完成：原件分片 {len(res['files'])} 个，"
        f"新增接收={res['accepted']}，幂等去重={res['duplicates']}，拒绝={res['rejected']}。"
    )
    return 0 if res["rejected"] == 0 else 1


def cmd_job_worker(args: argparse.Namespace) -> int:
    hub = _build_hub_client(args)
    if not hub.token:
        raise HubClientError(
            "job-worker 需要授权 Collector Token。",
            category="permission_error",
            code="missing_token",
            next_step="请在 .env 或 --token 中配置具有 worker / ingest 权限的 DOMAIN_HUB_TOKEN。",
        )

    providers = [p.strip() for p in (args.providers or "verisign_rdap,cnnic_whois,registry_rdap").split(",") if p.strip()]
    state_dir = Path(args.state_dir)
    cfg = WhoisQueryConfig(
        rdap_delay_min=_env_float("WHOIS_RDAP_DELAY_MIN", 0.7),
        rdap_delay_max=_env_float("WHOIS_RDAP_DELAY_MAX", 1.2),
        cnnic_delay_min=_env_float("WHOIS_CNNIC_DELAY_MIN", 1.4),
        cnnic_delay_max=_env_float("WHOIS_CNNIC_DELAY_MAX", 2.2),
        socks5_proxy=clean_text(args.socks5_proxy or os.environ.get("WHOIS_SOCKS5_PROXY") or ""),
        bootstrap_cache_path=state_dir / "iana_rdap_dns.json",
    )
    engine = SingleThreadWhoisEngine(cfg, checkpoint=None)

    batch = hub.create_batch(
        "刷新任务回填",
        f"Single-thread queue worker ({','.join(providers)})",
        "job_worker",
    )
    batch_id = batch.get("batch_id") or batch.get("id")
    handled = 0

    while True:
        if args.max_jobs and handled >= args.max_jobs:
            break
        job = hub.claim_job(providers=providers)
        if not job:
            print("[空闲] 当前队列暂无待刷新任务。")
            if args.once:
                break
            time.sleep(float(args.idle_sleep))
            continue

        job_id = str(job["id"])
        domain = str(job["domain"])
        lease = str(job["lease_token"])
        attempts = int(job.get("attempts") or 1)
        print(f"[领取任务] job={job_id} domain={domain} provider={job.get('provider')} attempt={attempts}")

        try:
            hub.heartbeat_job(job_id, lease)
            probe = engine.query_domain(domain, force=True)
            bundles = to_hub_evidence_items([probe])
            # Match worker idempotent job event_id format
            bundles[0]["observation"]["event_id"] = clean_id(f"job:{job_id}:{attempts}")
            upload_res = hub.upload_evidence_jsonl_and_observations(
                batch_id,
                bundles,
                file_prefix=f"job_{clean_id(job_id)}",
                description=f"job:{domain}",
                wait_receipts=True,
            )
            receipt_id = upload_res["receipts"][0]["id"]
            if upload_res.get("rejected", 0) > 0:
                hub.fail_job(job_id, lease, f"observation_rejected receipt={receipt_id}")
                print(f"[失败] 任务 {job_id} 观测被拒绝: receipt={receipt_id}")
            else:
                hub.complete_job(job_id, lease, receipt_id)
                print(f"[完成] 任务 {job_id} ({domain}) -> outcome={probe['outcome']} receipt={receipt_id}")
        except Exception as exc:
            LOGGER.exception("Job %s failed", job_id)
            try:
                hub.fail_job(job_id, lease, str(exc)[:280])
            except Exception as fail_exc:
                LOGGER.warning("Failed to report job failure for %s: %s", job_id, fail_exc)
        handled += 1
        if args.once:
            break

    print(f"[结束] 单线程队列 Worker 退出，本轮共处理 {handled} 个任务。")
    return 0


def cmd_export_csv(args: argparse.Namespace) -> int:
    rows: list[dict[str, Any]] = []
    if args.from_hub:
        hub = _build_hub_client(args)
        filters: dict[str, Any] = {
            "evidence_scope": args.evidence_scope,
            "require_official_expiration": not args.allow_unverified,
        }
        if args.max_days is not None and not args.all_days:
            filters["max_days_left"] = int(args.max_days)
        if args.province:
            filters["province_in"] = [normalize_province(p.strip()) or p.strip() for p in args.province.split(",") if p.strip()]
        if args.tld:
            filters["registrable_suffix_in"] = [t.strip().lstrip(".").lower() for t in args.tld.split(",") if t.strip()]

        for item in hub.iter_candidates(filters, max_items=args.limit or None):
            rows.append(
                {
                    "domain": item.get("domain"),
                    "matched_type": item.get("registry_state"),
                    "expiration_date": item.get("expiration_date"),
                    "outcome": "not_found" if item.get("registry_state") == "not_found" else "registered",
                    "statuses": [item.get("registry_state")] if item.get("registry_state") else [],
                    "source": item.get("provider"),
                    "unit_name": item.get("icp_subject"),
                    "service_licence": item.get("icp_license"),
                    "main_licence": item.get("icp_license"),
                    "nature": item.get("icp_subject_type") or item.get("icp_province"),
                    "updated": item.get("registration_observed_at") or item.get("icp_updated_on"),
                }
            )
    else:
        if args.whois_file:
            whois_rows = [
                json.loads(ln)
                for ln in Path(args.whois_file).read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
        else:
            state_dir = Path(args.state_dir)
            ckpt_path = Path(args.checkpoint) if args.checkpoint else (state_dir / "whois_checkpoint.db")
            whois_rows = WhoisCheckpointStore(ckpt_path).list_results(only_unuploaded=False)
        icp_map = _load_icp_lookup(Path(args.icp_file)) if args.icp_file else {}
        rows = _merge_whois_and_icp(whois_rows, icp_map)

    out_path = Path(args.output)
    written = export_ordered_csv(
        rows,
        out_path,
        max_days=None if args.all_days else int(args.max_days),
        exclude_restricted=not args.include_restricted,
    )
    print(f"[成功] 有序资产 CSV 导出完成：{out_path}（共 {written} 行，按过期/pendingDelete -> 0天 -> 1天 -> 30天内升序排列，UTF-8 BOM 编码）")
    return 0


def cmd_enrich_icp_llm(args: argparse.Namespace) -> int:
    api_url = clean_text(args.api_url or os.environ.get("ICP_LLM_API_URL") or "")
    api_key = clean_text(args.api_key or os.environ.get("ICP_LLM_API_KEY") or "")
    model = clean_text(args.model or os.environ.get("ICP_LLM_MODEL") or "glm-4-flash")
    if not api_url or not api_key:
        raise HubClientError(
            "缺少联网查询 API 配置，无法执行补充查询。",
            category="permission_error",
            code="missing_llm_config",
            next_step="请在 .env 中配置 ICP_LLM_API_URL 与 ICP_LLM_API_KEY 后重试。",
        )
    domains = _load_domains_from_file(Path(args.input))
    if args.limit and args.limit > 0:
        domains = domains[: args.limit]
    if not domains:
        print("[阻塞] 未读取到合法 ASCII 域名。")
        return 2

    print(f"[进行中] 正在单线程小批（batch={args.batch_size}）查询 {len(domains)} 个域名的补充 ICP 信息...")
    enriched = enrich_icp_with_llm(
        domains,
        api_url=api_url,
        api_key=api_key,
        model=model,
        batch_size=int(args.batch_size),
        delay_sec=float(args.delay),
    )
    out_path = Path(args.output)
    atomic_write_text(
        out_path,
        "\n".join(json.dumps(r, ensure_ascii=False) for r in enriched) + ("\n" if enriched else ""),
    )
    print(f"[成功] 补充查询完成：命中 {len(enriched)} 条（标注为 llm_web_search 非官方来源），已写入 {out_path}。")
    return 0


def _load_icp_lookup(icp_path: Path) -> dict[str, dict[str, Any]]:
    if not icp_path.is_file():
        return {}
    rows, _ = clean_icp_file(icp_path, dedup_mode="domain")
    return {r["domain"]: r for r in rows}


def _merge_whois_and_icp(whois_rows: list[dict[str, Any]], icp_map: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for w in whois_rows:
        if w.get("outcome") == "unavailable":
            continue
        dom = normalize_domain(w.get("domain"), collapse_subdomain=False) or ""
        icp = icp_map.get(dom, {})
        merged.append(
            {
                "domain": dom,
                "expiration_date": w.get("expiration_date"),
                "outcome": w.get("outcome"),
                "statuses": w.get("statuses") or [],
                "source": w.get("provider"),
                "unit_name": icp.get("subject") or w.get("registrar") or "",
                "service_licence": icp.get("service_license") or "",
                "main_licence": icp.get("main_license") or "",
                "nature": icp.get("subject_type") or icp.get("province") or "",
                "updated": icp.get("updated_on") or w.get("observed_at") or "",
            }
        )
    return merged


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-workflow",
        description="Domain Hub v2 单线程 Linux 采集清洗、官方 WHOIS/RDAP 核验与有序导出工具箱",
    )
    parser.add_argument("--env-file", default=".env", help="环境变量文件路径（默认 .env）")
    parser.add_argument("--hub-url", help="覆盖 DOMAIN_HUB_URL")
    parser.add_argument("--token", help="覆盖 DOMAIN_HUB_TOKEN")
    parser.add_argument("--hub-proxy", help="访问 Hub 时可选的单个 HTTP/SOCKS5 代理")
    parser.add_argument("--timeout", type=float, help="HTTP 超时秒数（默认 60）")
    parser.add_argument("--state-dir", default="runtime_state", help="断点数据库与运行状态目录")
    parser.add_argument("--log-file", help="详细技术日志输出文件（与用户界面提示隔离）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")

    sub = parser.add_subparsers(dest="command", required=True)

    # verify
    p_ver = sub.add_parser("verify", help="检查 Hub 服务连通性、Token 身份与单线程配置")
    p_ver.add_argument("--socks5-proxy", help="验证可选单节点 SOCKS5 代理格式")
    p_ver.set_defaults(func=cmd_verify)

    # clean-icp
    p_clean = sub.add_parser("clean-icp", help="清洗备案原始表（过滤IP/汉字、666优先排序、省份推断、fact_hash去重）")
    p_clean.add_argument("--input", required=True, help="原始 ICP 文件路径（CSV/TSV/TXT/JSON/JSONL）")
    p_clean.add_argument("--output", default="runtime_state/cleaned_icp.jsonl", help="清洗后 JSONL 输出路径")
    p_clean.add_argument("--domains-out", default="runtime_state/cleaned_domains.txt", help="去重域名 TXT 输出路径")
    p_clean.add_argument("--require-666", action="store_true", help="仅保留 666 网站分号记录（过滤 665 纯主体）")
    p_clean.add_argument("--keep-subdomain", action="store_true", help="保留子域名而不折叠至可注册根域名")
    p_clean.add_argument("--dedup-mode", choices=("fact", "domain"), default="fact", help="按事实哈希还是按域名去重")
    p_clean.add_argument("--default-province", help="当省份为空且备案号无简称时的默认省份")
    p_clean.add_argument("--archive-raw", action="store_true", help="同步原始资料到 result/raw_inputs/")
    p_clean.add_argument("--seq", default="00", help="批次序号，如 46")
    p_clean.add_argument("--province", default="全国", help="省份名称，如 湖南省")
    p_clean.add_argument("--desc", default="", help="资料说明，如 备案域名快照")
    p_clean.add_argument("--result-dir", default="result", help="result 归档根目录")
    p_clean.set_defaults(func=cmd_clean_icp)

    # ingest-icp
    p_ing = sub.add_parser("ingest-icp", help="清洗并上传 ICP 数据到 Domain Hub（支持授权档案模式与匿名 /v1/intake）")
    p_ing.add_argument("--input", required=True, help="原始或已清洗 ICP 文件路径")
    p_ing.add_argument("--mode", choices=("auto", "authorized", "intake"), default="auto", help="上传通道")
    p_ing.add_argument("--province", default="全国", help="省份/主题名")
    p_ing.add_argument("--topic", help="主题名（同 province）")
    p_ing.add_argument("--desc", default="", help="批次说明")
    p_ing.add_argument("--source-kind", default="miit_snapshot", help="批次 source_kind 标识")
    p_ing.add_argument("--provider", default="miit_snapshot", help="观测来源 provider")
    p_ing.add_argument("--client-batch-ref", help="幂等批次引用标识")
    p_ing.add_argument("--require-666", action="store_true", help="仅上传 666 有网站分号记录")
    p_ing.add_argument("--dedup-mode", choices=("fact", "domain"), default="fact")
    p_ing.add_argument("--default-province", help="默认省份兜底")
    p_ing.add_argument("--archive-raw", action="store_true", help="同时拷贝原件到本地 result/raw_inputs/")
    p_ing.add_argument("--seq", default="00", help="本地归档序号")
    p_ing.add_argument("--result-dir", default="result")
    p_ing.add_argument("--intake-delay", type=float, help="匿名 /v1/intake 每批(20条)之间的等待秒数（默认 16）")
    p_ing.add_argument("--no-wait", action="store_true", help="提交 observations:batch 后不阻塞等待回执")
    p_ing.set_defaults(func=cmd_ingest_icp)

    # pull-missing
    p_pull = sub.add_parser("pull-missing", help="通过 Hub 游标接口批量拉取未核验/待刷新域名列表")
    p_pull.add_argument("--coverage", default="missing_official", choices=("any", "official", "historical", "dated", "missing", "missing_any", "missing_official"))
    p_pull.add_argument("--evidence-scope", default="all", choices=("official", "historical", "all"))
    p_pull.add_argument("--tld", help="限定后缀，逗号分隔，如 com,cn,net")
    p_pull.add_argument("--province", help="限定省份，逗号分隔，如 湖南,江苏")
    p_pull.add_argument("--max-age-hours", type=float, help="仅拉取观测新鲜度内记录，或配合筛选")
    p_pull.add_argument("--has-service-subid", choices=("true", "false"), help="筛选 666(true) 或 665(false)")
    p_pull.add_argument("--page-size", type=int, default=200)
    p_pull.add_argument("--limit", type=int, default=5000, help="最多拉取条数，设为 0 表示不限全量游标遍历")
    p_pull.add_argument("--output", default="runtime_state/missing_domains.txt", help="导出域名列表路径")
    p_pull.add_argument("--json-out", help="可选：保存完整候选 JSONL")
    p_pull.set_defaults(func=cmd_pull_missing)

    # probe-whois
    p_prb = sub.add_parser("probe-whois", help="Linux 单线程顺序查询官方 Verisign RDAP / CNNIC 43 / IANA RDAP")
    p_prb.add_argument("--input", required=True, help="待查域名文件（TXT/CSV/JSON/JSONL）")
    p_prb.add_argument("--output-dir", default="runtime_state/whois_run", help="输出 results/evidence JSONL 的目录")
    p_prb.add_argument("--checkpoint", help="SQLite WAL 断点库路径")
    p_prb.add_argument("--socks5-proxy", help="可选单个 SOCKS5 代理（默认直连）")
    p_prb.add_argument("--rdap-min", type=float)
    p_prb.add_argument("--rdap-max", type=float)
    p_prb.add_argument("--cnnic-min", type=float)
    p_prb.add_argument("--cnnic-max", type=float)
    p_prb.add_argument("--max-retries", type=int, default=3)
    p_prb.add_argument("--max-cache-age-hours", type=float, default=24.0, help="本地缓存有效小时数，默认 24h")
    p_prb.add_argument("--force", action="store_true", help="忽略本地断点缓存强制重查")
    p_prb.add_argument("--limit", type=int, default=0, help="仅测试前 N 个域名")
    p_prb.add_argument("--export-csv", help="核验完成后直接导出有序结果 CSV 路径")
    p_prb.add_argument("--icp-file", help="配合导出 CSV 补全主办单位/备案号")
    p_prb.add_argument("--max-days", type=int, default=30, help="CSV 仅保留到期天数 <= max-days 的紧迫资产")
    p_prb.add_argument("--all-days", action="store_true", help="CSV 导出全部有效期限域名")
    p_prb.add_argument("--include-restricted", action="store_true", help="不排除 gov.cn/edu.cn")
    p_prb.set_defaults(func=cmd_probe_whois)

    # sync-whois
    p_syn = sub.add_parser("sync-whois", help="将 WHOIS 原件证据与观测批量上传至 Domain Hub")
    p_syn.add_argument("--input", help="直接读取 whois_results.jsonl；省略则自动读取 checkpoint 未上传记录")
    p_syn.add_argument("--checkpoint", help="SQLite WAL 断点库路径")
    p_syn.add_argument("--all-cached", action="store_true", help="重新上传 checkpoint 中全部终态记录（依赖服务端幂等去重）")
    p_syn.add_argument("--mode", choices=("auto", "authorized", "intake"), default="auto")
    p_syn.add_argument("--topic", default="WHOIS官方核验")
    p_syn.add_argument("--province", help="同 topic")
    p_syn.add_argument("--desc", default="")
    p_syn.add_argument("--source-kind", default="whois_verification")
    p_syn.add_argument("--client-batch-ref", help="幂等批次引用标识")
    p_syn.add_argument("--file-prefix", default="whois_evidence")
    p_syn.add_argument("--intake-delay", type=float)
    p_syn.add_argument("--no-wait", action="store_true")
    p_syn.set_defaults(func=cmd_sync_whois)

    # job-worker
    p_wrk = sub.add_parser("job-worker", help="单线程领取并执行 Hub 刷新队列任务 (/v1/jobs:claim)")
    p_wrk.add_argument("--providers", default="verisign_rdap,cnnic_whois,registry_rdap", help="允许领取的 provider 列表")
    p_wrk.add_argument("--socks5-proxy", help="可选单个 SOCKS5 代理")
    p_wrk.add_argument("--once", action="store_true", help="处理完一次领取即退出")
    p_wrk.add_argument("--max-jobs", type=int, default=0, help="最多处理任务数，0 为持续运行")
    p_wrk.add_argument("--idle-sleep", type=float, default=10.0, help="队列空时的轮询间隔秒数")
    p_wrk.set_defaults(func=cmd_job_worker)

    # export-csv
    p_exp = sub.add_parser("export-csv", help="按 GEMINI.md 紧迫程度升序导出 UTF-8-BOM 资产表")
    p_exp.add_argument("--output", required=True, help="目标 CSV 路径，例如 result/01_省份_过期与临期资产_有序结果.csv")
    p_exp.add_argument("--whois-file", help="本地 whois_results.jsonl 路径")
    p_exp.add_argument("--checkpoint", help="本地 whois_checkpoint.db 路径")
    p_exp.add_argument("--icp-file", help="关联本地 ICP 文件补全主办方和备案号")
    p_exp.add_argument("--from-hub", action="store_true", help="改为直接从 Hub /v1/candidates/search 拉取并导出")
    p_exp.add_argument("--evidence-scope", default="official", choices=("official", "historical", "all"))
    p_exp.add_argument("--allow-unverified", action="store_true", help="包含非官方核验记录")
    p_exp.add_argument("--province", help="筛选省份（--from-hub 时生效）")
    p_exp.add_argument("--tld", help="筛选后缀（--from-hub 时生效）")
    p_exp.add_argument("--limit", type=int, default=0, help="从 Hub 拉取上限（0=不限）")
    p_exp.add_argument("--max-days", type=int, default=30, help="仅保留 <= max-days 天到期或已过期/删除期资产")
    p_exp.add_argument("--all-days", action="store_true", help="不限制 30 天窗口，全部导出")
    p_exp.add_argument("--include-restricted", action="store_true", help="包含 gov.cn / edu.cn 等受限后缀")
    p_exp.set_defaults(func=cmd_export_csv)

    # enrich-icp-llm (+ alias icp-enrich-llm)
    for name in ("enrich-icp-llm", "icp-enrich-llm"):
        p_llm = sub.add_parser(name, help="可选：使用用户配置的 OpenAI 兼容联网检索 API 小批补充备案线索")
        p_llm.add_argument("--input", required=True, help="无备案域名的列表文件")
        p_llm.add_argument("--output", default="runtime_state/enriched_icp_llm.jsonl", help="输出 JSONL 路径")
        p_llm.add_argument("--api-url", help="覆盖 ICP_LLM_API_URL")
        p_llm.add_argument("--api-key", help="覆盖 ICP_LLM_API_KEY")
        p_llm.add_argument("--model", help="覆盖 ICP_LLM_MODEL")
        p_llm.add_argument("--batch-size", type=int, default=2, help="每次请求域名数（建议 1~3）")
        p_llm.add_argument("--delay", type=float, default=2.0, help="请求间隔秒数")
        p_llm.add_argument("--limit", type=int, default=0)
        p_llm.set_defaults(func=cmd_enrich_icp_llm)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_env_file(args.env_file)
    _setup_logging(args.verbose, args.log_file)
    try:
        return int(args.func(args))
    except HubClientError as err:
        print(err.format_for_user(), file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(f"[input_error] {err}\n建议下一步: 请确认文件路径是否正确后重新运行。", file=sys.stderr)
        return 2
    except ValueError as err:
        print(f"[input_error] {err}\n建议下一步: 请检查输入参数或数据格式是否合法。", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[已中断] 操作已安全中止，已完成的数据与断点均已保留。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
