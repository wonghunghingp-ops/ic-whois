"""Single-threaded ICP snapshot ingestion, hygiene normalization, 666/665 prioritization, and optional LLM enrichment.

Encodes practical lessons from province ICP collection:
- Multi-encoding (UTF-8-SIG, UTF-8, GB18030, GBK) and multi-format (CSV, TSV, TXT, JSON, JSONL) support
- Pure ASCII domain normalization (drops IPs, non-ASCII / Chinese IDNs, URL paths/ports, leading www.)
- Explicit 666 website sub-license (`号-1`) vs 665 main-only classification & priority ordering (no blind -1 probing)
- Province normalization with license-prefix inference (`湘ICP备...` -> `湖南省`)
- Pre-deduplication by `icp_fact_hash` + deterministic `event_id` generation for Hub idempotency
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .common import (
    DEFAULT_USER_AGENT,
    clean_date_only,
    clean_id,
    clean_text,
    domain_shape,
    has_non_ascii,
    icp_fact_hash,
    is_ip_address,
    normalize_domain,
    normalize_province,
    service_subid_flag,
    strip_empty,
    utc_now_iso_ms,
)

LOGGER = logging.getLogger("agent_workflow.icp")

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "domain": ("domain", "domain_name", "域名", "主域名", "网站域名", "url", "host", "site", "website", "ym", "yuming"),
    "subject": ("subject", "unit_name", "unit", "organizer", "company", "dwmc", "主办单位名称", "主办单位", "备案主体", "单位名称", "公司名称", "企业名称"),
    "subject_type": ("subject_type", "nature", "entity_type", "dwlx", "单位性质", "主体性质", "性质"),
    "main_license": ("main_license", "main_licence", "baxh", "主体备案号", "主备案号", "备案号", "icp_license"),
    "service_license": ("service_license", "service_licence", "wz_baxh", "网站备案号", "服务备案号", "子备案号"),
    "province": ("province", "prov", "sf", "省份", "省", "所属省份", "地区", "icp_province"),
    "filed_on": ("filed_on", "first_filed_on", "scbasj", "首次备案日期", "首次备案时间", "首次备案", "核准日期"),
    "updated_on": ("updated_on", "updated", "shsj", "审核时间", "审核日期", "更新日期", "更新时间", "最近审核时间"),
    "sheet": ("sheet", "source", "来源", "备注"),
}


@dataclass
class IcpCleanStats:
    total_rows: int = 0
    accepted_rows: int = 0
    unique_domains: int = 0
    count_666_sublicense: int = 0
    count_665_mainonly: int = 0
    skipped_empty: int = 0
    skipped_ip: int = 0
    skipped_non_ascii: int = 0
    skipped_invalid_domain: int = 0
    deduped_facts: int = 0
    skipped_665_filtered: int = 0
    detected_encoding: str = "utf-8"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "accepted_rows": self.accepted_rows,
            "unique_domains": self.unique_domains,
            "count_666_sublicense": self.count_666_sublicense,
            "count_665_mainonly": self.count_665_mainonly,
            "skipped_empty": self.skipped_empty,
            "skipped_ip": self.skipped_ip,
            "skipped_non_ascii": self.skipped_non_ascii,
            "skipped_invalid_domain": self.skipped_invalid_domain,
            "deduped_facts": self.deduped_facts,
            "skipped_665_filtered": self.skipped_665_filtered,
            "detected_encoding": self.detected_encoding,
            "warnings": self.warnings,
        }


def decode_text_auto(raw_bytes: bytes) -> tuple[str, str]:
    """Decode CSV/TXT bytes gracefully across UTF-8-SIG, UTF-8, GB18030, GBK."""
    for enc in ("utf-8-sig", "utf-8", "gb18030", "gbk"):
        try:
            return raw_bytes.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace"), "utf-8-replace"


def _resolve_column_map(headers: list[str]) -> dict[str, str]:
    norm_to_orig: dict[str, str] = {}
    for h in headers:
        key = clean_text(h).lower().replace(" ", "").replace("-", "_")
        if key:
            norm_to_orig[key] = h
            norm_to_orig[clean_text(h)] = h

    mapping: dict[str, str] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            alias_norm = alias.lower().replace(" ", "").replace("-", "_")
            if alias in norm_to_orig:
                mapping[canonical] = norm_to_orig[alias]
                break
            if alias_norm in norm_to_orig:
                mapping[canonical] = norm_to_orig[alias_norm]
                break
    return mapping


def load_raw_rows(input_path: Path | str) -> tuple[list[dict[str, Any]], str]:
    """Read raw ICP snapshot from CSV, TSV, TXT, JSON, or JSONL."""
    path = Path(input_path)
    if not path.is_file():
        raise FileNotFoundError(f"输入文件不存在: {path}")

    raw_bytes = path.read_bytes()
    text, encoding = decode_text_auto(raw_bytes)
    suffix = path.suffix.lower()

    if suffix == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("records", "items", "data", "rows", "domains"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list):
            raise ValueError("JSON 文件顶层必须是数组或包含 records/items/data 数组")
        rows: list[dict[str, Any]] = []
        for idx, item in enumerate(data, start=1):
            if isinstance(item, str):
                rows.append({"domain": item, "_row_number": idx})
            elif isinstance(item, dict):
                r = dict(item)
                r.setdefault("_row_number", idx)
                rows.append(r)
        return rows, encoding

    if suffix in (".jsonl", ".ndjson"):
        rows = []
        for idx, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            obj = json.loads(stripped)
            if isinstance(obj, str):
                rows.append({"domain": obj, "_row_number": idx})
            elif isinstance(obj, dict):
                r = dict(obj)
                r.setdefault("_row_number", idx)
                rows.append(r)
        return rows, encoding

    # TXT line list or tabular CSV/TSV
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return [], encoding

    if suffix == ".txt" and ("," not in lines[0] and "\t" not in lines[0]):
        return [{"domain": ln.strip(), "_row_number": idx} for idx, ln in enumerate(lines, start=1)], encoding

    sample = "\n".join(lines[:10])
    delimiter = "\t" if sample.count("\t") > sample.count(",") else ","
    reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delimiter)
    if not reader.fieldnames:
        return [], encoding

    col_map = _resolve_column_map(list(reader.fieldnames))
    if "domain" not in col_map and suffix == ".txt":
        return [{"domain": ln.strip(), "_row_number": idx} for idx, ln in enumerate(lines, start=1)], encoding

    rows = []
    for idx, row in enumerate(reader, start=2):
        mapped: dict[str, Any] = {"_row_number": idx}
        if col_map:
            for canonical, orig_col in col_map.items():
                if orig_col in row:
                    mapped[canonical] = row[orig_col]
            # Fallback if table had extra unknown domain-like first column
            if "domain" not in mapped and reader.fieldnames:
                mapped["domain"] = row.get(reader.fieldnames[0], "")
        else:
            mapped.update(row)
        rows.append(mapped)
    return rows, encoding


def clean_icp_file(
    input_path: Path | str,
    *,
    require_666: bool = False,
    collapse_subdomain: bool = True,
    dedup_mode: str = "fact",
    default_province: str = "",
) -> tuple[list[dict[str, Any]], IcpCleanStats]:
    """Normalize, validate, deduplicate, and prioritize ICP records (666 before 665).

    `dedup_mode`:
      - `"fact"`: keep distinct `(domain, subject, main_license, service_license, filed_on, updated_on)` facts
      - `"domain"`: keep single best row per normalized domain (preferring 666 sub-license & newer dates)
    """
    raw_rows, encoding = load_raw_rows(input_path)
    stats = IcpCleanStats(total_rows=len(raw_rows), detected_encoding=encoding)

    seen_facts: set[str] = set()
    by_domain_best: dict[str, dict[str, Any]] = {}
    cleaned_list: list[dict[str, Any]] = []

    for row in raw_rows:
        raw_domain = clean_text(
            row.get("domain") or row.get("域名") or row.get("domain_name") or row.get("url") or row.get("host")
        )
        if not raw_domain:
            stats.skipped_empty += 1
            continue
        if is_ip_address(raw_domain):
            stats.skipped_ip += 1
            continue
        if has_non_ascii(raw_domain):
            stats.skipped_non_ascii += 1
            continue

        shape = domain_shape(raw_domain, reject_punycode=True)
        domain = shape["apex_domain"] if collapse_subdomain else shape["host"]
        if not shape["valid"] or not domain:
            # Distinguish IP embedded in URL like http://101.227.52.182/
            stripped_url = re.sub(r"^https?://", "", raw_domain, flags=re.I).split("/", 1)[0].split(":", 1)[0]
            if is_ip_address(stripped_url):
                stats.skipped_ip += 1
            else:
                stats.skipped_invalid_domain += 1
            continue

        subject = clean_text(row.get("subject") or row.get("unit_name") or row.get("主办单位名称"))
        subject_type = clean_text(row.get("subject_type") or row.get("nature") or row.get("单位性质"))
        main_lic = clean_text(row.get("main_license") or row.get("main_licence") or row.get("主体备案号"))
        svc_lic = clean_text(row.get("service_license") or row.get("service_licence") or row.get("网站备案号"))
        province = normalize_province(row.get("province") or row.get("省份") or default_province, main_lic, svc_lic)
        filed_on = clean_date_only(row.get("filed_on") or row.get("首次备案日期"))
        updated_on = clean_date_only(row.get("updated_on") or row.get("updated") or row.get("审核时间"))
        subid_flag = service_subid_flag(svc_lic, main_lic)
        sheet = clean_text(row.get("sheet") or row.get("source"))
        row_num = int(row.get("_row_number") or row.get("row_number") or 0) or None

        if require_666 and subid_flag != 1:
            stats.skipped_665_filtered += 1
            continue

        fhash = icp_fact_hash(domain, subject, main_lic, svc_lic, filed_on, updated_on)
        if fhash in seen_facts:
            stats.deduped_facts += 1
            continue
        seen_facts.add(fhash)

        record = {
            "domain": domain,
            "original_host": shape["host"],
            "domain_was_collapsed": shape["host"] != domain,
            "is_restricted_suffix": bool(shape["is_restricted"]),
            "subject": subject,
            "subject_type": subject_type,
            "main_license": main_lic,
            "service_license": svc_lic,
            "province": province,
            "filed_on": filed_on or "",
            "updated_on": updated_on or "",
            "has_service_subid": subid_flag,
            "record_tier": "666_website_sublicense" if subid_flag == 1 else "665_main_or_bare",
            "fact_hash": fhash,
            "sheet": sheet,
            "row_number": row_num,
        }

        if dedup_mode == "domain":
            existing = by_domain_best.get(domain)
            if existing is not None:
                if _rank_icp_record(record) > _rank_icp_record(existing):
                    by_domain_best[domain] = record
                stats.deduped_facts += 1
                continue
            by_domain_best[domain] = record
        else:
            cleaned_list.append(record)

    if dedup_mode == "domain":
        cleaned_list = list(by_domain_best.values())

    # Sort strictly: newest updated_on first, then 666 website sub-licenses before 665 main-only
    cleaned_list.sort(key=lambda r: (r["updated_on"] or "0000-00-00", r["domain"]), reverse=True)
    cleaned_list.sort(
        key=lambda r: (
            0 if r["has_service_subid"] == 1 else 1,
            0 if (r["subject"] and r["main_license"]) else 1,
        )
    )

    stats.accepted_rows = len(cleaned_list)
    stats.unique_domains = len({r["domain"] for r in cleaned_list})
    stats.count_666_sublicense = sum(1 for r in cleaned_list if r["has_service_subid"] == 1)
    stats.count_665_mainonly = stats.accepted_rows - stats.count_666_sublicense

    if stats.total_rows > 0 and stats.accepted_rows == 0:
        stats.warnings.append("未能提取到任何合法纯 ASCII 域名，请检查源文件列名或内容是否全为 IP / 汉字域名。")
    if stats.count_665_mainonly > stats.count_666_sublicense and stats.accepted_rows >= 5:
        stats.warnings.append("本批数据中 665 纯主体无分号记录偏多，可能包含 APP/小程序或已注销主体，建议后续 WHOIS 核验时优先跑 666 记录。")

    return cleaned_list, stats


def _rank_icp_record(r: dict[str, Any]) -> tuple[int, int, int, str]:
    completeness = sum(1 for k in ("subject", "main_license", "service_license", "province", "filed_on", "updated_on") if r.get(k))
    return (int(r.get("has_service_subid") or 0), completeness, 1 if r.get("service_license") else 0, str(r.get("updated_on") or ""))


def to_intake_records(cleaned_rows: list[dict[str, Any]], *, observed_at: str | None = None) -> list[dict[str, Any]]:
    """Build strict Plan A `/v1/intake` payloads from cleaned ICP rows."""
    obs = observed_at or utc_now_iso_ms()
    records: list[dict[str, Any]] = []
    for row in cleaned_rows:
        icp_obj = strip_empty(
            {
                "subject": row.get("subject"),
                "subject_type": row.get("subject_type"),
                "main_license": row.get("main_license"),
                "service_license": row.get("service_license"),
                "province": row.get("province"),
                "filed_on": row.get("filed_on") or None,
                "updated_on": row.get("updated_on") or None,
            }
        )
        if not any(icp_obj.get(k) for k in ("subject", "main_license", "service_license")):
            continue
        item: dict[str, Any] = {
            "domain": row["domain"],
            "icp": icp_obj,
            "observed_at": obs,
        }
        if row.get("sheet"):
            item["sheet"] = clean_text(row["sheet"])[:500]
        if row.get("row_number"):
            item["row_number"] = int(row["row_number"])
        records.append(item)
    return records


def to_authorized_icp_observations(
    cleaned_rows: list[dict[str, Any]],
    *,
    source_file_id: str | None = None,
    provider: str = "miit_snapshot",
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Build Plan B `POST /v1/observations:batch` `kind='icp'` records with deterministic event_ids."""
    obs = observed_at or utc_now_iso_ms()
    records: list[dict[str, Any]] = []
    for row in cleaned_rows:
        data_obj = strip_empty(
            {
                "subject": row.get("subject"),
                "subject_type": row.get("subject_type"),
                "main_license": row.get("main_license"),
                "service_license": row.get("service_license"),
                "province": row.get("province"),
                "filed_on": row.get("filed_on") or None,
                "updated_on": row.get("updated_on") or None,
                "has_service_subid": row.get("has_service_subid"),
            }
        )
        if not any(data_obj.get(k) for k in ("subject", "main_license", "service_license")):
            continue
        event_id = clean_id(f"icp_{row['fact_hash'][:32]}")
        rec: dict[str, Any] = {
            "event_id": event_id,
            "domain": row["domain"],
            "kind": "icp",
            "provider": provider,
            "observed_at": obs,
            "outcome": "success",
            "data": data_obj,
        }
        if source_file_id:
            ref: dict[str, Any] = {"file_id": clean_id(source_file_id)}
            if row.get("row_number") and int(row["row_number"]) > 0:
                ref["row_number"] = int(row["row_number"])
            rec["source_refs"] = [ref]
        records.append(rec)
    return records


# ----------------------------------------------------------------------
# Optional User-Configured OpenAI-Compatible Web Search ICP Enrichment
# ----------------------------------------------------------------------

_CITATION_RE = re.compile(r"\[(?:citation:)?\d+\]")


def strip_llm_artifacts(text: str) -> str:
    """Clean markdown code fences and web search `[citation:N]` noise from LLM text."""
    cleaned = _CITATION_RE.sub("", clean_text(text)).strip()
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL | re.IGNORECASE)
    if fence:
        cleaned = fence.group(1).strip()
    return cleaned


def enrich_icp_with_llm(
    domains: list[str],
    *,
    api_url: str,
    api_key: str,
    model: str = "glm-4-flash",
    batch_size: int = 2,
    delay_sec: float = 2.0,
    timeout_sec: float = 45.0,
) -> list[dict[str, Any]]:
    """Sequentially enrich domains without official ICP using a user-provided OpenAI-compatible search API.

    Follows empirical constraints:
    - Strict single-threaded small batch (`1..3` domains per call) to avoid search timeouts
    - Strips `[citation:N]` tags and normalizes province / license format
    - Emits clean records tagged `provider='llm_web_search'` (never mislabeled as official MIIT proof)
    """
    url = clean_text(api_url)
    key = clean_text(api_key)
    if not url or not key:
        raise ValueError("尚未配置 ICP_LLM_API_URL 或 ICP_LLM_API_KEY，无法运行联网补充。")

    safe_batch = max(1, min(3, int(batch_size)))
    norm_domains = [d for d in (normalize_domain(x) for x in domains) if d]
    results: list[dict[str, Any]] = []

    for idx in range(0, len(norm_domains), safe_batch):
        chunk = norm_domains[idx : idx + safe_batch]
        prompt = (
            "请查询以下中国网站域名的公开 ICP 备案信息，严格返回 JSON 数组（不要解释文字）。\n"
            "每个元素包含字段：domain, subject(主办单位), subject_type(单位性质), "
            "main_license(主体备案号), service_license(网站备案号), province(省份), filed_on(YYYY-MM-DD或空)。\n"
            "若未查到备案信息，subject 等填空字符串。\n"
            f"域名列表: {json.dumps(chunk, ensure_ascii=False)}"
        )
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "User-Agent": DEFAULT_USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                resp_obj = json.loads(resp.read().decode("utf-8"))
            content = (
                resp_obj.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "[]")
            )
            cleaned_json = strip_llm_artifacts(content)
            parsed = json.loads(cleaned_json)
            if isinstance(parsed, dict):
                parsed = [parsed]
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    dom = normalize_domain(item.get("domain"))
                    if not dom:
                        continue
                    main_lic = strip_llm_artifacts(item.get("main_license") or "")
                    svc_lic = strip_llm_artifacts(item.get("service_license") or "")
                    subject = strip_llm_artifacts(item.get("subject") or "")
                    if not any((subject, main_lic, svc_lic)):
                        continue
                    prov = normalize_province(strip_llm_artifacts(item.get("province") or ""), main_lic, svc_lic)
                    filed = clean_date_only(item.get("filed_on")) or ""
                    results.append(
                        {
                            "domain": dom,
                            "subject": subject,
                            "subject_type": strip_llm_artifacts(item.get("subject_type") or ""),
                            "main_license": main_lic,
                            "service_license": svc_lic,
                            "province": prov,
                            "filed_on": filed,
                            "updated_on": "",
                            "has_service_subid": service_subid_flag(svc_lic, main_lic),
                            "fact_hash": icp_fact_hash(dom, subject, main_lic, svc_lic, filed, ""),
                            "sheet": "llm_web_search",
                            "row_number": None,
                        }
                    )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, IndexError) as exc:
            LOGGER.warning("LLM ICP enrich chunk %s failed: %s", chunk, exc)

        if idx + safe_batch < len(norm_domains) and delay_sec > 0:
            time.sleep(float(delay_sec))

    return results
