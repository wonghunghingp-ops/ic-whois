"""Single-threaded Linux WHOIS & RDAP verification engine with SQLite resume and raw evidence packing.

Key engineering guarantees (zero threads, zero multi-proxy rotation pools):
1. Pure sequential loop with jittered per-protocol delays (`0.7-1.2s` RDAP, `1.4-2.2s` CNNIC 43)
2. Official endpoints only:
   - `.com` / `.net` -> `https://rdap.verisign.com/{tld}/v1/domain/{domain}`
   - `.cc` -> `https://tld-rdap.verisign.com/cc/v1/domain/{domain}`
   - `*.cn` -> `whois.cnnic.cn:43` (port 43 TCP, `http_status` omitted on both evidence & record)
   - Other TLDs -> IANA RDAP `dns.json` bootstrap cache (`registry_rdap`) -> `whois.iana.org:43` referral fallback
3. Anti-false-404 protection: timeouts, empty replies, HTTP 429/403/5xx, or WHOIS rate-limit banners
   always become `unavailable`/`error` — NEVER `not_found`.
4. Resumable SQLite WAL state + graceful SIGINT/SIGTERM handling + verbatim JSONL evidence output.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import signal
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .common import (
    DEFAULT_USER_AGENT,
    SHANGHAI_TZ,
    clean_id,
    clean_text,
    domain_shape,
    lifecycle,
    ms_iso_utc,
    normalize_domain,
    strip_empty,
    utc_now_iso_ms,
)
from .hub_client import ProxyConfig, build_url_opener, parse_proxy_url, socks5_connect

LOGGER = logging.getLogger("agent_workflow.whois")

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_CACHE_TTL_SEC = 86400

BUILTIN_RDAP_SERVERS: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "cc": "https://tld-rdap.verisign.com/cc/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "mobi": "https://rdap.identitydigital.services/rdap/",
    "pro": "https://rdap.identitydigital.services/rdap/",
    "io": "https://rdap.nic.io/",
    "ai": "https://rdap.nic.ai/",
    "co": "https://rdap.registry.co/",
    "me": "https://rdap.identitydigital.services/rdap/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "top": "https://rdap.zdnsgtld.com/top/",
    "vip": "https://rdap.nic.vip/",
    "club": "https://rdap.nic.club/",
    "tv": "https://rdap.nic.tv/",
    "uk": "https://rdap.nominet.uk/uk/",
}

RATE_LIMIT_KEYWORDS: tuple[str, ...] = (
    "too many",
    "rate limit",
    "exceeded",
    "try again later",
    "quota",
    "access denied",
    "blocked",
    "temporarily unavailable",
    "server is busy",
    "frequency",
    "connection refused",
    "请求过于频繁",
    "访问受限",
)

CNNIC_NOT_FOUND_MARKERS: tuple[str, ...] = (
    "no matching record",
    "the domain you requested is not exist",
    "does not exist",
    "not found",
)

GENERIC_NOT_FOUND_MARKERS: tuple[str, ...] = (
    "no match for",
    "not found",
    "no matching record",
    "no data found",
    "domain not found",
    "status: free",
    "status: available",
    "is free",
    "no entries found",
    "object does not exist",
)

BACKOFF_SCHEDULE_SEC: tuple[float, ...] = (5.0, 15.0, 35.0, 60.0)


@dataclass
class WhoisQueryConfig:
    rdap_delay_min: float = 0.7
    rdap_delay_max: float = 1.2
    cnnic_delay_min: float = 1.4
    cnnic_delay_max: float = 2.2
    timeout_sec: float = 20.0
    max_retries: int = 3
    socks5_proxy: str = ""
    bootstrap_cache_path: Path | None = None
    user_agent: str = DEFAULT_USER_AGENT


class WhoisCheckpointStore:
    """SQLite WAL store persisting per-domain WHOIS verification state for safe resume."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS whois_results (
                    domain TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    http_status INTEGER,
                    observed_at TEXT NOT NULL,
                    expiration_date TEXT,
                    creation_date TEXT,
                    registrar TEXT,
                    statuses_json TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    response_text TEXT NOT NULL,
                    response_sha256 TEXT NOT NULL,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def get_fresh(self, domain: str, *, max_age_hours: float = 24.0) -> dict[str, Any] | None:
        """Return cached terminal result (`success`/`not_found`) if within `max_age_hours`."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM whois_results WHERE domain=?", (domain,)).fetchone()
        if not row:
            return None
        if row["outcome"] not in ("success", "not_found"):
            return None
        if max_age_hours <= 0:
            return None
        obs = ms_iso_utc(row["observed_at"])
        if not obs:
            return None
        age_sec = time.time() - _iso_to_epoch(obs)
        if age_sec > max_age_hours * 3600.0:
            return None
        return _row_to_result(dict(row))

    def upsert(self, result: dict[str, Any], *, uploaded: bool = False) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO whois_results(
                    domain, provider, endpoint, outcome, http_status, observed_at,
                    expiration_date, creation_date, registrar, statuses_json, data_json,
                    response_text, response_sha256, uploaded, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    provider=excluded.provider,
                    endpoint=excluded.endpoint,
                    outcome=excluded.outcome,
                    http_status=excluded.http_status,
                    observed_at=excluded.observed_at,
                    expiration_date=excluded.expiration_date,
                    creation_date=excluded.creation_date,
                    registrar=excluded.registrar,
                    statuses_json=excluded.statuses_json,
                    data_json=excluded.data_json,
                    response_text=excluded.response_text,
                    response_sha256=excluded.response_sha256,
                    uploaded=CASE WHEN excluded.uploaded=1 THEN 1 ELSE 0 END,
                    updated_at=excluded.updated_at
                """,
                (
                    result["domain"],
                    result["provider"],
                    result["endpoint"],
                    result["outcome"],
                    result.get("http_status"),
                    result["observed_at"],
                    result.get("expiration_date") or "",
                    result.get("creation_date") or "",
                    result.get("registrar") or "",
                    json.dumps(result.get("statuses") or [], ensure_ascii=False),
                    json.dumps(result.get("data") or {}, ensure_ascii=False),
                    result.get("response_text") or "",
                    result.get("response_sha256") or "",
                    1 if uploaded else 0,
                    utc_now_iso_ms(),
                ),
            )

    def mark_uploaded(self, domains: list[str]) -> None:
        if not domains:
            return
        with self._connect() as conn:
            now_iso = utc_now_iso_ms()
            conn.executemany(
                "UPDATE whois_results SET uploaded=1, updated_at=? WHERE domain=?",
                [(now_iso, d) for d in domains],
            )

    def list_results(self, *, only_unuploaded: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM whois_results"
        if only_unuploaded:
            query += " WHERE uploaded=0 AND outcome IN ('success','not_found','partial')"
        query += " ORDER BY updated_at ASC"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [_row_to_result(dict(r)) for r in rows]


def _row_to_result(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": row["domain"],
        "provider": row["provider"],
        "endpoint": row["endpoint"],
        "outcome": row["outcome"],
        "http_status": row["http_status"],
        "observed_at": row["observed_at"],
        "expiration_date": row["expiration_date"] or None,
        "creation_date": row["creation_date"] or None,
        "registrar": row["registrar"] or None,
        "statuses": json.loads(row["statuses_json"] or "[]"),
        "data": json.loads(row["data_json"] or "{}"),
        "response_text": row["response_text"],
        "response_sha256": row["response_sha256"],
        "uploaded": bool(row["uploaded"]),
    }


def _iso_to_epoch(iso_str: str) -> float:
    from .common import parse_datetime_utc

    dt = parse_datetime_utc(iso_str)
    return dt.timestamp() if dt else 0.0


def parse_rdap_json(domain: str, raw_text: str, http_status: int | None) -> dict[str, Any]:
    """Parse Verisign/Registry RDAP JSON safely without false 404 misreporting."""
    try:
        obj = json.loads(raw_text)
    except Exception:
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "rdap_invalid_json",
        }

    if not isinstance(obj, dict):
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "rdap_non_object",
        }

    if http_status == 404:
        err_code = obj.get("errorCode")
        title = clean_text(obj.get("title")).lower()
        if err_code == 404 or "not found" in title:
            return {
                "outcome": "not_found",
                "expiration_date": None,
                "creation_date": None,
                "registrar": None,
                "statuses": [],
                "has_explicit_timezone": True,
            }
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "http_404_without_rdap_errorcode",
        }

    exp_dates: list[str] = []
    creation_date: str | None = None
    updated_date: str | None = None

    for ev in obj.get("events") or []:
        if not isinstance(ev, dict):
            continue
        action = clean_text(ev.get("eventAction")).lower()
        raw_dt = clean_text(ev.get("eventDate"))
        iso_dt = ms_iso_utc(raw_dt)
        if not iso_dt:
            continue
        if action == "expiration":
            exp_dates.append(iso_dt)
        elif action in ("registration", "registered"):
            creation_date = creation_date or iso_dt
        elif action in ("last changed", "last update of rdap database"):
            updated_date = updated_date or iso_dt

    statuses = [clean_text(s) for s in (obj.get("status") or []) if clean_text(s)]
    statuses = list(dict.fromkeys(statuses))

    registrar = _extract_rdap_registrar(obj.get("entities") or [])

    unique_exp = list(dict.fromkeys(exp_dates))
    conflicting = len(unique_exp) > 1
    expiration_date = unique_exp[0] if unique_exp else None
    outcome = "partial" if conflicting else ("success" if (expiration_date or statuses or registrar) else "partial")

    return {
        "outcome": outcome,
        "expiration_date": expiration_date,
        "all_expiration_dates": unique_exp if conflicting else [],
        "creation_date": creation_date,
        "updated_date": updated_date,
        "registrar": registrar,
        "statuses": statuses,
        "has_explicit_timezone": True,
        "conflicting_expirations": conflicting,
    }


def _extract_rdap_registrar(entities: list[Any]) -> str | None:
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [clean_text(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and clean_text(prop[0]).lower() == "fn":
                    fn = clean_text(prop[3])
                    if fn:
                        return fn
        handle = clean_text(ent.get("handle"))
        if handle:
            return handle
    return None


def parse_whois_text(domain: str, raw_text: str, *, is_cnnic: bool = False) -> dict[str, Any]:
    """Parse port-43 text WHOIS (CNNIC & generic registries) with strict rate-limit/not-found guards."""
    text = raw_text or ""
    lower = text.lower().strip()
    if not lower:
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "empty_whois_response",
        }

    # Check rate-limit / block BEFORE not_found!
    if any(kw in lower for kw in RATE_LIMIT_KEYWORDS):
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "whois_rate_limited",
        }

    has_domain_line = bool(re.search(r"(?im)^\s*domain name\s*:", text))
    not_found_markers = CNNIC_NOT_FOUND_MARKERS if is_cnnic else GENERIC_NOT_FOUND_MARKERS
    if not has_domain_line and any(m in lower for m in not_found_markers):
        return {
            "outcome": "not_found",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": True,
        }

    exp_raw = _first_whois_match(
        text,
        (
            r"(?im)^\s*Expiration Time\s*:\s*(.+)$",
            r"(?im)^\s*Registry Expiry Date\s*:\s*(.+)$",
            r"(?im)^\s*Registrar Registration Expiration Date\s*:\s*(.+)$",
            r"(?im)^\s*Expiry Date\s*:\s*(.+)$",
            r"(?im)^\s*Expires On\s*:\s*(.+)$",
            r"(?im)^\s*paid-till\s*:\s*(.+)$",
        ),
    )
    reg_raw = _first_whois_match(
        text,
        (
            r"(?im)^\s*Registration Time\s*:\s*(.+)$",
            r"(?im)^\s*Creation Date\s*:\s*(.+)$",
            r"(?im)^\s*Created On\s*:\s*(.+)$",
        ),
    )
    registrar = _first_whois_match(
        text,
        (
            r"(?im)^\s*Sponsoring Registrar\s*:\s*(.+)$",
            r"(?im)^\s*Registrar\s*:\s*(.+)$",
        ),
    )
    statuses = [
        re.sub(r"\s+(?:https?://\S+|\(.*\))\s*$", "", clean_text(m)).strip()
        for m in re.findall(r"(?im)^\s*(?:Domain Status|Status)\s*:\s*(.+)$", text)
        if clean_text(m)
    ]
    statuses = list(dict.fromkeys(s for s in statuses if s))

    has_explicit_tz = False
    if exp_raw:
        has_explicit_tz = bool(
            re.search(r"(?:Z|[+-]\d{2}:?\d{2}|\bUTC\b|\bGMT\b)", exp_raw, re.IGNORECASE)
        )

    naive_tz = SHANGHAI_TZ if is_cnnic else SHANGHAI_TZ
    exp_iso = ms_iso_utc(exp_raw, naive_tz=naive_tz) if exp_raw else None
    reg_iso = ms_iso_utc(reg_raw, naive_tz=naive_tz) if reg_raw else None

    if not exp_iso and not statuses and not registrar and not has_domain_line:
        return {
            "outcome": "unavailable",
            "expiration_date": None,
            "creation_date": None,
            "registrar": None,
            "statuses": [],
            "has_explicit_timezone": False,
            "error_note": "unrecognized_whois_payload",
        }

    return {
        "outcome": "success" if (exp_iso or statuses or registrar) else "partial",
        "expiration_date": exp_iso,
        "raw_expiration_date": exp_raw,
        "creation_date": reg_iso,
        "registrar": clean_text(registrar) or None,
        "statuses": statuses,
        "has_explicit_timezone": has_explicit_tz,
    }


def _first_whois_match(text: str, patterns: tuple[str, ...]) -> str | None:
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            val = clean_text(m.group(1))
            if val:
                return val
    return None


class SingleThreadWhoisEngine:
    """Strictly sequential WHOIS/RDAP client built for single-threaded Linux agents."""

    def __init__(self, config: WhoisQueryConfig | None = None, checkpoint: WhoisCheckpointStore | None = None):
        self.config = config or WhoisQueryConfig()
        self.proxy_cfg: ProxyConfig | None = parse_proxy_url(self.config.socks5_proxy)
        self.opener = build_url_opener(self.proxy_cfg)
        self.checkpoint = checkpoint
        self._stop_requested = False
        self._rdap_map: dict[str, str] | None = None
        self._extra_cooldown = 0.0

    def request_stop(self) -> None:
        self._stop_requested = True

    def _load_iana_rdap_map(self) -> dict[str, str]:
        if self._rdap_map is not None:
            return self._rdap_map

        merged = dict(BUILTIN_RDAP_SERVERS)
        cache_path = self.config.bootstrap_cache_path
        cached_obj: dict[str, Any] | None = None

        if cache_path and cache_path.is_file():
            age = time.time() - cache_path.stat().st_mtime
            if age <= BOOTSTRAP_CACHE_TTL_SEC:
                try:
                    cached_obj = json.loads(cache_path.read_text(encoding="utf-8"))
                except Exception:
                    cached_obj = None

        if cached_obj is None:
            try:
                req = urllib.request.Request(
                    IANA_BOOTSTRAP_URL,
                    method="GET",
                    headers={"User-Agent": self.config.user_agent, "Accept": "application/json"},
                )
                with self.opener.open(req, timeout=self.config.timeout_sec) as resp:
                    cached_obj = json.loads(resp.read().decode("utf-8"))
                if cache_path:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(cached_obj, ensure_ascii=False), encoding="utf-8")
            except Exception as exc:
                LOGGER.warning("Failed to fetch IANA RDAP dns.json bootstrap, using builtin fallback: %s", exc)
                if cache_path and cache_path.is_file():
                    try:
                        cached_obj = json.loads(cache_path.read_text(encoding="utf-8"))
                    except Exception:
                        cached_obj = None

        if isinstance(cached_obj, dict):
            for entry in cached_obj.get("services") or []:
                if not isinstance(entry, list) or len(entry) < 2:
                    continue
                tlds, urls = entry[0], entry[1]
                https_urls = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
                chosen = (https_urls or [u for u in urls if isinstance(u, str)])
                if not chosen:
                    continue
                base = chosen[0].rstrip("/") + "/"
                for tld in tlds:
                    if isinstance(tld, str):
                        merged.setdefault(tld.lower(), base)

        # Ensure official Verisign overrides stay authoritative
        merged["com"] = "https://rdap.verisign.com/com/v1/"
        merged["net"] = "https://rdap.verisign.com/net/v1/"
        merged["cc"] = "https://tld-rdap.verisign.com/cc/v1/"
        self._rdap_map = merged
        return merged

    def resolve_target(self, raw_domain: str) -> tuple[str, str, str, str]:
        """Return `(apex_domain, provider, protocol, endpoint_or_host)`."""
        info = domain_shape(raw_domain, reject_punycode=False)
        if not info["valid"] or not info["apex_domain"]:
            raise ValueError(f"非法域名无法查询 WHOIS: {raw_domain!r}")
        domain = str(info["apex_domain"])
        tld = domain.rsplit(".", 1)[-1].lower()

        if tld in ("com", "net"):
            return domain, "verisign_rdap", "rdap", f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
        if tld == "cc":
            return domain, "verisign_rdap", "rdap", f"https://tld-rdap.verisign.com/cc/v1/domain/{domain}"
        if tld == "cn":
            return domain, "cnnic_whois", "whois43", "whois.cnnic.cn:43"

        rdap_map = self._load_iana_rdap_map()
        base = rdap_map.get(tld)
        if base:
            return domain, "registry_rdap", "rdap", f"{base.rstrip('/')}/domain/{domain}"
        return domain, "registry_whois", "iana_referral", tld

    def query_domain(self, raw_domain: str, *, max_cache_age_hours: float = 24.0, force: bool = False) -> dict[str, Any]:
        """Query a single domain sequentially with checkpoint cache & rate-limit backoff."""
        domain = normalize_domain(raw_domain, collapse_subdomain=True, reject_punycode=False)
        if not domain:
            raise ValueError(f"域名无效，跳过 WHOIS 查询: {raw_domain!r}")

        if not force and self.checkpoint:
            cached = self.checkpoint.get_fresh(domain, max_age_hours=max_cache_age_hours)
            if cached is not None:
                cached["from_cache"] = True
                return cached

        domain, provider, protocol, target = self.resolve_target(domain)

        if protocol == "rdap":
            res = self._query_rdap_with_retry(domain, provider, target)
            self._sleep_between_queries(is_cnnic=False)
        elif protocol == "whois43":
            host, port_s = target.split(":", 1)
            res = self._query_whois43_with_retry(domain, provider, host, int(port_s), is_cnnic=True)
            self._sleep_between_queries(is_cnnic=True)
        else:
            refer_host = self._lookup_iana_whois_host(target)
            if not refer_host:
                res = _unavailable_result(
                    domain,
                    provider="registry_whois",
                    endpoint="whois.iana.org:43",
                    raw_text="",
                    http_status=None,
                    note="iana_no_whois_referral",
                )
            else:
                res = self._query_whois43_with_retry(domain, "registry_whois", refer_host, 43, is_cnnic=False)
            self._sleep_between_queries(is_cnnic=False)

        lc = lifecycle(res["outcome"], res.get("statuses"), res.get("expiration_date"), as_of=res["observed_at"])
        res["lifecycle"] = lc["lifecycle"]
        res["days_left"] = lc["days_left"]
        res["urgency"] = lc["urgency"]
        res["from_cache"] = False

        if self.checkpoint:
            self.checkpoint.upsert(res, uploaded=False)
        return res

    def query_batch(
        self,
        domains: list[str],
        *,
        max_cache_age_hours: float = 24.0,
        force: bool = False,
        progress_cb: Any = None,
    ) -> list[dict[str, Any]]:
        """Run strict single-threaded sequential WHOIS verification across domains with SIGINT support."""
        # Install clean SIGINT/SIGTERM handler only if running in main thread
        old_int = None
        old_term = None
        installed_signals = False
        try:
            old_int = signal.getsignal(signal.SIGINT)
            old_term = signal.getsignal(signal.SIGTERM)

            def _handle_sig(signum: int, _frame: Any) -> None:
                LOGGER.warning("收到停止信号 (%s)，完成当前单条查询并保存断点后退出...", signum)
                self._stop_requested = True

            signal.signal(signal.SIGINT, _handle_sig)
            signal.signal(signal.SIGTERM, _handle_sig)
            installed_signals = True
        except ValueError:
            pass

        unique_domains: list[str] = []
        seen: set[str] = set()
        for raw in domains:
            d = normalize_domain(raw, collapse_subdomain=True, reject_punycode=False)
            if d and d not in seen:
                seen.add(d)
                unique_domains.append(d)

        results: list[dict[str, Any]] = []
        try:
            for idx, domain in enumerate(unique_domains, start=1):
                if self._stop_requested:
                    break
                item = self.query_domain(domain, max_cache_age_hours=max_cache_age_hours, force=force)
                results.append(item)
                if progress_cb:
                    progress_cb(idx, len(unique_domains), item)
        finally:
            if installed_signals:
                try:
                    signal.signal(signal.SIGINT, old_int)
                    signal.signal(signal.SIGTERM, old_term)
                except Exception:
                    pass
        return results

    def _query_rdap_with_retry(self, domain: str, provider: str, endpoint: str) -> dict[str, Any]:
        last_raw = ""
        last_status: int | None = None
        last_note = "rdap_request_failed"

        for attempt in range(1, self.config.max_retries + 1):
            if self._stop_requested:
                break
            req = urllib.request.Request(
                endpoint,
                method="GET",
                headers={
                    "User-Agent": self.config.user_agent,
                    "Accept": "application/rdap+json, application/json",
                },
            )
            obs_at = utc_now_iso_ms()
            try:
                with self.opener.open(req, timeout=self.config.timeout_sec) as resp:
                    status = int(resp.status)
                    raw_text = resp.read().decode("utf-8", errors="replace")
                parsed = parse_rdap_json(domain, raw_text, status)
                if parsed["outcome"] in ("success", "partial"):
                    self._extra_cooldown = max(0.0, self._extra_cooldown * 0.5)
                    return _build_result(domain, provider, endpoint, status, obs_at, raw_text, parsed)
                last_raw, last_status, last_note = raw_text, status, parsed.get("error_note") or "rdap_partial"
            except urllib.error.HTTPError as exc:
                try:
                    status = int(exc.code)
                    raw_text = exc.read().decode("utf-8", errors="replace")
                finally:
                    exc.close()
                obs_at = utc_now_iso_ms()
                if status == 404:
                    parsed = parse_rdap_json(domain, raw_text, 404)
                    if parsed["outcome"] == "not_found":
                        self._extra_cooldown = max(0.0, self._extra_cooldown * 0.5)
                        return _build_result(domain, provider, endpoint, 404, obs_at, raw_text, parsed)
                    last_raw, last_status, last_note = raw_text, 404, "suspicious_404_not_rdap_json"
                elif status in (403, 429, 500, 502, 503, 504):
                    last_raw, last_status, last_note = raw_text, status, f"http_{status}"
                    self._extra_cooldown = min(5.0, self._extra_cooldown + 1.0)
                else:
                    return _unavailable_result(domain, provider, endpoint, raw_text, status, note=f"http_{status}", obs_at=obs_at)
            except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
                last_raw, last_status, last_note = "", None, str(exc)

            if attempt < self.config.max_retries and not self._stop_requested:
                wait_s = BACKOFF_SCHEDULE_SEC[min(attempt - 1, len(BACKOFF_SCHEDULE_SEC) - 1)] + random.uniform(0.3, 1.5)
                LOGGER.warning("RDAP retry %d/%d for %s (%s), waiting %.1fs", attempt, self.config.max_retries, domain, last_note, wait_s)
                time.sleep(wait_s)

        return _unavailable_result(domain, provider, endpoint, last_raw, last_status, note=last_note)

    def _query_whois43_with_retry(
        self,
        domain: str,
        provider: str,
        host: str,
        port: int,
        *,
        is_cnnic: bool,
    ) -> dict[str, Any]:
        endpoint = f"{host}:{port}"
        last_raw = ""
        last_note = "whois_failed"

        for attempt in range(1, self.config.max_retries + 1):
            if self._stop_requested:
                break
            obs_at = utc_now_iso_ms()
            try:
                raw_text = self._tcp_whois_query(host, port, domain)
                parsed = parse_whois_text(domain, raw_text, is_cnnic=is_cnnic)
                if parsed["outcome"] in ("success", "not_found", "partial"):
                    self._extra_cooldown = max(0.0, self._extra_cooldown * 0.5)
                    # Note: port 43 has no HTTP status -> pass None cleanly
                    return _build_result(domain, provider, endpoint, None, obs_at, raw_text, parsed)
                last_raw = raw_text
                last_note = parsed.get("error_note") or "whois_rate_limited"
                self._extra_cooldown = min(6.0, self._extra_cooldown + 1.2)
            except (TimeoutError, socket.timeout, OSError, EOFError, PermissionError) as exc:
                last_raw = ""
                last_note = str(exc)
                self._extra_cooldown = min(6.0, self._extra_cooldown + 1.0)

            if attempt < self.config.max_retries and not self._stop_requested:
                wait_s = BACKOFF_SCHEDULE_SEC[min(attempt - 1, len(BACKOFF_SCHEDULE_SEC) - 1)] + random.uniform(0.5, 2.0)
                LOGGER.warning("WHOIS-43 retry %d/%d for %s (%s), waiting %.1fs", attempt, self.config.max_retries, domain, last_note, wait_s)
                time.sleep(wait_s)

        return _unavailable_result(domain, provider, endpoint, last_raw, None, note=last_note)

    def _tcp_whois_query(self, host: str, port: int, query: str) -> str:
        if self.proxy_cfg and self.proxy_cfg.scheme in ("socks5", "socks5h"):
            sock = socks5_connect(self.proxy_cfg, host, port, timeout=self.config.timeout_sec)
        else:
            sock = socket.create_connection((host, port), timeout=self.config.timeout_sec)
        sock.settimeout(self.config.timeout_sec)
        try:
            sock.sendall((query + "\r\n").encode("ascii"))
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="replace")
        finally:
            sock.close()

    def _lookup_iana_whois_host(self, tld: str) -> str | None:
        try:
            raw = self._tcp_whois_query("whois.iana.org", 43, tld)
            m = re.search(r"(?im)^\s*refer\s*:\s*([A-Za-z0-9.-]+)\s*$", raw)
            return clean_text(m.group(1)) if m else None
        except Exception as exc:
            LOGGER.warning("IANA referral lookup failed for %s: %s", tld, exc)
            return None

    def _sleep_between_queries(self, *, is_cnnic: bool) -> None:
        if self._stop_requested:
            return
        if is_cnnic:
            lo, hi = self.config.cnnic_delay_min, self.config.cnnic_delay_max
        else:
            lo, hi = self.config.rdap_delay_min, self.config.rdap_delay_max
        base = random.uniform(max(0.0, lo), max(lo, hi)) + self._extra_cooldown
        if base > 0:
            time.sleep(base)


def _build_result(
    domain: str,
    provider: str,
    endpoint: str,
    http_status: int | None,
    obs_at: str,
    raw_text: str,
    parsed: dict[str, Any],
) -> dict[str, Any]:
    data_payload = strip_empty(
        {
            "expiration_date": parsed.get("expiration_date"),
            "creation_date": parsed.get("creation_date"),
            "registrar": parsed.get("registrar"),
            "statuses": parsed.get("statuses") or [],
            "raw_expiration_date": parsed.get("raw_expiration_date"),
            "all_expiration_dates": parsed.get("all_expiration_dates") or None,
            "conflicting_expirations": True if parsed.get("conflicting_expirations") else None,
            "expiration_timezone_explicit": parsed.get("has_explicit_timezone"),
        }
    )
    sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return {
        "domain": domain,
        "provider": provider,
        "endpoint": endpoint,
        "outcome": parsed["outcome"],
        "http_status": http_status,
        "observed_at": obs_at,
        "expiration_date": parsed.get("expiration_date"),
        "creation_date": parsed.get("creation_date"),
        "registrar": parsed.get("registrar"),
        "statuses": parsed.get("statuses") or [],
        "has_explicit_timezone": bool(parsed.get("has_explicit_timezone")),
        "data": data_payload,
        "response_text": raw_text,
        "response_sha256": sha,
    }


def _unavailable_result(
    domain: str,
    provider: str,
    endpoint: str,
    raw_text: str,
    http_status: int | None,
    *,
    note: str,
    obs_at: str | None = None,
) -> dict[str, Any]:
    obs = obs_at or utc_now_iso_ms()
    sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return {
        "domain": domain,
        "provider": provider,
        "endpoint": endpoint,
        "outcome": "unavailable",
        "http_status": http_status,
        "observed_at": obs,
        "expiration_date": None,
        "creation_date": None,
        "registrar": None,
        "statuses": [],
        "has_explicit_timezone": False,
        "data": {"error_note": note},
        "response_text": raw_text,
        "response_sha256": sha,
    }


def to_hub_evidence_items(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build exact `(observation, evidence_entry)` bundles for `HubClient.upload_evidence_jsonl_and_observations`."""
    bundles: list[dict[str, Any]] = []
    for res in results:
        domain = res["domain"]
        provider = res["provider"]
        endpoint = res["endpoint"]
        obs_at = ms_iso_utc(res["observed_at"]) or utc_now_iso_ms()
        raw_text = res.get("response_text") or ""
        sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        http_status = res.get("http_status")

        evidence_entry: dict[str, Any] = {
            "endpoint": endpoint,
            "observed_at": obs_at,
            "response_text": raw_text,
        }
        if http_status is not None:
            evidence_entry["http_status"] = int(http_status)

        ev_meta: dict[str, Any] = {
            "endpoint": endpoint,
            "response_sha256": sha,
        }
        if http_status is not None:
            ev_meta["http_status"] = int(http_status)

        compact_ts = re.sub(r"[^0-9]", "", obs_at)[:14]
        event_id = clean_id(f"whois_{provider}_{domain}_{compact_ts}_{sha[:10]}")

        observation: dict[str, Any] = {
            "event_id": event_id,
            "domain": domain,
            "kind": "registration",
            "provider": provider,
            "observed_at": obs_at,
            "outcome": res["outcome"],
            "data": res.get("data") or {},
            "evidence": ev_meta,
            "parser_version": "agent-workflow/2.0",
        }
        bundles.append({"observation": observation, "evidence_entry": evidence_entry})
    return bundles
