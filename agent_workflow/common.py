"""Shared normalization, hashing, lifecycle calculation, and Linux-safe I/O helpers.

Designed to stay strictly aligned with Domain Hub v2 (`src/core.ts`,
`src/verification.ts`, `src/intake.ts`) and workspace archival rules (`GEMINI.md`).
Pure Python 3 standard library only (>= 3.9).
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_USER_AGENT = (
    "agent-workflow/2.0 (searchold-domain-hub-client; "
    "+https://github.com/wonghunghingp-ops/ic-whois)"
)

SHANGHAI_TZ = timezone(timedelta(hours=8))

ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TLD_RE = re.compile(r"^[a-z]{2,24}$")
SUB_LICENSE_RE = re.compile(r"(?:号[-_]\d+|-\d{1,4})\s*$")

ARCHIVED_CSV_HEADERS = [
    "domain",
    "matched_type",
    "expiration_date",
    "days_left",
    "source",
    "unit_name",
    "service_licence",
    "main_licence",
    "nature",
    "updated",
]

# Complete Chinese 2nd-level (.cn) and common international 2nd-level suffixes
SECOND_LEVEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # China national & provincial .cn
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "ac.cn",
        "mil.cn",
        "bj.cn",
        "sh.cn",
        "tj.cn",
        "cq.cn",
        "he.cn",
        "sx.cn",
        "nm.cn",
        "ln.cn",
        "jl.cn",
        "hl.cn",
        "js.cn",
        "zj.cn",
        "ah.cn",
        "fj.cn",
        "jx.cn",
        "sd.cn",
        "ha.cn",
        "hb.cn",
        "hn.cn",
        "gd.cn",
        "gx.cn",
        "hi.cn",
        "sc.cn",
        "gz.cn",
        "yn.cn",
        "xz.cn",
        "sn.cn",
        "gs.cn",
        "qh.cn",
        "nx.cn",
        "xj.cn",
        "tw.cn",
        "hk.cn",
        "mo.cn",
        # HK / TW / MO
        "com.hk",
        "net.hk",
        "org.hk",
        "edu.hk",
        "gov.hk",
        "idv.hk",
        "com.tw",
        "net.tw",
        "org.tw",
        "edu.tw",
        "gov.tw",
        "idv.tw",
        "com.mo",
        "net.mo",
        "org.mo",
        "edu.mo",
        "gov.mo",
        # Global common ccTLD / SLD
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "net.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "ed.jp",
        "gr.jp",
        "lg.jp",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "com.sg",
        "net.sg",
        "org.sg",
        "edu.sg",
        "gov.sg",
        "com.my",
        "net.my",
        "org.my",
        "edu.my",
        "gov.my",
        "co.kr",
        "or.kr",
        "ne.kr",
        "re.kr",
        "pe.kr",
        "go.kr",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "com.ru",
        "net.ru",
        "org.ru",
        "pp.ru",
        "ru.net",
        "co.nz",
        "net.nz",
        "org.nz",
        "co.in",
        "net.in",
        "org.in",
        "gen.in",
        "firm.in",
        "ind.in",
        "co.id",
        "or.id",
        "web.id",
        "my.id",
        "sch.id",
        "ac.id",
        "co.th",
        "in.th",
        "or.th",
        "ac.th",
        "go.th",
        "com.vn",
        "net.vn",
        "org.vn",
        "edu.vn",
        "gov.vn",
        "com.ph",
        "net.ph",
        "org.ph",
        "com.tr",
        "net.tr",
        "org.tr",
        "com.mx",
        "org.mx",
        "com.ar",
        "com.co",
        "com.ua",
        "net.ua",
        "org.ua",
        "in.ua",
        "co.za",
        "org.za",
        "eu.org",
        "us.com",
        "uk.com",
        "cn.com",
        "jpn.com",
        "de.com",
        "za.com",
        "com.es",
        "nom.es",
        "org.es",
        "co.il",
        "org.il",
        "com.sa",
        "com.eg",
        "com.pk",
        "com.bd",
        "com.np",
        "com.lk",
    }
)

RESTRICTED_SUFFIXES: tuple[str, ...] = (
    "gov.cn",
    "edu.cn",
    "mil.cn",
    "gov.hk",
    "edu.hk",
    "gov.tw",
    "edu.tw",
    "gov.uk",
    "ac.uk",
    "gov.au",
    "edu.au",
    "gov",
    "edu",
    "mil",
)

PROVINCE_MAP: dict[str, str] = {
    "京": "北京市",
    "北京": "北京市",
    "北京市": "北京市",
    "津": "天津市",
    "天津": "天津市",
    "天津市": "天津市",
    "冀": "河北省",
    "河北": "河北省",
    "河北省": "河北省",
    "晋": "山西省",
    "山西": "山西省",
    "山西省": "山西省",
    "蒙": "内蒙古自治区",
    "内蒙古": "内蒙古自治区",
    "内蒙古自治区": "内蒙古自治区",
    "辽": "辽宁省",
    "辽宁": "辽宁省",
    "辽宁省": "辽宁省",
    "吉": "吉林省",
    "吉林": "吉林省",
    "吉林省": "吉林省",
    "黑": "黑龙江省",
    "黑龙江": "黑龙江省",
    "黑龙江省": "黑龙江省",
    "沪": "上海市",
    "上海": "上海市",
    "上海市": "上海市",
    "苏": "江苏省",
    "江苏": "江苏省",
    "江苏省": "江苏省",
    "浙": "浙江省",
    "浙江": "浙江省",
    "浙江省": "浙江省",
    "皖": "安徽省",
    "安徽": "安徽省",
    "安徽省": "安徽省",
    "闽": "福建省",
    "福建": "福建省",
    "福建省": "福建省",
    "赣": "江西省",
    "江西": "江西省",
    "江西省": "江西省",
    "鲁": "山东省",
    "山东": "山东省",
    "山东省": "山东省",
    "豫": "河南省",
    "河南": "河南省",
    "河南省": "河南省",
    "鄂": "湖北省",
    "湖北": "湖北省",
    "湖北省": "湖北省",
    "湘": "湖南省",
    "湖南": "湖南省",
    "湖南省": "湖南省",
    "粤": "广东省",
    "广东": "广东省",
    "广东省": "广东省",
    "桂": "广西壮族自治区",
    "广西": "广西壮族自治区",
    "广西壮族自治区": "广西壮族自治区",
    "琼": "海南省",
    "海南": "海南省",
    "海南省": "海南省",
    "渝": "重庆市",
    "重庆": "重庆市",
    "重庆市": "重庆市",
    "蜀": "四川省",
    "川": "四川省",
    "四川": "四川省",
    "四川省": "四川省",
    "黔": "贵州省",
    "贵": "贵州省",
    "贵州": "贵州省",
    "贵州省": "贵州省",
    "滇": "云南省",
    "云": "云南省",
    "云南": "云南省",
    "云南省": "云南省",
    "藏": "西藏自治区",
    "西藏": "西藏自治区",
    "西藏自治区": "西藏自治区",
    "陕": "陕西省",
    "秦": "陕西省",
    "陕西": "陕西省",
    "陕西省": "陕西省",
    "陇": "甘肃省",
    "甘": "甘肃省",
    "甘肃": "甘肃省",
    "甘肃省": "甘肃省",
    "青": "青海省",
    "青海": "青海省",
    "青海省": "青海省",
    "宁": "宁夏回族自治区",
    "宁夏": "宁夏回族自治区",
    "宁夏回族自治区": "宁夏回族自治区",
    "新": "新疆维吾尔自治区",
    "新疆": "新疆维吾尔自治区",
    "新疆维吾尔自治区": "新疆维吾尔自治区",
    "港": "香港特别行政区",
    "香港": "香港特别行政区",
    "香港特别行政区": "香港特别行政区",
    "澳": "澳门特别行政区",
    "澳门": "澳门特别行政区",
    "澳门特别行政区": "澳门特别行政区",
    "台": "台湾省",
    "台湾": "台湾省",
    "台湾省": "台湾省",
}

LICENSE_PROVINCE_RE = re.compile(
    r"^([京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝蜀川黔贵滇云藏陕秦陇甘青宁新])(?:ICP|备|[AB]\d-|\d)",
    re.IGNORECASE,
)

EMPTY_PLACEHOLDERS: frozenset[str] = frozenset(
    {"", "-", "--", "none", "null", "n/a", "na", "未知", "暂无", "无", "undefined"}
)


def load_env_file(path: Path | str | None = None, override: bool = False) -> dict[str, str]:
    """Load key=value pairs from a .env file into os.environ without external deps."""
    loaded: dict[str, str] = {}
    env_path = Path(path) if path else Path(".env")
    if not env_path.is_file():
        return loaded

    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key:
            loaded[key] = val
            if override or key not in os.environ:
                os.environ[key] = val
    return loaded


def clean_text(value: Any) -> str:
    """Normalize arbitrary scalar values into trimmed text."""
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in {"nan", "none", "null"}:
        return ""
    return text


def clean_id(raw: str, prefix: str = "id") -> str:
    """Ensure identifier complies with Domain Hub `^[A-Za-z0-9_.:-]+$` (len 1..128)."""
    sanitized = re.sub(r"[^A-Za-z0-9_.:-]+", "_", clean_text(raw)).strip("_.-:")
    if not sanitized:
        sanitized = f"{prefix}_0"
    if len(sanitized) > 128:
        digest = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()[:12]
        sanitized = f"{sanitized[:115]}_{digest}"
    if not ID_RE.match(sanitized):
        raise ValueError(f"Invalid hub id after sanitization: {sanitized!r}")
    return sanitized


def is_ip_address(value: str) -> bool:
    """Return True if value looks like an IPv4 or IPv6 literal (optionally with port)."""
    candidate = value.strip().strip("[]")
    if not candidate:
        return False
    # Strip trailing :port for IPv4 or [v6]:port
    if candidate.count(":") == 1 and "." in candidate:
        host_part, port_part = candidate.rsplit(":", 1)
        if port_part.isdigit():
            candidate = host_part
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def has_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value)


def normalize_host(raw: Any, strip_www: bool = True, reject_punycode: bool = True) -> str | None:
    """Extract and validate a clean ASCII hostname from raw text/URL."""
    text = clean_text(raw)
    if not text:
        return None
    if has_non_ascii(text):
        return None

    # Handle full URLs or host/path inputs
    candidate = text
    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.netloc or parsed.path
    else:
        # Remove path/query/hash if present
        candidate = re.split(r"[/?#]", candidate, maxsplit=1)[0]

    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]

    candidate = candidate.strip().strip("[]").rstrip(".").lower()
    if ":" in candidate:
        host_only, maybe_port = candidate.rsplit(":", 1)
        if maybe_port.isdigit():
            candidate = host_only
        else:
            return None

    if not candidate or len(candidate) > 253:
        return None
    if is_ip_address(candidate):
        return None

    if strip_www and candidate.startswith("www.") and candidate.count(".") >= 2:
        candidate = candidate[4:]

    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    if reject_punycode and any(lbl.startswith("xn--") for lbl in labels):
        return None
    if not all(LABEL_RE.match(lbl) for lbl in labels):
        return None
    if not TLD_RE.match(labels[-1]):
        return None

    return candidate


def extract_suffix(host: str) -> str:
    """Return effective suffix (1 or 2 labels) for a normalized lowercase hostname."""
    labels = host.split(".")
    if len(labels) >= 3:
        two_level = ".".join(labels[-2:])
        if two_level in SECOND_LEVEL_SUFFIXES:
            return two_level
    return labels[-1]


def to_registrable_domain(host: str) -> str:
    """Collapse a normalized hostname to its WHOIS-queryable registrable root domain."""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    suffix = extract_suffix(host)
    suffix_parts = suffix.count(".") + 1
    if len(labels) <= suffix_parts + 1:
        return host
    return ".".join(labels[-(suffix_parts + 1) :])


def domain_shape(raw: Any, reject_punycode: bool = True) -> dict[str, Any]:
    """Inspect normalized host, apex domain, suffix, and restricted policy status."""
    host = normalize_host(raw, strip_www=True, reject_punycode=reject_punycode)
    if not host:
        return {
            "valid": False,
            "host": None,
            "apex_domain": None,
            "suffix": None,
            "shape": "invalid",
            "is_restricted": False,
        }
    suffix = extract_suffix(host)
    apex = to_registrable_domain(host)
    shape = "apex" if host == apex else "subdomain"
    is_restricted = suffix in RESTRICTED_SUFFIXES or any(
        apex.endswith(f".{r}") for r in RESTRICTED_SUFFIXES
    )
    return {
        "valid": True,
        "host": host,
        "apex_domain": apex,
        "suffix": suffix,
        "shape": shape,
        "is_restricted": is_restricted,
    }


def normalize_domain(
    raw: Any,
    collapse_subdomain: bool = True,
    reject_punycode: bool = True,
) -> str | None:
    """Normalize raw domain/URL into clean ASCII domain (defaulting to apex root)."""
    info = domain_shape(raw, reject_punycode=reject_punycode)
    if not info["valid"]:
        return None
    return info["apex_domain"] if collapse_subdomain else info["host"]


def is_restricted_domain(domain: str) -> bool:
    """Return True for policy-restricted TLDs such as .gov.cn / .edu.cn."""
    info = domain_shape(domain, reject_punycode=False)
    return bool(info["is_restricted"])


def match_province(text: Any) -> str | None:
    """Match canonical Chinese province name from province text or license prefix."""
    raw = clean_text(text)
    if not raw or raw.lower() in EMPTY_PLACEHOLDERS:
        return None
    if raw in PROVINCE_MAP:
        return PROVINCE_MAP[raw]

    # Try stripping common suffixes if partial match exists
    for key, canonical in PROVINCE_MAP.items():
        if len(key) >= 2 and raw.startswith(key):
            return canonical

    m = LICENSE_PROVINCE_RE.match(raw)
    if m:
        prefix = m.group(1)
        return PROVINCE_MAP.get(prefix)
    return None


def normalize_province(
    raw: Any,
    main_license: Any = None,
    service_license: Any = None,
) -> str:
    """Normalize province with fallback inference from main/service ICP license prefix."""
    for candidate in (raw, main_license, service_license):
        matched = match_province(candidate)
        if matched:
            return matched
    return ""


def service_subid_flag(service_license: Any, main_license: Any = None) -> int:
    """Return 1 for 666 website sub-license (e.g. '号-1'), 0 for 665 main-only / empty."""
    svc = clean_text(service_license)
    if not svc or svc.lower() in EMPTY_PLACEHOLDERS:
        return 0
    if re.search(r"号\s*[-_]\s*\d+\s*$", svc):
        return 1
    if svc.count("-") >= 2 and re.search(r"-\d{1,4}\s*$", svc):
        return 1
    main = clean_text(main_license)
    if main and svc != main and SUB_LICENSE_RE.search(svc) and not re.match(r"^[A-Z]\d-\d{6,}$", svc, re.I):
        return 1
    return 0


def parse_datetime_utc(raw: Any, naive_tz: timezone = SHANGHAI_TZ) -> datetime | None:
    """Parse flexible date/time representations into timezone-aware UTC datetime."""
    if isinstance(raw, datetime):
        dt = raw
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=naive_tz)
        return dt.astimezone(timezone.utc)

    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        val = float(raw)
        if val > 1e12:
            val /= 1000.0
        if val <= 0:
            return None
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    text = clean_text(raw)
    if not text or text.lower() in EMPTY_PLACEHOLDERS:
        return None

    # Clean common trailing "(UTC)" or extra whitespace
    cleaned = re.sub(r"\s+", " ", text).strip()
    if cleaned.endswith("Z"):
        iso_candidate = cleaned[:-1] + "+00:00"
    elif re.search(r"[+-]\d{2}:\d{2}$", cleaned):
        iso_candidate = cleaned
    elif re.search(r"[+-]\d{4}$", cleaned):
        iso_candidate = cleaned[:-2] + ":" + cleaned[-2:]
    else:
        iso_candidate = ""

    if iso_candidate:
        try:
            dt = datetime.fromisoformat(iso_candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    patterns: list[tuple[str, timezone]] = [
        ("%Y-%m-%d %H:%M:%S.%f", naive_tz),
        ("%Y-%m-%d %H:%M:%S", naive_tz),
        ("%Y/%m/%d %H:%M:%S", naive_tz),
        ("%Y-%m-%d", timezone.utc),
        ("%Y/%m/%d", timezone.utc),
        ("%Y.%m.%d", timezone.utc),
        ("%Y%m%d", timezone.utc),
        ("%Y年%m月%d日", timezone.utc),
    ]
    for fmt, tz in patterns:
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            continue

    # Last-resort prefix extraction (e.g. "2026-03-15 12:00:00 (UTC)")
    m_dt = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T ](\d{1,2}):(\d{2}):(\d{2}))?", cleaned)
    if m_dt:
        year, month, day = int(m_dt.group(1)), int(m_dt.group(2)), int(m_dt.group(3))
        hour = int(m_dt.group(4) or 0)
        minute = int(m_dt.group(5) or 0)
        second = int(m_dt.group(6) or 0)
        try:
            has_time = m_dt.group(4) is not None
            tz = timezone.utc if ("utc" in cleaned.lower() or "gmt" in cleaned.lower() or not has_time) else naive_tz
            return datetime(year, month, day, hour, minute, second, tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            return None

    return None


def ms_iso_utc(raw: Any = None, naive_tz: timezone = SHANGHAI_TZ) -> str | None:
    """Format timestamp into exact 3-digit ms UTC ISO string `YYYY-MM-DDTHH:MM:SS.mmmZ`."""
    dt = datetime.now(timezone.utc) if raw is None else parse_datetime_utc(raw, naive_tz=naive_tz)
    if dt is None:
        return None
    dt = dt.astimezone(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def utc_now_iso_ms() -> str:
    """Current UTC timestamp formatted with 3-digit milliseconds."""
    res = ms_iso_utc(None)
    assert res is not None
    return res


def normalize_timestamp(raw: Any, naive_tz: timezone = SHANGHAI_TZ) -> str | None:
    """Normalize input timestamp string into Hub-canonical UTC ISO string."""
    if raw is None:
        return None
    return ms_iso_utc(raw, naive_tz=naive_tz)


def clean_date_only(raw: Any) -> str | None:
    """Normalize date input into strict `YYYY-MM-DD` required by `/v1/intake` `filed_on`/`updated_on`."""
    text = clean_text(raw)
    if not text or text.lower() in EMPTY_PLACEHOLDERS:
        return None
    m = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T ].*)?$", text)
    if m:
        try:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return None
    if re.fullmatch(r"\d{8}", text):
        try:
            dt = datetime.strptime(text, "%Y%m%d")
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return None
    return None


def icp_fact_hash(
    domain: str,
    subject: str | None = None,
    main_license: str | None = None,
    service_license: str | None = None,
    filed_on: str | None = None,
    updated_on: str | None = None,
) -> str:
    """Compute SHA-256 fact hash matching `icpFactHash` in Hub `src/core.ts`."""
    payload = json.dumps(
        [
            domain,
            subject or "",
            main_license or "",
            service_license or "",
            filed_on or "",
            updated_on or "",
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def lifecycle(
    outcome: str,
    statuses: list[str] | None = None,
    expiration_date: str | None = None,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Classify expiration urgency in Asia/Shanghai calendar days matching Hub `src/core.ts`."""
    norm_outcome = clean_text(outcome).lower()
    if norm_outcome == "not_found":
        return {"lifecycle": "not_found", "days_left": None, "urgency": 9}

    norm_statuses = {
        re.sub(r"[\s_-]+", "", clean_text(s).lower())
        for s in (statuses or [])
        if clean_text(s)
    }

    as_of_dt = parse_datetime_utc(as_of) if as_of else datetime.now(timezone.utc)
    if as_of_dt is None:
        as_of_dt = datetime.now(timezone.utc)
    exp_dt = parse_datetime_utc(expiration_date) if expiration_date else None

    days_left: int | None = None
    if exp_dt is not None:
        as_of_day = (int(as_of_dt.timestamp()) + 28800) // 86400
        exp_day = (int(exp_dt.timestamp()) + 28800) // 86400
        days_left = exp_day - as_of_day

    if "pendingdelete" in norm_statuses:
        return {"lifecycle": "pending_delete", "days_left": days_left, "urgency": 0}
    if "redemptionperiod" in norm_statuses or "redemption" in norm_statuses:
        return {"lifecycle": "redemption", "days_left": days_left, "urgency": 0}

    if exp_dt is not None and days_left is not None:
        if exp_dt <= as_of_dt or days_left < 0:
            return {"lifecycle": "expired", "days_left": days_left, "urgency": 0}
        if days_left == 0:
            return {"lifecycle": "expiring_today", "days_left": 0, "urgency": 1}
        if days_left == 1:
            return {"lifecycle": "expiring_tomorrow", "days_left": 1, "urgency": 2}
        if 2 <= days_left <= 30:
            return {"lifecycle": "expiring_soon", "days_left": days_left, "urgency": 3}

    return {"lifecycle": "active", "days_left": days_left, "urgency": 9}


def strip_empty(obj: dict[str, Any]) -> dict[str, Any]:
    """Remove None and empty string keys so strict JSON validators do not reject optional fields."""
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, str) and v == "":
            continue
        if isinstance(v, dict):
            nested = strip_empty(v)
            if nested:
                out[k] = nested
        elif isinstance(v, list):
            cleaned_list = [x for x in v if x is not None and x != ""]
            if cleaned_list:
                out[k] = cleaned_list
        else:
            out[k] = v
    return out


def safe_csv_cell(value: Any) -> str:
    """Prevent Excel formula injection while leaving negative integers intact."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text[0] in ("=", "+", "@", "\t", "\r"):
        return "'" + text
    if text[0] == "-" and not re.fullmatch(r"-\d+(?:\.\d+)?", text):
        return "'" + text
    return text


def atomic_write_bytes(path: Path | str, data: bytes) -> None:
    """Atomically write bytes via temp file in same directory + os.replace."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path | str, content: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, content.encode(encoding))


def archive_raw_input(
    src_path: Path | str,
    seq: str,
    province: str,
    description: str,
    result_dir: Path | str = Path("result"),
) -> Path:
    """Copy a raw source file into `result/raw_inputs/{seq}_{province}_原始_{description}.{ext}`."""
    src = Path(src_path)
    if not src.is_file():
        raise FileNotFoundError(f"原始文件不存在: {src}")
    ext = src.suffix.lstrip(".") or "txt"
    safe_seq = clean_text(seq) or "00"
    safe_prov = clean_text(province) or "全国"
    safe_desc = re.sub(r"[\\/\s]+", "_", clean_text(description) or "原始数据")
    dest_dir = Path(result_dir) / "raw_inputs"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{safe_seq}_{safe_prov}_原始_{safe_desc}.{ext}"
    if dest.is_file():
        src_hash = hashlib.sha256(src.read_bytes()).hexdigest()
        dest_hash = hashlib.sha256(dest.read_bytes()).hexdigest()
        if src_hash == dest_hash:
            return dest
        ts = datetime.now(SHANGHAI_TZ).strftime("%Y%m%d_%H%M%S")
        dest = dest_dir / f"{safe_seq}_{safe_prov}_原始_{safe_desc}_{ts}.{ext}"
    shutil.copy2(src, dest)
    return dest


def export_ordered_csv(
    rows: list[dict[str, Any]],
    out_path: Path | str,
    max_days: int | None = 30,
    exclude_restricted: bool = True,
    as_of: str | None = None,
) -> int:
    """Export ordered urgent/expiring assets CSV with UTF-8 BOM per GEMINI.md rules.

    Sort order (ascending urgency):
    1. Expired / pendingDelete / redemptionPeriod (urgency=0)
    2. Expiring today (days_left == 0, urgency=1)
    3. Expiring tomorrow (days_left == 1, urgency=2)
    4. Expiring within `max_days` (2..max_days, urgency=3, ascending by days_left)
    """
    filtered: list[tuple[tuple[int, int, str, str], dict[str, Any]]] = []

    for row in rows:
        domain = normalize_domain(row.get("domain"), collapse_subdomain=False)
        if not domain:
            continue
        if exclude_restricted and is_restricted_domain(domain):
            continue

        exp = clean_text(row.get("expiration_date"))
        statuses = row.get("statuses") or row.get("whois_statuses") or []
        if isinstance(statuses, str):
            statuses = [s.strip() for s in statuses.split(",") if s.strip()]
        outcome = clean_text(row.get("outcome")) or "registered"

        lc = lifecycle(outcome, statuses, exp or None, as_of=as_of)
        urgency = int(lc["urgency"])
        days_left = lc["days_left"]

        if max_days is not None:
            if urgency == 9:
                continue
            if days_left is not None and days_left > max_days and urgency not in (0,):
                continue

        matched_type = clean_text(row.get("matched_type")) or str(lc["lifecycle"])
        sort_days = days_left if days_left is not None else -999999
        sort_key = (urgency, sort_days, exp, domain)

        record = {
            "domain": domain,
            "matched_type": matched_type,
            "expiration_date": exp,
            "days_left": "" if days_left is None else str(days_left),
            "source": clean_text(row.get("source") or row.get("provider")),
            "unit_name": clean_text(row.get("unit_name") or row.get("subject")),
            "service_licence": clean_text(row.get("service_licence") or row.get("service_license")),
            "main_licence": clean_text(row.get("main_licence") or row.get("main_license")),
            "nature": clean_text(row.get("nature") or row.get("subject_type") or row.get("province")),
            "updated": clean_text(
                row.get("updated")
                or row.get("updated_on")
                or row.get("registration_observed_at")
                or row.get("observed_at")
            ),
        }
        filtered.append((sort_key, record))

    filtered.sort(key=lambda item: item[0])

    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=ARCHIVED_CSV_HEADERS, lineterminator="\r\n")
            writer.writeheader()
            for _, rec in filtered:
                writer.writerow({k: safe_csv_cell(rec.get(k, "")) for k in ARCHIVED_CSV_HEADERS})
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return len(filtered)
