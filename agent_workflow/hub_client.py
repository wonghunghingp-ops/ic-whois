"""Domain Hub v2 single-threaded stdlib HTTP client, SQLite WAL outbox, and evidence uploader.

Supports:
- Mandatory custom User-Agent (avoids edge WAF 403 rejections)
- Direct HTTPS, optional single HTTP CONNECT proxy, or RFC-1928 SOCKS5 proxy
- Plan A: Anonymous/public `POST /v1/intake` (1..20 records, 5/min/IP pacing, local rejection capture)
- Plan B: Authorized Collector archive upload (`batches -> files -> PUT -> observations:batch -> receipts`)
  with automatic `< 900 KiB` JSONL evidence chunking and SHA-256 verification
- Cursor search across >5,000 candidates via `POST /v1/candidates/search`
- Job worker lifecycle (`/v1/jobs:claim`, `/heartbeat`, `/complete`, `/fail`)
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import random
import socket
import sqlite3
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .common import (
    DEFAULT_USER_AGENT,
    clean_date_only,
    clean_id,
    clean_text,
    ms_iso_utc,
    normalize_domain,
    normalize_province,
    strip_empty,
    utc_now_iso_ms,
)

LOGGER = logging.getLogger("agent_workflow.hub")

MAX_BATCH_RECORDS = 100
MAX_BATCH_JSON_BYTES = 850_000
MAX_EVIDENCE_FILE_BYTES = 900_000  # Server cap is 1,048,576 bytes; keep safety headroom
MAX_SINGLE_RECORD_BYTES = 60_000  # Server cap is 65,536 bytes
NON_RETRYABLE_HTTP = frozenset({400, 401, 403, 404, 409, 413, 415, 422})


@dataclass(frozen=True)
class ProxyConfig:
    scheme: str  # "http" | "https" | "socks5" | "socks5h"
    host: str
    port: int
    username: str = ""
    password: str = ""
    raw_url: str = ""


def parse_proxy_url(raw: str | None) -> ProxyConfig | None:
    """Parse single proxy URL (`socks5://...`, `socks5h://...`, `http://...`)."""
    text = clean_text(raw)
    if not text:
        return None
    if "://" not in text:
        text = "socks5://" + text
    parsed = urllib.parse.urlsplit(text)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise HubClientError(
            "不支持的代理协议，仅支持 http:// 或 socks5://。",
            category="input_error",
            code="invalid_proxy_scheme",
            next_step="请检查 WHOIS_SOCKS5_PROXY 或 --proxy 配置格式，例如 socks5://127.0.0.1:1080",
        )
    if not parsed.hostname or not parsed.port:
        raise HubClientError(
            "代理地址缺少主机或端口。",
            category="input_error",
            code="invalid_proxy_address",
            next_step="请使用完整格式：socks5://host:port 或 socks5://user:pass@host:port",
        )
    return ProxyConfig(
        scheme=scheme,
        host=parsed.hostname,
        port=parsed.port,
        username=urllib.parse.unquote(parsed.username or ""),
        password=urllib.parse.unquote(parsed.password or ""),
        raw_url=text,
    )


def socks5_connect(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float = 15.0,
) -> socket.socket:
    """Open TCP stream via RFC-1928/RFC-1929 SOCKS5 proxy with remote hostname resolution."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        methods = b"\x00\x02" if (proxy.username or proxy.password) else b"\x00"
        sock.sendall(bytes([0x05, len(methods)]) + methods)
        greeting = _recv_exact(sock, 2)
        if greeting[0] != 0x05:
            raise OSError("代理服务器未返回有效的 SOCKS5 握手响应")
        chosen = greeting[1]
        if chosen == 0xFF:
            raise OSError("代理服务器拒绝当前认证方式")
        if chosen == 0x02:
            user_b = proxy.username.encode("utf-8")
            pass_b = proxy.password.encode("utf-8")
            if len(user_b) > 255 or len(pass_b) > 255:
                raise ValueError("SOCKS5 用户名或密码过长")
            auth_pkt = bytes([0x01, len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b
            sock.sendall(auth_pkt)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[1] != 0x00:
                raise PermissionError("SOCKS5 代理用户名或密码认证失败")
        elif chosen != 0x00:
            raise OSError(f"不支持的 SOCKS5 认证方法: {chosen}")

        host_b = target_host.encode("idna")
        if len(host_b) > 255:
            raise ValueError(f"目标域名过长: {target_host}")
        req_pkt = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", target_port)
        sock.sendall(req_pkt)
        resp_hdr = _recv_exact(sock, 4)
        if resp_hdr[0] != 0x05 or resp_hdr[1] != 0x00:
            raise OSError(f"SOCKS5 连接目标失败，返回码: {resp_hdr[1]}")
        atyp = resp_hdr[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            alen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, alen + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        else:
            raise OSError(f"未知 SOCKS5 地址类型: {atyp}")
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("SOCKS5 连接意外断开")
        buf.extend(chunk)
    return bytes(buf)


class _Socks5HTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int | None = None, *, socks_proxy: ProxyConfig, timeout: float = 60.0):
        super().__init__(host, port=port, timeout=timeout)
        self._socks_proxy = socks_proxy

    def connect(self) -> None:
        self.sock = socks5_connect(self._socks_proxy, self.host, self.port, timeout=float(self.timeout or 60.0))


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int | None = None,
        *,
        socks_proxy: ProxyConfig,
        context: ssl.SSLContext | None = None,
        timeout: float = 60.0,
    ):
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._socks_proxy = socks_proxy

    def connect(self) -> None:
        raw_sock = socks5_connect(self._socks_proxy, self.host, self.port, timeout=float(self.timeout or 60.0))
        ctx = self._context or ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)


class _Socks5HTTPHandler(urllib.request.AbstractHTTPHandler):
    def __init__(self, socks_proxy: ProxyConfig, debuglevel: int = 0):
        super().__init__(debuglevel)
        self._socks_proxy = socks_proxy

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, timeout=60.0, **kwargs: _Socks5HTTPConnection(
                host, socks_proxy=self._socks_proxy, timeout=timeout
            ),
            req,
        )


class _Socks5HTTPSHandler(urllib.request.AbstractHTTPHandler):
    def __init__(self, socks_proxy: ProxyConfig, context: ssl.SSLContext | None = None, debuglevel: int = 0):
        super().__init__(debuglevel)
        self._socks_proxy = socks_proxy
        self._context = context or ssl.create_default_context()

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, timeout=60.0, **kwargs: _Socks5HTTPSConnection(
                host, socks_proxy=self._socks_proxy, context=self._context, timeout=timeout
            ),
            req,
        )


def build_url_opener(proxy: ProxyConfig | None = None) -> urllib.request.OpenerDirector:
    """Create urllib opener supporting direct, HTTP proxy, or SOCKS5 proxy."""
    if proxy is None:
        return urllib.request.build_opener()
    if proxy.scheme in {"socks5", "socks5h"}:
        return urllib.request.build_opener(
            _Socks5HTTPHandler(proxy),
            _Socks5HTTPSHandler(proxy),
        )
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy.raw_url, "https": proxy.raw_url})
    )


class HubClientError(RuntimeError):
    """Classified, user-friendly exception avoiding raw stack traces or secret leaks."""

    def __init__(
        self,
        user_message: str,
        *,
        category: str = "unknown_error",
        code: str = "hub_error",
        http_status: int | None = None,
        retryable: bool = False,
        next_step: str = "",
        detail: str = "",
    ):
        super().__init__(user_message)
        self.user_message = user_message
        self.category = category
        self.code = code
        self.http_status = http_status
        self.retryable = retryable
        self.next_step = next_step
        self.detail = detail

    def format_for_user(self) -> str:
        lines = [f"[{self.category}] {self.user_message}"]
        if self.next_step:
            lines.append(f"建议下一步: {self.next_step}")
        return "\n".join(lines)


def classify_http_error(
    status: int,
    body_text: str,
    endpoint: str,
    retry_after: str | None = None,
) -> HubClientError:
    """Map Hub HTTP error responses into actionable Chinese error feedback."""
    code = f"http_{status}"
    msg = ""
    try:
        parsed = json.loads(body_text)
        if isinstance(parsed, dict):
            code = clean_text(parsed.get("code") or parsed.get("error") or code)
            msg = clean_text(parsed.get("message") or parsed.get("error_description") or "")
    except Exception:
        pass

    LOGGER.warning("Hub HTTP error %s on %s: code=%s body=%s", status, endpoint, code, body_text[:300])

    if status == 401:
        return HubClientError(
            "身份凭证无效或已失效，服务端拒绝访问。",
            category="permission_error",
            code=code,
            http_status=status,
            retryable=False,
            next_step="请检查 .env 中的 DOMAIN_HUB_TOKEN 是否正确，或在无 Token 场景使用匿名通道 /v1/intake。",
            detail=msg,
        )
    if status == 403:
        return HubClientError(
            f"权限或边缘防护拒绝访问（{code}）。",
            category="permission_error",
            code=code,
            http_status=status,
            retryable=False,
            next_step="若触发防护拦截，请确认请求携带自定义 User-Agent；若是节点权限不足，请联系管理员开通对应 provider 权限。",
            detail=msg,
        )
    if status == 409:
        return HubClientError(
            "幂等键内容冲突：同一个 Idempotency-Key 被用于提交了不同的数据内容。",
            category="input_error",
            code=code,
            http_status=status,
            retryable=False,
            next_step="如需重新上传新数据，请生成新的批次标识或更换 client_batch_ref，不要复用旧请求键。",
            detail=msg,
        )
    if status in (413, 415, 422, 400):
        hint = msg or "请求字段、日期格式或单批体积不符合 Hub 规范"
        return HubClientError(
            f"数据校验未通过：{hint}",
            category="input_error",
            code=code,
            http_status=status,
            retryable=False,
            next_step="请确认日期为 YYYY-MM-DD、时间戳为 UTC 毫秒格式、单批不超过 100 条 / 850 KiB（/v1/intake 不超过 20 条）。",
            detail=msg,
        )
    if status == 429:
        wait_hint = f"约 {retry_after} 秒后" if retry_after else "60 秒后"
        return HubClientError(
            f"上传或查询频率触发限流，需等待 {wait_hint}再继续。",
            category="service_error",
            code=code,
            http_status=status,
            retryable=True,
            next_step="单线程客户端会自动退避等待后重试；如使用匿名 /v1/intake，请保持单次 <=20 条且间隔 >=16 秒。",
            detail=msg,
        )
    if status >= 500:
        return HubClientError(
            f"服务端暂时不可用（状态 {status}），当前写入可能尚未完成。",
            category="service_error",
            code=code,
            http_status=status,
            retryable=True,
            next_step="请等待几秒后重试同一批次；幂等机制会确保不会产生重复记录。",
            detail=msg,
        )
    return HubClientError(
        f"请求未能完成（{code}）。",
        category="unknown_error",
        code=code,
        http_status=status,
        retryable=False,
        next_step="请查看本地运行日志了解详细原因，或稍后重试。",
        detail=msg,
    )


class OutboxStore:
    """SQLite WAL state store for idempotent retries and failed/rejected intake recovery."""

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
                CREATE TABLE IF NOT EXISTS idempotency_ops (
                    op_key TEXT PRIMARY KEY,
                    idem_key TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    response_json TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intake_rejected (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chunk_id TEXT NOT NULL,
                    record_index INTEGER NOT NULL,
                    domain TEXT,
                    code TEXT NOT NULL,
                    message TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def get_or_create_idem_key(self, op_key: str, body_sha256: str) -> tuple[str, dict[str, Any] | None]:
        """Return stable Idempotency-Key for identical payloads; rotate cleanly if payload changed."""
        now_iso = utc_now_iso_ms()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT idem_key, body_sha256, state, response_json FROM idempotency_ops WHERE op_key=?",
                (op_key,),
            ).fetchone()
            if row and row["body_sha256"] == body_sha256:
                cached = json.loads(row["response_json"]) if (row["state"] == "done" and row["response_json"]) else None
                return str(row["idem_key"]), cached
            new_key = "aw-" + hashlib.sha256(f"{op_key}:{body_sha256}".encode("utf-8")).hexdigest()[:32]
            conn.execute(
                """
                INSERT INTO idempotency_ops(op_key, idem_key, body_sha256, state, response_json, updated_at)
                VALUES(?, ?, ?, 'pending', NULL, ?)
                ON CONFLICT(op_key) DO UPDATE SET
                    idem_key=excluded.idem_key,
                    body_sha256=excluded.body_sha256,
                    state='pending',
                    response_json=NULL,
                    updated_at=excluded.updated_at
                """,
                (op_key, new_key, body_sha256, now_iso),
            )
            return new_key, None

    def mark_idem_done(self, op_key: str, response_obj: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE idempotency_ops SET state='done', response_json=?, updated_at=? WHERE op_key=?",
                (json.dumps(response_obj, ensure_ascii=False), utc_now_iso_ms(), op_key),
            )

    def save_rejected_intake(self, chunk_id: str, index: int, domain: str, code: str, message: str, record: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO intake_rejected(chunk_id, record_index, domain, code, message, record_json, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (chunk_id, index, domain, code, message, json.dumps(record, ensure_ascii=False), utc_now_iso_ms()),
            )

    def list_rejected_intake(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intake_rejected ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


def validate_intake_record(raw: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Strict client-side validator matching `src/intake.ts` `rowSchema` before upload."""
    if not isinstance(raw, dict):
        return None, "记录必须是对象类型"

    domain = normalize_domain(raw.get("domain"), collapse_subdomain=True)
    if not domain:
        return None, "域名格式无效（已自动拦截纯 IP、非 ASCII 汉字或非法主机名）"

    out: dict[str, Any] = {"domain": domain}

    # ICP block
    raw_icp = raw.get("icp")
    if raw_icp is None and any(
        raw.get(k) for k in ("subject", "unit_name", "main_license", "main_licence", "service_license", "service_licence")
    ):
        raw_icp = raw

    if isinstance(raw_icp, dict):
        main_lic = clean_text(raw_icp.get("main_license") or raw_icp.get("main_licence"))[:500]
        svc_lic = clean_text(raw_icp.get("service_license") or raw_icp.get("service_licence"))[:500]
        subject = clean_text(raw_icp.get("subject") or raw_icp.get("unit_name"))[:500]
        subj_type = clean_text(raw_icp.get("subject_type") or raw_icp.get("nature"))[:500]
        province = normalize_province(raw_icp.get("province"), main_lic, svc_lic)[:500]
        filed_on = clean_date_only(raw_icp.get("filed_on") or raw_icp.get("first_filed_on"))
        updated_on = clean_date_only(raw_icp.get("updated_on") or raw_icp.get("updated"))

        icp_obj = strip_empty(
            {
                "subject": subject,
                "subject_type": subj_type,
                "main_license": main_lic,
                "service_license": svc_lic,
                "province": province,
                "filed_on": filed_on,
                "updated_on": updated_on,
            }
        )
        if any(icp_obj.get(k) for k in ("subject", "main_license", "service_license")):
            out["icp"] = icp_obj

    # WHOIS block (note strict intake key is singular `status`)
    raw_whois = raw.get("whois")
    if raw_whois is None and any(raw.get(k) for k in ("expiration_date", "status", "statuses", "registrar")):
        raw_whois = raw

    if isinstance(raw_whois, dict):
        exp = ms_iso_utc(raw_whois.get("expiration_date")) or clean_text(raw_whois.get("expiration_date"))[:500]
        status_raw = raw_whois.get("status")
        if not status_raw and isinstance(raw_whois.get("statuses"), list):
            status_raw = ", ".join(clean_text(s) for s in raw_whois["statuses"] if clean_text(s))
        status_str = clean_text(status_raw)[:500]
        registrar = clean_text(raw_whois.get("registrar"))[:500]
        whois_obj = strip_empty(
            {
                "expiration_date": exp,
                "status": status_str,
                "registrar": registrar,
            }
        )
        if any(whois_obj.get(k) for k in ("expiration_date", "status", "registrar")):
            out["whois"] = whois_obj

    if "icp" not in out and "whois" not in out:
        return None, "至少需要一项有效的备案信息（主办方/备案号）或 WHOIS 信息（到期时间/状态/注册商）"

    obs_raw = raw.get("observed_at")
    if obs_raw:
        obs_iso = ms_iso_utc(obs_raw)
        if not obs_iso:
            return None, f"observed_at 时间格式无法解析: {obs_raw!r}"
        out["observed_at"] = obs_iso

    sheet = clean_text(raw.get("sheet"))[:500]
    if sheet:
        out["sheet"] = sheet
    row_num = raw.get("row_number")
    if isinstance(row_num, int) and row_num > 0:
        out["row_number"] = row_num

    return out, None


class DomainHubClient:
    """Single-threaded synchronous HTTP client for Domain Hub v2."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        proxy_url: str = "",
        timeout_sec: float = 60.0,
        user_agent: str = DEFAULT_USER_AGENT,
        max_retries: int = 4,
        outbox_path: Path | str | None = None,
    ):
        url = clean_text(base_url).rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise HubClientError(
                "Domain Hub 服务地址无效，必须以 http:// 或 https:// 开头。",
                category="input_error",
                code="invalid_hub_url",
                next_step="请设置 DOMAIN_HUB_URL=https://hub.llmhubone.net",
            )
        self.base_url = url
        self.token = clean_text(token)
        self.proxy_cfg = parse_proxy_url(proxy_url)
        self.timeout_sec = max(5.0, float(timeout_sec))
        self.user_agent = clean_text(user_agent) or DEFAULT_USER_AGENT
        self.max_retries = max(1, int(max_retries))
        self._opener = build_url_opener(self.proxy_cfg)
        self.outbox = OutboxStore(outbox_path) if outbox_path else None

    def _headers(self, *, auth_required: bool, content_type: str | None = "application/json", idem_key: str | None = None) -> dict[str, str]:
        if auth_required and not self.token:
            raise HubClientError(
                "当前操作需要 Collector Token，但尚未配置 DOMAIN_HUB_TOKEN。",
                category="permission_error",
                code="missing_token",
                next_step="请先在 .env 或 --token 中配置 Collector Token；若无 Token 可改用匿名上传指令。",
            )
        hdrs: dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        if self.token and auth_required:
            hdrs["Authorization"] = f"Bearer {self.token}"
        elif self.token and not auth_required:
            # Intake also works anonymously when auth_required=False
            pass
        if content_type:
            hdrs["Content-Type"] = content_type
        if idem_key:
            hdrs["Idempotency-Key"] = idem_key
        return hdrs

    def request_raw(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        raw_bytes: bytes | None = None,
        content_type: str | None = None,
        auth_required: bool = True,
        idem_key: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        if json_body is not None and raw_bytes is not None:
            raise ValueError("json_body and raw_bytes are mutually exclusive")
        body_data: bytes | None = raw_bytes
        if json_body is not None:
            body_data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            content_type = content_type or "application/json; charset=utf-8"

        full_url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        if method.upper() in ("POST", "PUT", "PATCH") and idem_key is None and path != "/v1/collectors/me/heartbeat" and not path.startswith("/v1/jobs"):
            digest = hashlib.sha256(body_data or b"").hexdigest()[:24]
            idem_key = f"aw-{digest}-{uuid.uuid4().hex[:8]}"

        headers = self._headers(auth_required=auth_required, content_type=content_type, idem_key=idem_key)

        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(full_url, data=body_data, method=method.upper())
            for k, v in headers.items():
                req.add_header(k, v)
            try:
                with self._opener.open(req, timeout=self.timeout_sec) as resp:
                    resp_bytes = resp.read()
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    return int(resp.status), resp_bytes, resp_headers
            except urllib.error.HTTPError as exc:
                try:
                    err_body = exc.read().decode("utf-8", errors="replace")
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    err_code = int(exc.code)
                finally:
                    exc.close()
                hub_err = classify_http_error(err_code, err_body, path, retry_after=retry_after)
                if not hub_err.retryable or attempt >= self.max_retries:
                    raise hub_err from exc
                wait_s = _compute_retry_wait(attempt, retry_after)
                LOGGER.warning("Retryable Hub status %s on %s (attempt %d/%d), sleeping %.1fs", err_code, path, attempt, self.max_retries, wait_s)
                time.sleep(wait_s)
            except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, http.client.HTTPException) as exc:
                LOGGER.warning("Network error on %s (attempt %d/%d): %s", path, attempt, self.max_retries, exc)
                if attempt >= self.max_retries:
                    raise HubClientError(
                        "无法连接 Domain Hub 服务器或请求超时。",
                        category="network_error",
                        code="network_unreachable",
                        retryable=True,
                        next_step="请检查本机网络、DNS、防火墙或代理设置，并确认服务地址可访问后重试。",
                        detail=str(exc),
                    ) from exc
                time.sleep(_compute_retry_wait(attempt, None))

        raise HubClientError("未知网络错误导致请求未完成", category="unknown_error")

    def request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        raw_bytes: bytes | None = None,
        content_type: str | None = None,
        auth_required: bool = True,
        idem_key: str | None = None,
    ) -> Any:
        _, raw, _ = self.request_raw(
            method,
            path,
            json_body=json_body,
            raw_bytes=raw_bytes,
            content_type=content_type,
            auth_required=auth_required,
            idem_key=idem_key,
        )
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise HubClientError(
                "服务端返回了无法解析的响应格式。",
                category="service_error",
                code="invalid_server_json",
                next_step="请稍后重试；若持续出现，请联系服务端维护人员。",
                detail=str(exc),
            ) from exc

    # ------------------------------------------------------------------
    # Health & Identity
    # ------------------------------------------------------------------

    def health_ready(self) -> dict[str, Any]:
        started = time.monotonic()
        data = self.request_json("GET", "/v1/health/ready", auth_required=False)
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 1)
        return {"ok": True, "latency_ms": elapsed_ms, "response": data}

    def collector_me(self) -> dict[str, Any]:
        return self.request_json("GET", "/v1/collectors/me", auth_required=True)

    # ------------------------------------------------------------------
    # Plan A: Public / Anonymous Intake (/v1/intake)
    # ------------------------------------------------------------------

    def submit_intake(
        self,
        records: list[dict[str, Any]],
        *,
        chunk_size: int = 20,
        delay_sec: float = 16.0,
    ) -> dict[str, Any]:
        """Validate locally and submit records sequentially to `POST /v1/intake`."""
        safe_chunk = max(1, min(20, int(chunk_size)))
        valid_rows: list[dict[str, Any]] = []
        locally_invalid: list[dict[str, Any]] = []

        for idx, raw in enumerate(records):
            cleaned, err = validate_intake_record(raw)
            if cleaned is None:
                item = {
                    "index": idx,
                    "domain": clean_text(raw.get("domain") if isinstance(raw, dict) else ""),
                    "code": "local_validation_failed",
                    "message": err or "校验失败",
                    "record": raw,
                }
                locally_invalid.append(item)
                if self.outbox:
                    self.outbox.save_rejected_intake(
                        "local", idx, item["domain"], item["code"], item["message"], raw if isinstance(raw, dict) else {"raw": str(raw)}
                    )
            else:
                valid_rows.append(cleaned)

        receipts: list[dict[str, Any]] = []
        server_rejected: list[dict[str, Any]] = []
        accepted_records = 0
        accepted_observations = 0

        total_chunks = (len(valid_rows) + safe_chunk - 1) // safe_chunk
        for chunk_idx in range(total_chunks):
            chunk = valid_rows[chunk_idx * safe_chunk : (chunk_idx + 1) * safe_chunk]
            payload = {"records": chunk}
            payload_sha = hashlib.sha256(
                json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            op_key = f"intake:{payload_sha[:24]}"
            idem_key = (
                self.outbox.get_or_create_idem_key(op_key, payload_sha)[0]
                if self.outbox
                else f"intake-{payload_sha[:28]}"
            )
            res = self.request_json(
                "POST",
                "/v1/intake",
                json_body=payload,
                auth_required=False,
                idem_key=idem_key,
            )
            if self.outbox:
                self.outbox.mark_idem_done(op_key, res)
            receipts.append(res)
            accepted_records += int(res.get("accepted_records") or 0)
            accepted_observations += int(res.get("accepted_observations") or 0)
            for rej in res.get("rejected") or []:
                rej_idx = int(rej.get("index") or 0)
                bad_rec = chunk[rej_idx] if 0 <= rej_idx < len(chunk) else {}
                rej_info = {
                    "receipt_id": res.get("id"),
                    "index": rej_idx,
                    "domain": clean_text(bad_rec.get("domain")),
                    "code": clean_text(rej.get("code") or "rejected"),
                    "message": clean_text(rej.get("message") or "服务端拒绝"),
                    "record": bad_rec,
                }
                server_rejected.append(rej_info)
                if self.outbox:
                    self.outbox.save_rejected_intake(
                        str(res.get("id") or "intake"),
                        rej_idx,
                        rej_info["domain"],
                        rej_info["code"],
                        rej_info["message"],
                        bad_rec,
                    )
            if chunk_idx + 1 < total_chunks and delay_sec > 0:
                time.sleep(float(delay_sec))

        return {
            "total_input": len(records),
            "sent_valid": len(valid_rows),
            "accepted_records": accepted_records,
            "accepted_observations": accepted_observations,
            "locally_invalid": locally_invalid,
            "server_rejected": server_rejected,
            "receipts": receipts,
        }

    # ------------------------------------------------------------------
    # Plan B: Authorized Archive & Authoritative Batch Pipeline
    # ------------------------------------------------------------------

    def create_batch(
        self,
        province_or_topic: str,
        description: str,
        source_kind: str,
        *,
        client_batch_ref: str | None = None,
        op_seed: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "province_or_topic": clean_text(province_or_topic)[:100] or "全国",
            "description": clean_text(description)[:500],
            "source_kind": clean_text(source_kind)[:64] or "mixed_collection",
        }
        if client_batch_ref:
            payload["client_batch_ref"] = clean_text(client_batch_ref)[:128]

        body_sha = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        op_key = op_seed or f"batch:{payload['province_or_topic']}:{payload['source_kind']}:{body_sha[:16]}"
        if self.outbox:
            idem_key, cached = self.outbox.get_or_create_idem_key(op_key, body_sha)
            if cached and cached.get("batch_id"):
                return cached
        else:
            idem_key = f"batch-{body_sha[:24]}-{uuid.uuid4().hex[:6]}"

        res = self.request_json("POST", "/v1/batches", json_body=payload, auth_required=True, idem_key=idem_key)
        if self.outbox:
            self.outbox.mark_idem_done(op_key, res)
        return res

    def upload_file_bytes(
        self,
        batch_id: str,
        original_name: str,
        role: str,
        description: str,
        content_bytes: bytes,
        *,
        media_type: str | None = None,
        encoding: str = "utf-8",
    ) -> dict[str, Any]:
        if not content_bytes:
            raise HubClientError(
                f"文件 {original_name} 为空，禁止上传空文件。",
                category="input_error",
                code="empty_file",
                next_step="请确认源文件包含有效记录后再上传。",
            )
        suffix = Path(original_name).suffix.lower()
        resolved_media = media_type or (
            "application/json" if suffix in (".json", ".jsonl") else "text/csv" if suffix == ".csv" else "text/plain"
        )
        digest = hashlib.sha256(content_bytes).hexdigest()
        file_meta_req = strip_empty(
            {
                "batch_id": clean_id(batch_id),
                "original_name": original_name[:200],
                "role": role,
                "description": clean_text(description)[:150] or original_name[:150],
                "media_type": resolved_media,
                "byte_size": len(content_bytes),
                "sha256": digest,
                "encoding": encoding,
            }
        )
        key = "file-" + hashlib.sha256(
            f"{batch_id}:{role}:{original_name}:{digest}".encode("utf-8")
        ).hexdigest()[:32]
        reg = self.request_json("POST", "/v1/files", json_body=file_meta_req, auth_required=True, idem_key=key)
        if reg.get("state") == "verified":
            return reg

        upload_url = reg.get("upload_url") or f"/v1/files/{reg['file_id']}/content"
        try:
            res = self.request_json(
                "PUT",
                upload_url,
                raw_bytes=content_bytes,
                content_type=resolved_media,
                auth_required=True,
                idem_key=f"put-{digest[:24]}",
            )
            return res if res else self.request_json("GET", f"/v1/files/{reg['file_id']}", auth_required=True)
        except HubClientError as err:
            if err.http_status == 409:
                current = self.request_json("GET", f"/v1/files/{reg['file_id']}", auth_required=True)
                if current.get("state") == "verified" and current.get("sha256") == digest:
                    return current
            raise

    def upload_evidence_jsonl_and_observations(
        self,
        batch_id: str,
        items: list[dict[str, Any]],
        *,
        file_prefix: str = "whois_evidence",
        description: str = "WHOIS raw responses",
        wait_receipts: bool = True,
        receipt_timeout_sec: float = 120.0,
    ) -> dict[str, Any]:
        """Chunk raw JSONL evidence (<900 KiB per file), register/PUT each file, align indices, and submit observations."""
        if not items:
            return {"files": [], "receipts": [], "accepted": 0, "duplicates": 0, "rejected": 0}

        chunks: list[list[dict[str, Any]]] = []
        current_chunk: list[dict[str, Any]] = []
        current_bytes = 0

        for item in items:
            entry = item["evidence_entry"]
            line_str = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
            line_bytes = len(line_str.encode("utf-8"))
            if line_bytes > MAX_EVIDENCE_FILE_BYTES:
                raise HubClientError(
                    f"单条原件响应过大（{line_bytes} bytes），超出单文件限制。",
                    category="input_error",
                    code="single_evidence_too_large",
                    next_step="请截断或检查异常超长 WHOIS 响应文本。",
                )
            if current_chunk and (current_bytes + line_bytes > MAX_EVIDENCE_FILE_BYTES or len(current_chunk) >= 500):
                chunks.append(current_chunk)
                current_chunk = []
                current_bytes = 0
            current_chunk.append(item)
            current_bytes += line_bytes
        if current_chunk:
            chunks.append(current_chunk)

        uploaded_files: list[dict[str, Any]] = []
        all_records: list[dict[str, Any]] = []

        for part_idx, chunk in enumerate(chunks, start=1):
            jsonl_lines = [
                json.dumps(it["evidence_entry"], ensure_ascii=False, separators=(",", ":"))
                for it in chunk
            ]
            raw_bytes = ("\n".join(jsonl_lines) + "\n").encode("utf-8")
            fname = f"{file_prefix}_part{part_idx:03d}.jsonl"
            file_info = self.upload_file_bytes(
                batch_id,
                fname,
                "query_response",
                f"{description} (part {part_idx}/{len(chunks)})",
                raw_bytes,
                media_type="application/json",
            )
            uploaded_files.append(file_info)
            file_id = file_info["file_id"]

            for rec_idx, it in enumerate(chunk):
                rec = dict(it["observation"])
                ev = dict(rec.get("evidence") or {})
                ev["file_id"] = file_id
                ev["record_index"] = rec_idx
                # Keep http_status parity: omit http_status completely when None
                if ev.get("http_status") is None:
                    ev.pop("http_status", None)
                rec["evidence"] = ev
                all_records.append(rec)

        obs_summary = self.submit_observations_batch(
            batch_id,
            all_records,
            wait_receipts=wait_receipts,
            receipt_timeout_sec=receipt_timeout_sec,
        )
        return {
            "files": uploaded_files,
            **obs_summary,
        }

    def submit_observations_batch(
        self,
        batch_id: str,
        records: list[dict[str, Any]],
        *,
        query_runs: bool = False,
        wait_receipts: bool = True,
        receipt_timeout_sec: float = 120.0,
    ) -> dict[str, Any]:
        """Chunk observation payloads (`<=100` records, `<=850 KiB`), submit & wait for terminal receipt state."""
        path = "/v1/query-runs:batch" if query_runs else "/v1/observations:batch"
        if not records:
            return {"receipts": [], "accepted": 0, "duplicates": 0, "rejected": 0, "items": []}

        batches: list[list[dict[str, Any]]] = []
        curr: list[dict[str, Any]] = []
        for rec in records:
            rec_bytes = len(json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if rec_bytes > MAX_SINGLE_RECORD_BYTES:
                raise HubClientError(
                    f"单条记录 {rec.get('domain')} 超过 60 KiB 安全阈值。",
                    category="input_error",
                    code="record_too_large",
                    next_step="请精简 data 字段或将长文本存入 query_response 原件文件。",
                )
            candidate = curr + [rec]
            encoded = json.dumps({"schema_version": "1.0", "batch_id": batch_id, "records": candidate}, ensure_ascii=False)
            if curr and (len(candidate) > MAX_BATCH_RECORDS or len(encoded.encode("utf-8")) > MAX_BATCH_JSON_BYTES):
                batches.append(curr)
                curr = [rec]
            else:
                curr = candidate
        if curr:
            batches.append(curr)

        receipts: list[dict[str, Any]] = []
        all_items: list[dict[str, Any]] = []
        accepted = 0
        duplicates = 0
        rejected = 0

        for idx, chunk in enumerate(batches):
            payload = {"schema_version": "1.0", "batch_id": batch_id, "records": chunk}
            payload_sha = hashlib.sha256(
                json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            op_key = f"obs:{path}:{batch_id}:{payload_sha[:24]}"
            idem_key = (
                self.outbox.get_or_create_idem_key(op_key, payload_sha)[0]
                if self.outbox
                else f"obs-{payload_sha[:28]}"
            )
            submitted = self.request_json("POST", path, json_body=payload, auth_required=True, idem_key=idem_key)
            receipt_id = submitted["id"]
            if wait_receipts:
                terminal = self.wait_receipt(receipt_id, timeout_sec=receipt_timeout_sec)
                if self.outbox:
                    self.outbox.mark_idem_done(op_key, terminal)
                receipts.append(terminal)
                items = self.receipt_items(receipt_id)
                all_items.extend(items)
                for it in items:
                    st = clean_text(it.get("state") or it.get("status")).lower()
                    if st == "duplicate":
                        duplicates += 1
                    elif st in ("rejected", "failed", "event_payload_conflict"):
                        rejected += 1
                    else:
                        accepted += 1
            else:
                receipts.append(submitted)
                accepted += int(submitted.get("accepted") or len(chunk))
                rejected += int(submitted.get("rejected") or 0)

        return {
            "receipts": receipts,
            "items": all_items,
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
        }

    def wait_receipt(self, receipt_id: str, *, timeout_sec: float = 120.0, poll_interval: float = 2.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_sec
        while True:
            receipt = self.request_json("GET", f"/v1/ingest-receipts/{receipt_id}", auth_required=True)
            state = clean_text(receipt.get("state"))
            pending = int(receipt.get("pending") or 0)
            if state in ("processed", "partial") and pending == 0:
                return receipt
            if state == "failed":
                raise HubClientError(
                    f"入库回执 {receipt_id} 处理失败（{receipt.get('error_code') or 'processing_failed'}）。",
                    category="service_error",
                    code=clean_text(receipt.get("error_code") or "receipt_failed"),
                    next_step="请拉取该回执明细 /items 核查被拒绝或冲突的具体行。",
                )
            if time.monotonic() >= deadline:
                raise HubClientError(
                    f"等待入库回执 {receipt_id} 超时（state={state}, pending={pending}）。",
                    category="service_error",
                    code="receipt_timeout",
                    retryable=True,
                    next_step="服务端队列可能仍在消化中，请稍后使用同一批数据重跑，幂等键不会导致重复入库。",
                )
            time.sleep(poll_interval)

    def receipt_items(self, receipt_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cursor: str | None = "0"
        while cursor is not None:
            q = urllib.parse.quote(str(cursor))
            page = self.request_json("GET", f"/v1/ingest-receipts/{receipt_id}/items?cursor={q}", auth_required=True)
            out.extend(page.get("items") or [])
            nxt = page.get("next_cursor")
            cursor = str(nxt) if nxt not in (None, "", "null") else None
        return out

    # ------------------------------------------------------------------
    # Search (>5,000 cursor paging) & Exports
    # ------------------------------------------------------------------

    def search_candidates_page(
        self,
        filters: dict[str, Any] | None = None,
        *,
        limit: int = 200,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "filters": filters or {},
            "limit": max(1, min(500, int(limit))),
            "sort": "expiry_urgency_asc",
            "policy_version": "expiry-watch/1",
        }
        if cursor:
            payload["cursor"] = cursor
        return self.request_json("POST", "/v1/candidates/search", json_body=payload, auth_required=True)

    def iter_candidates(
        self,
        filters: dict[str, Any] | None = None,
        *,
        page_size: int = 200,
        max_items: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Cursor-paginated sequential iterator supporting full >5,000 result traversal."""
        cursor: str | None = None
        yielded = 0
        while True:
            page = self.search_candidates_page(filters, limit=page_size, cursor=cursor)
            items = page.get("items") or []
            if not items:
                break
            for item in items:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return
            nxt = page.get("next_cursor")
            if not nxt:
                break
            cursor = str(nxt)

    def create_official_export(self, batch_id: str, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {
            "batch_id": batch_id,
            "filters": filters or {},
            "policy_version": "expiry-watch/1",
        }
        return self.request_json("POST", "/v1/exports", json_body=payload, auth_required=True)

    # ------------------------------------------------------------------
    # Queue Job Worker
    # ------------------------------------------------------------------

    def claim_job(self, providers: list[str] | None = None) -> dict[str, Any] | None:
        payload: dict[str, Any] = {}
        if providers:
            payload["providers"] = list(providers)
        res = self.request_json("POST", "/v1/jobs:claim", json_body=payload, auth_required=True)
        return res.get("job")

    def heartbeat_job(self, job_id: str, lease_token: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/v1/jobs/{clean_id(job_id)}/heartbeat",
            json_body={"lease_token": lease_token},
            auth_required=True,
        )

    def complete_job(self, job_id: str, lease_token: str, receipt_id: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/v1/jobs/{clean_id(job_id)}/complete",
            json_body={"lease_token": lease_token, "receipt_id": clean_id(receipt_id)},
            auth_required=True,
        )

    def fail_job(self, job_id: str, lease_token: str, error_msg: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/v1/jobs/{clean_id(job_id)}/fail",
            json_body={"lease_token": lease_token, "error": clean_text(error_msg)[:300] or "worker_error"},
            auth_required=True,
        )


def _compute_retry_wait(attempt: int, retry_after: str | None) -> float:
    if retry_after and retry_after.strip().isdigit():
        base = float(int(retry_after.strip()))
        return min(120.0, max(1.0, base + random.uniform(0.5, 2.5)))
    schedule = (2.0, 5.0, 15.0, 30.0)
    base = schedule[min(attempt - 1, len(schedule) - 1)]
    return base + random.uniform(0.2, 1.2)
