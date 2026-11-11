"""Comprehensive offline unit and mock-server integration tests for agent-workflow."""

from __future__ import annotations

import csv
import hashlib
import http.server
import io
import json
import os
import shutil
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from agent_workflow.cli import main as cli_main
from agent_workflow.common import (
    ARCHIVED_CSV_HEADERS,
    SHANGHAI_TZ,
    archive_raw_input,
    clean_date_only,
    domain_shape,
    export_ordered_csv,
    icp_fact_hash,
    is_restricted_domain,
    lifecycle,
    ms_iso_utc,
    normalize_domain,
    normalize_province,
    safe_csv_cell,
    service_subid_flag,
)
from agent_workflow.hub_client import DomainHubClient, HubClientError, OutboxStore, validate_intake_record
from agent_workflow.icp_cleaner import (
    clean_icp_file,
    strip_llm_artifacts,
    to_authorized_icp_observations,
    to_intake_records,
)
from agent_workflow.whois_single import (
    SingleThreadWhoisEngine,
    WhoisCheckpointStore,
    WhoisQueryConfig,
    parse_rdap_json,
    parse_whois_text,
    to_hub_evidence_items,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestNormalizationAndHashing(unittest.TestCase):
    def test_domain_hygiene_and_collapsing(self) -> None:
        self.assertEqual(normalize_domain("example.com"), "example.com")
        self.assertEqual(normalize_domain("https://www.sub.example.cn/index.html"), "example.cn")
        self.assertEqual(
            normalize_domain("https://www.sub.example.cn/index.html", collapse_subdomain=False),
            "sub.example.cn",
        )
        self.assertEqual(normalize_domain("http://www.Portal.Shop.COM.CN:8443/home?a=1"), "shop.com.cn")
        self.assertEqual(normalize_domain("a.b.city.gd.cn"), "city.gd.cn")
        self.assertEqual(normalize_domain("sub.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(normalize_domain("www.com"), "www.com")
        self.assertIsNone(normalize_domain("101.227.52.182"))
        self.assertIsNone(normalize_domain("http://101.227.52.182:8080/test"))
        self.assertIsNone(normalize_domain("[::1]"))
        self.assertIsNone(normalize_domain("中文域名测试.中国"))
        self.assertIsNone(normalize_domain("xn--fiqs8s.cn"))
        self.assertEqual(normalize_domain("xn--fiqs8s.cn", reject_punycode=False), "xn--fiqs8s.cn")
        self.assertTrue(is_restricted_domain("bureau.gov.cn"))
        self.assertTrue(is_restricted_domain("pku.edu.cn"))
        self.assertFalse(is_restricted_domain("example.com"))
        shape = domain_shape("news.example.com")
        self.assertEqual(shape["shape"], "subdomain")
        self.assertEqual(shape["apex_domain"], "example.com")

    def test_province_and_subid_rules(self) -> None:
        self.assertEqual(normalize_province("未知", "湘ICP备2021000002号"), "湖南省")
        self.assertEqual(normalize_province("沪"), "上海市")
        self.assertEqual(normalize_province("内蒙古"), "内蒙古自治区")
        self.assertEqual(normalize_province("", "", "浙ICP备2022000003号-1"), "浙江省")
        self.assertEqual(normalize_province("unknown"), "")

        self.assertEqual(service_subid_flag("沪ICP备2020000001号-1", "沪ICP备2020000001号"), 1)
        self.assertEqual(service_subid_flag("B2-20090007-1", "B2-20090007"), 1)
        self.assertEqual(service_subid_flag("B2-20090007", "B2-20090007"), 0)
        self.assertEqual(service_subid_flag("沪ICP备2020000001号", "沪ICP备2020000001号"), 0)
        self.assertEqual(service_subid_flag("", "浙ICP备2022000003号"), 0)

    def test_dates_and_icp_fact_hash_parity(self) -> None:
        self.assertEqual(clean_date_only("2021/03/15"), "2021-03-15")
        self.assertEqual(clean_date_only("2026-01-10 08:30:00"), "2026-01-10")
        self.assertIsNone(clean_date_only("2026-02-31"))
        self.assertEqual(ms_iso_utc("2026-11-11 08:00:00", naive_tz=SHANGHAI_TZ), "2026-11-11T00:00:00.000Z")

        # Verify exact compact UTF-8 JSON SHA-256 matching Node JSON.stringify([...])
        raw_js_equiv = '["example.com","上海示例科技有限公司","沪ICP备2020000001号","沪ICP备2020000001号-1","2020-05-12","2025-11-01"]'
        expected = hashlib.sha256(raw_js_equiv.encode("utf-8")).hexdigest()
        actual = icp_fact_hash(
            "example.com",
            "上海示例科技有限公司",
            "沪ICP备2020000001号",
            "沪ICP备2020000001号-1",
            "2020-05-12",
            "2025-11-01",
        )
        self.assertEqual(actual, expected)

    def test_lifecycle_shanghai_day_boundaries_and_csv_export(self) -> None:
        # 2026-11-11T15:30:00Z = 2026-11-11 23:30 CST (+08:00)
        as_of = "2026-11-11T15:30:00.000Z"
        # Same Shanghai calendar day (23:59 CST) -> days_left = 0, urgency = 1
        same_day = lifecycle("success", ["ok"], "2026-11-11T15:59:00.000Z", as_of=as_of)
        self.assertEqual(same_day["days_left"], 0)
        self.assertEqual(same_day["urgency"], 1)

        # Next Shanghai calendar day (2026-11-12 00:30 CST = 2026-11-11T16:30:00Z) -> days_left = 1, urgency = 2
        next_day = lifecycle("success", ["ok"], "2026-11-11T16:30:00.000Z", as_of=as_of)
        self.assertEqual(next_day["days_left"], 1)
        self.assertEqual(next_day["urgency"], 2)

        self.assertEqual(lifecycle("success", ["pendingDelete"], "2026-11-20T00:00:00Z", as_of=as_of)["urgency"], 0)
        self.assertEqual(lifecycle("success", ["redemption"], "2026-11-20T00:00:00Z", as_of=as_of)["urgency"], 0)
        self.assertEqual(lifecycle("not_found", [], None, as_of=as_of)["urgency"], 9)

        self.assertEqual(safe_csv_cell("-3"), "-3")
        self.assertEqual(safe_csv_cell("=CMD()"), "'=CMD()")
        self.assertEqual(safe_csv_cell("-evil"), "'-evil")

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "ordered.csv"
            rows = [
                {"domain": "later.com", "expiration_date": "2026-11-25T00:00:00Z", "outcome": "success"},
                {"domain": "today.com", "expiration_date": "2026-11-11T15:50:00Z", "outcome": "success"},
                {"domain": "far.com", "expiration_date": "2027-05-01T00:00:00Z", "outcome": "success"},
                {"domain": "city.gov.cn", "expiration_date": "2026-11-12T00:00:00Z", "outcome": "success"},
                {"domain": "tomorrow.com", "expiration_date": "2026-11-12T05:00:00Z", "outcome": "success"},
                {"domain": "expired.com", "expiration_date": "2026-11-09T00:00:00Z", "outcome": "success", "statuses": ["pendingDelete"]},
            ]
            count = export_ordered_csv(rows, csv_path, max_days=30, exclude_restricted=True, as_of=as_of)
            self.assertEqual(count, 4)  # far.com & city.gov.cn excluded
            raw_bytes = csv_path.read_bytes()
            self.assertTrue(raw_bytes.startswith(b"\xef\xbb\xbf"))
            with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
                parsed = list(csv.DictReader(fh))
            self.assertEqual(list(parsed[0].keys()), ARCHIVED_CSV_HEADERS)
            self.assertEqual([r["domain"] for r in parsed], ["expired.com", "today.com", "tomorrow.com", "later.com"])
            self.assertEqual(parsed[0]["days_left"], "-2")


class TestIcpCleaner(unittest.TestCase):
    def test_sample_icp_cleaning_and_666_priority(self) -> None:
        rows, stats = clean_icp_file(REPO_ROOT / "examples" / "sample_icp.csv")
        self.assertEqual(stats.total_rows, 5)
        self.assertEqual(stats.skipped_ip, 1)
        self.assertEqual(stats.skipped_non_ascii, 1)
        self.assertEqual(stats.accepted_rows, 3)
        self.assertEqual(stats.count_666_sublicense, 2)
        self.assertEqual(stats.count_665_mainonly, 1)

        # Last row must be the 665 main-only domain
        self.assertEqual(rows[-1]["domain"], "onlymain.net")
        self.assertEqual(rows[-1]["has_service_subid"], 0)

        cn_row = next(r for r in rows if r["domain"] == "example.cn")
        self.assertEqual(cn_row["province"], "湖南省")
        self.assertEqual(cn_row["filed_on"], "2021-03-15")
        self.assertEqual(cn_row["updated_on"], "2026-01-10")

        rows_666_only, stats_666 = clean_icp_file(REPO_ROOT / "examples" / "sample_icp.csv", require_666=True)
        self.assertEqual(len(rows_666_only), 2)
        self.assertEqual(stats_666.skipped_665_filtered, 1)

        # Intake & authorized builders check
        intake_recs = to_intake_records(rows)
        self.assertEqual(len(intake_recs), 3)
        for rec in intake_recs:
            cleaned, err = validate_intake_record(rec)
            self.assertIsNone(err)
            self.assertIsNotNone(cleaned)
            self.assertNotIn("nature", cleaned["icp"])
            self.assertIn("subject_type", cleaned["icp"])

        auth_obs = to_authorized_icp_observations(rows, source_file_id="file_123")
        self.assertEqual(len(auth_obs), 3)
        self.assertTrue(all(o["kind"] == "icp" and o["source_refs"][0]["file_id"] == "file_123" for o in auth_obs))

    def test_gb18030_decoding_and_archive_non_destructive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "gbk_sample.csv"
            content = "域名,主办单位名称,主体备案号,网站备案号,省份\r\nwww.gbktest.com,广东测试企业,粤ICP备2023000111号,粤ICP备2023000111号-1,\r\n"
            p.write_bytes(content.encode("gb18030"))
            rows, stats = clean_icp_file(p)
            self.assertEqual(stats.accepted_rows, 1)
            self.assertEqual(rows[0]["domain"], "gbktest.com")
            self.assertEqual(rows[0]["province"], "广东省")

            res_dir = Path(tmp) / "result"
            d1 = archive_raw_input(p, "46", "广东省", "快照", res_dir)
            d2 = archive_raw_input(p, "46", "广东省", "快照", res_dir)
            self.assertEqual(d1, d2)
            p.write_bytes((content + "extra.com,企业B,粤ICP备2023000222号,粤ICP备2023000222号-1,广东\r\n").encode("gb18030"))
            d3 = archive_raw_input(p, "46", "广东省", "快照", res_dir)
            self.assertNotEqual(d1, d3)
            self.assertTrue(d1.is_file() and d3.is_file())

    def test_strip_llm_artifacts(self) -> None:
        raw = '```json\n[{"domain": "foo.cn", "subject": "测试公司[citation:1]", "main_license": "京ICP备1号[2]"}]\n```'
        parsed = json.loads(strip_llm_artifacts(raw))
        self.assertEqual(parsed[0]["subject"], "测试公司")
        self.assertEqual(parsed[0]["main_license"], "京ICP备1号")


class TestWhoisParsersAndEngine(unittest.TestCase):
    def test_rdap_parser_cases(self) -> None:
        valid_rdap = json.dumps(
            {
                "ldhName": "EXAMPLE.COM",
                "status": ["clientTransferProhibited"],
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-12-01T00:00:00Z"},
                ],
                "entities": [
                    {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar LLC"]]]}
                ],
            }
        )
        p1 = parse_rdap_json("example.com", valid_rdap, 200)
        self.assertEqual(p1["outcome"], "success")
        self.assertEqual(p1["registrar"], "Test Registrar LLC")
        self.assertEqual(p1["expiration_date"], "2026-12-01T00:00:00.000Z")

        # True Verisign 404
        true_404 = json.dumps({"errorCode": 404, "title": "Not Found"})
        self.assertEqual(parse_rdap_json("free.com", true_404, 404)["outcome"], "not_found")

        # Fake 404 HTML page -> must NEVER return not_found
        fake_404 = "<html><title>404 Not Found</title><body>nginx/edge block</body></html>"
        self.assertEqual(parse_rdap_json("example.com", fake_404, 404)["outcome"], "unavailable")

        # Conflicting expiration dates -> partial + flag
        conflict = json.dumps(
            {
                "events": [
                    {"eventAction": "expiration", "eventDate": "2026-12-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
                ]
            }
        )
        pc = parse_rdap_json("conflict.com", conflict, 200)
        self.assertTrue(pc["conflicting_expirations"])
        self.assertEqual(pc["outcome"], "partial")

    def test_cnnic_parser_anti_false_404_and_timezone(self) -> None:
        # Standard CNNIC response WITHOUT timezone suffix
        cn_no_tz = "\n".join(
            [
                "Domain Name: example.cn",
                "ROID: 20200101s10001s00000001-cn",
                "Domain Status: ok",
                "Domain Status: clientDeleteProhibited",
                "Sponsoring Registrar: 阿里云计算有限公司（万网）",
                "Registration Time: 2020-01-01 10:00:00",
                "Expiration Time: 2026-12-01 23:59:59",
            ]
        )
        parsed = parse_whois_text("example.cn", cn_no_tz, is_cnnic=True)
        self.assertEqual(parsed["outcome"], "success")
        self.assertFalse(parsed["has_explicit_timezone"])
        self.assertEqual(parsed["expiration_date"], "2026-12-01T15:59:59.000Z")
        self.assertEqual(parsed["statuses"], ["ok", "clientDeleteProhibited"])

        # Explicit timezone-aware WHOIS text
        cn_tz = "Domain Name: tz.cn\nDomain Status: pending delete\nRegistry Expiry Date: 2026-12-01T00:00:00Z\n"
        p_tz = parse_whois_text("tz.cn", cn_tz, is_cnnic=True)
        self.assertTrue(p_tz["has_explicit_timezone"])
        self.assertEqual(p_tz["statuses"], ["pending delete"])

        # Rate limit response containing "not found"-like noise must still stay unavailable
        rate_limited = "Query rate limit exceeded. Too many requests from your IP, please try again later."
        self.assertEqual(parse_whois_text("busy.cn", rate_limited, is_cnnic=True)["outcome"], "unavailable")

        # Real CNNIC unregistered phrase
        real_unreg = "The domain you requested is not exist"
        self.assertEqual(parse_whois_text("unreg.cn", real_unreg, is_cnnic=True)["outcome"], "not_found")

        # Empty response -> unavailable
        self.assertEqual(parse_whois_text("blank.cn", "", is_cnnic=True)["outcome"], "unavailable")

    def test_endpoint_routing_and_cc_fix(self) -> None:
        engine = SingleThreadWhoisEngine(WhoisQueryConfig())
        self.assertEqual(
            engine.resolve_target("sub.example.com"),
            ("example.com", "verisign_rdap", "rdap", "https://rdap.verisign.com/com/v1/domain/example.com"),
        )
        self.assertEqual(
            engine.resolve_target("example.cc"),
            ("example.cc", "verisign_rdap", "rdap", "https://tld-rdap.verisign.com/cc/v1/domain/example.cc"),
        )
        self.assertEqual(
            engine.resolve_target("www.foo.gd.cn"),
            ("foo.gd.cn", "cnnic_whois", "whois43", "whois.cnnic.cn:43"),
        )
        self.assertEqual(
            engine.resolve_target("example.org"),
            ("example.org", "registry_rdap", "rdap", "https://rdap.publicinterestregistry.org/rdap/domain/example.org"),
        )

    def test_checkpoint_and_port43_http_status_omission(self) -> None:
        class _WhoisMockHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                _ = self.rfile.readline()
                self.wfile.write(
                    b"Domain Name: live.cn\n"
                    b"Domain Status: ok\n"
                    b"Sponsoring Registrar: MockCnRegistrar\n"
                    b"Expiration Time: 2026-12-10 08:00:00\n"
                )

        server = socketserver.TCPServer(("127.0.0.1", 0), _WhoisMockHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ckpt = WhoisCheckpointStore(Path(tmp) / "ckpt.db")
                cfg = WhoisQueryConfig(cnnic_delay_min=0.0, cnnic_delay_max=0.0)
                engine = SingleThreadWhoisEngine(cfg, checkpoint=ckpt)
                res = engine._query_whois43_with_retry("live.cn", "cnnic_whois", "127.0.0.1", port, is_cnnic=True)
                self.assertEqual(res["outcome"], "success")
                self.assertIsNone(res["http_status"])
                ckpt.upsert(res, uploaded=False)

                bundles = to_hub_evidence_items([res])
                ev_entry = bundles[0]["evidence_entry"]
                obs = bundles[0]["observation"]
                self.assertNotIn("http_status", ev_entry)
                self.assertNotIn("http_status", obs["evidence"])
                self.assertEqual(ev_entry["observed_at"], obs["observed_at"])
                self.assertEqual(
                    obs["evidence"]["response_sha256"],
                    hashlib.sha256(ev_entry["response_text"].encode("utf-8")).hexdigest(),
                )
        finally:
            server.shutdown()
            server.server_close()


class _MockHubState:
    def __init__(self) -> None:
        self.batches: dict[str, dict[str, Any]] = {}
        self.files: dict[str, dict[str, Any]] = {}
        self.file_bytes: dict[str, bytes] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.receipt_items: dict[str, list[dict[str, Any]]] = {}
        self.seen_event_ids: set[str] = set()
        self.idem_requests: dict[str, tuple[str, int, bytes]] = {}
        self.intake_calls = 0
        self.simulate_rate_limit_once = False
        self.search_items = [
            {
                "domain": f"missing{i}.com",
                "registry_state": "expiring" if i == 0 else "unknown",
                "expiration_date": "2026-11-15T00:00:00.000Z" if i == 0 else None,
                "provider": "verisign_rdap",
                "icp_subject": f"企业{i}",
                "icp_license": f"沪ICP备20260000{i}号-1",
                "icp_subject_type": "企业",
            }
            for i in range(5)
        ]
        self.job_claimed = False
        self.job_completed_receipt: str | None = None
        self.rdap_base = ""


def _make_mock_handler(state: _MockHubState):
    class MockHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, code: int, obj: Any, headers: dict[str, str] | None = None) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _require_ua(self) -> bool:
            ua = self.headers.get("User-Agent", "")
            if "Python-urllib" in ua or not ua.strip():
                self._send_json(403, {"code": "waf_blocked", "message": "Missing custom User-Agent"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._require_ua():
                return
            parsed = urlsplit(self.path)
            path = parsed.path

            # Local mock RDAP endpoint for E2E job worker test
            if path.startswith("/mock-rdap/domain/"):
                dom = path.rsplit("/", 1)[-1]
                self._send_json(
                    200,
                    {
                        "ldhName": dom.upper(),
                        "status": ["clientTransferProhibited"],
                        "events": [{"eventAction": "expiration", "eventDate": "2027-01-15T00:00:00Z"}],
                    },
                )
                return

            if path == "/v1/health/ready":
                self._send_json(200, {"status": "ready"})
                return
            if path == "/v1/collectors/me":
                if self.headers.get("Authorization") != "Bearer test-token":
                    self._send_json(401, {"code": "unauthorized", "message": "Invalid token"})
                    return
                self._send_json(
                    200,
                    {"id": "col_test", "name": "MockCollector", "scopes": ["ingest", "read", "export"], "providers": ["verisign_rdap", "cnnic_whois", "miit_snapshot"]},
                )
                return
            if path.startswith("/v1/files/"):
                fid = path.split("/")[3]
                if fid not in state.files:
                    self._send_json(404, {"code": "not_found"})
                    return
                self._send_json(200, state.files[fid])
                return
            if path.startswith("/v1/ingest-receipts/"):
                parts = path.strip("/").split("/")
                rid = parts[2]
                if len(parts) == 3:
                    self._send_json(200, state.receipts[rid])
                elif len(parts) == 4 and parts[3] == "items":
                    qs = parse_qs(parsed.query)
                    cur = int((qs.get("cursor") or ["0"])[0])
                    all_it = state.receipt_items.get(rid, [])
                    page = all_it[cur : cur + 2]
                    nxt = str(cur + len(page)) if cur + len(page) < len(all_it) else None
                    self._send_json(200, {"items": page, "next_cursor": nxt})
                return
            self._send_json(404, {"code": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._require_ua():
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length)
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            path = urlsplit(self.path).path
            idem = self.headers.get("Idempotency-Key") or ""

            if path == "/v1/intake":
                state.intake_calls += 1
                if state.simulate_rate_limit_once:
                    state.simulate_rate_limit_once = False
                    self._send_json(429, {"code": "public_intake_rate", "message": "Slow down"}, headers={"Retry-After": "1"})
                    return
                body_hash = hashlib.sha256(raw_body).hexdigest()
                if idem and idem in state.idem_requests and state.idem_requests[idem][0] != body_hash:
                    self._send_json(409, {"code": "idempotency_conflict", "message": "Conflict"})
                    return
                state.idem_requests[idem] = (body_hash, 200, raw_body)
                recs = body.get("records") or []
                rejected = []
                accepted = 0
                for idx, r in enumerate(recs):
                    if not isinstance(r, dict) or "invalid.fail" in str(r.get("domain")):
                        rejected.append({"index": idx, "code": "invalid_domain", "message": "Invalid"})
                    else:
                        accepted += 1
                self._send_json(
                    200,
                    {
                        "id": f"rcpt-intake-{state.intake_calls}",
                        "state": "partial" if rejected else "processed",
                        "accepted_records": accepted,
                        "accepted_observations": accepted,
                        "rejected": rejected,
                    },
                )
                return

            if self.headers.get("Authorization") != "Bearer test-token":
                self._send_json(401, {"code": "unauthorized"})
                return

            if path == "/v1/batches":
                bid = f"batch_{len(state.batches) + 1}"
                res = {"id": bid, "batch_id": bid, "display_seq": len(state.batches) + 1, **body}
                state.batches[bid] = res
                self._send_json(201, res)
                return

            if path == "/v1/files":
                fid = f"file_{len(state.files) + 1}"
                res = {
                    "id": fid,
                    "file_id": fid,
                    "state": "pending",
                    "upload_url": f"/v1/files/{fid}/content",
                    **body,
                }
                state.files[fid] = res
                self._send_json(201, res)
                return

            if path == "/v1/observations:batch":
                rid = f"00000000-0000-4000-8000-0000000000{len(state.receipts)+1:02d}"
                items_out = []
                acc = dup = rej = 0
                for idx, rec in enumerate(body.get("records") or []):
                    ev_id = rec["event_id"]
                    ev_meta = rec.get("evidence")
                    if ev_meta:
                        raw_f = state.file_bytes.get(ev_meta["file_id"], b"").decode("utf-8").splitlines()
                        entry = json.loads(raw_f[ev_meta["record_index"]])
                        if entry["observed_at"] != rec["observed_at"] or entry.get("http_status") != ev_meta.get("http_status"):
                            items_out.append({"item_index": idx, "state": "rejected", "error_code": "evidence_metadata"})
                            rej += 1
                            continue
                    if ev_id in state.seen_event_ids:
                        items_out.append({"item_index": idx, "event_id": ev_id, "state": "duplicate"})
                        dup += 1
                    else:
                        state.seen_event_ids.add(ev_id)
                        items_out.append({"item_index": idx, "event_id": ev_id, "state": "accepted"})
                        acc += 1
                state.receipt_items[rid] = items_out
                rcpt = {"id": rid, "state": "partial" if rej else "processed", "pending": 0, "accepted": acc, "duplicate": dup, "rejected": rej}
                state.receipts[rid] = rcpt
                self._send_json(202, rcpt)
                return

            if path == "/v1/candidates/search":
                limit = int(body.get("limit") or 2)
                cur_str = body.get("cursor")
                offset = int(cur_str.split(":")[1]) if cur_str and ":" in cur_str else 0
                page = state.search_items[offset : offset + limit]
                nxt = f"snap1:{offset + len(page)}" if offset + len(page) < len(state.search_items) else None
                self._send_json(200, {"snapshot_id": "snap1", "total": len(state.search_items), "items": page, "next_cursor": nxt})
                return

            if path == "/v1/jobs:claim":
                if not state.job_claimed:
                    state.job_claimed = True
                    self._send_json(200, {"job": {"id": "job_1", "domain": "worker-test.com", "provider": "verisign_rdap", "attempts": 1, "lease_token": "lease_1"}})
                else:
                    self._send_json(200, {"job": None})
                return

            if path == "/v1/jobs/job_1/heartbeat":
                self._send_json(200, {"ok": True})
                return

            if path == "/v1/jobs/job_1/complete":
                state.job_completed_receipt = body.get("receipt_id")
                self._send_json(200, {"ok": True})
                return

            self._send_json(404, {"code": "not_found"})

        def do_PUT(self) -> None:  # noqa: N802
            if not self._require_ua():
                return
            path = urlsplit(self.path).path
            if path.startswith("/v1/files/") and path.endswith("/content"):
                fid = path.split("/")[3]
                length = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(length)
                sha = hashlib.sha256(data).hexdigest()
                if sha != state.files[fid]["sha256"]:
                    self._send_json(422, {"code": "sha256_mismatch"})
                    return
                state.file_bytes[fid] = data
                state.files[fid]["state"] = "verified"
                self._send_json(200, state.files[fid])
                return
            self._send_json(404, {"code": "not_found"})

    return MockHandler


class TestHubIntegrationAndCli(unittest.TestCase):
    def setUp(self) -> None:
        self.state = _MockHubState()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_mock_handler(self.state))
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_intake_partial_retry_429_and_409_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hub = DomainHubClient(
                self.base_url,
                timeout_sec=10.0,
                outbox_path=Path(tmp) / "outbox.db",
            )
            self.state.simulate_rate_limit_once = True
            records = [
                {"domain": "good1.com", "icp": {"subject": "好企业"}},
                {"domain": "invalid.fail", "icp": {"subject": "触发服务端拒绝"}},
                {"domain": "101.227.52.182", "icp": {"subject": "触发本地拒绝"}},
            ]
            res = hub.submit_intake(records, chunk_size=20, delay_sec=0.0)
            self.assertEqual(res["accepted_records"], 1)
            self.assertEqual(len(res["locally_invalid"]), 1)
            self.assertEqual(len(res["server_rejected"]), 1)
            rejected_saved = hub.outbox.list_rejected_intake()
            self.assertEqual(len(rejected_saved), 2)

            # Verify 409 idempotency_conflict classification
            with self.assertRaises(HubClientError) as ctx:
                hub.request_json("POST", "/v1/intake", json_body={"records": [{"domain": "a.com", "icp": {"subject": "A"}}]}, auth_required=False, idem_key="fixed-key")
                hub.request_json("POST", "/v1/intake", json_body={"records": [{"domain": "b.com", "icp": {"subject": "B"}}]}, auth_required=False, idem_key="fixed-key")
            self.assertEqual(ctx.exception.http_status, 409)
            self.assertEqual(ctx.exception.category, "input_error")

    def test_authorized_chunked_evidence_and_cursor_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hub = DomainHubClient(
                self.base_url,
                token="test-token",
                timeout_sec=10.0,
                outbox_path=Path(tmp) / "outbox.db",
            )
            batch = hub.create_batch("湖南省", "E2E test", "whois_verification")
            bid = batch["batch_id"]

            # Generate oversized evidence entries to force multi-file JSONL splitting
            large_text = "Domain Name: example.com\n" + ("X" * 320_000)
            obs_items = []
            for idx in range(4):
                obs_at = f"2026-11-11T03:20:0{idx}.123Z"
                sha = hashlib.sha256(large_text.encode("utf-8")).hexdigest()
                obs_items.append(
                    {
                        "evidence_entry": {
                            "endpoint": "whois.cnnic.cn:43",
                            "observed_at": obs_at,
                            "response_text": large_text,
                        },
                        "observation": {
                            "event_id": f"whois_cnnic_test{idx}_{sha[:10]}",
                            "domain": f"test{idx}.cn",
                            "kind": "registration",
                            "provider": "cnnic_whois",
                            "observed_at": obs_at,
                            "outcome": "success",
                            "data": {"expiration_date": "2026-12-01T15:59:59.000Z"},
                            "evidence": {"endpoint": "whois.cnnic.cn:43", "response_sha256": sha},
                        },
                    }
                )

            up = hub.upload_evidence_jsonl_and_observations(bid, obs_items, wait_receipts=True)
            self.assertEqual(len(up["files"]), 2)
            self.assertEqual(up["accepted"], 4)
            self.assertEqual(up["rejected"], 0)

            # Re-submitting identical events should classify cleanly as duplicate (NOT error)
            up_dup = hub.upload_evidence_jsonl_and_observations(bid, obs_items, wait_receipts=True)
            self.assertEqual(up_dup["duplicates"], 4)
            self.assertEqual(up_dup["rejected"], 0)

            # Cursor search iterating all 5 mock items across 3 pages (page_size=2)
            pulled = list(hub.iter_candidates({"evidence_scope": "all"}, page_size=2))
            self.assertEqual([p["domain"] for p in pulled], [f"missing{i}.com" for i in range(5)])

    def test_cli_end_to_end_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            result_dir = Path(tmp) / "result"
            cleaned_jsonl = state_dir / "cleaned.jsonl"
            domains_txt = state_dir / "domains.txt"
            missing_txt = state_dir / "missing.txt"
            out_csv = result_dir / "01_湖南省_Hub导出_有序结果.csv"

            rc = cli_main(["--hub-url", self.base_url, "--token", "test-token", "--state-dir", str(state_dir), "verify"])
            self.assertEqual(rc, 0)

            rc = cli_main(
                [
                    "--state-dir",
                    str(state_dir),
                    "clean-icp",
                    "--input",
                    str(REPO_ROOT / "examples" / "sample_icp.csv"),
                    "--output",
                    str(cleaned_jsonl),
                    "--domains-out",
                    str(domains_txt),
                    "--archive-raw",
                    "--seq",
                    "01",
                    "--province",
                    "样例省",
                    "--desc",
                    "测试",
                    "--result-dir",
                    str(result_dir),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((result_dir / "raw_inputs" / "01_样例省_原始_测试.csv").is_file())

            rc = cli_main(
                [
                    "--hub-url",
                    self.base_url,
                    "--token",
                    "test-token",
                    "--state-dir",
                    str(state_dir),
                    "ingest-icp",
                    "--input",
                    str(REPO_ROOT / "examples" / "sample_icp.csv"),
                    "--province",
                    "样例省",
                ]
            )
            self.assertEqual(rc, 0)

            rc = cli_main(
                [
                    "--hub-url",
                    self.base_url,
                    "--token",
                    "test-token",
                    "--state-dir",
                    str(state_dir),
                    "pull-missing",
                    "--limit",
                    "0",
                    "--page-size",
                    "2",
                    "--output",
                    str(missing_txt),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(len(missing_txt.read_text(encoding="utf-8").splitlines()), 5)

            rc = cli_main(
                [
                    "--hub-url",
                    self.base_url,
                    "--token",
                    "test-token",
                    "--state-dir",
                    str(state_dir),
                    "export-csv",
                    "--from-hub",
                    "--output",
                    str(out_csv),
                    "--max-days",
                    "30",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out_csv.is_file())

    def test_job_worker_once_and_sync_whois(self) -> None:
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            fake_rdap_url = f"{self.base_url}/mock-rdap/domain/worker-test.com"
            with patch(
                "agent_workflow.whois_single.SingleThreadWhoisEngine.resolve_target",
                return_value=("worker-test.com", "verisign_rdap", "rdap", fake_rdap_url),
            ):
                rc = cli_main(
                    [
                        "--hub-url",
                        self.base_url,
                        "--token",
                        "test-token",
                        "--state-dir",
                        str(state_dir),
                        "job-worker",
                        "--once",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIsNotNone(self.state.job_completed_receipt)

            # Also verify checkpoint -> sync-whois flow
            ckpt = WhoisCheckpointStore(state_dir / "whois_checkpoint.db")
            ckpt.upsert(
                {
                    "domain": "syncdemo.cn",
                    "provider": "cnnic_whois",
                    "endpoint": "whois.cnnic.cn:43",
                    "outcome": "success",
                    "http_status": None,
                    "observed_at": "2026-11-11T03:20:00.123Z",
                    "expiration_date": "2026-12-01T15:59:59.000Z",
                    "creation_date": "2020-01-01T00:00:00.000Z",
                    "registrar": "TestReg",
                    "statuses": ["ok"],
                    "data": {"expiration_date": "2026-12-01T15:59:59.000Z"},
                    "response_text": "Domain Name: syncdemo.cn\nExpiration Time: 2026-12-01 23:59:59\n",
                    "response_sha256": hashlib.sha256(
                        b"Domain Name: syncdemo.cn\nExpiration Time: 2026-12-01 23:59:59\n"
                    ).hexdigest(),
                }
            )
            rc = cli_main(
                [
                    "--hub-url",
                    self.base_url,
                    "--token",
                    "test-token",
                    "--state-dir",
                    str(state_dir),
                    "sync-whois",
                    "--topic",
                    "测试同步",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(len(ckpt.list_results(only_unuploaded=True)), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
