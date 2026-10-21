"""CADP end-to-end integration test (stdlib only)."""

from __future__ import annotations

import http.cookiejar
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cadp  # noqa: E402


def solve_pow(ch):
    bits = int(ch["bits"])
    target = 1 << (32 - bits)
    n = 0
    while cadp.fnv1a(ch["id"] + ch["salt"] + str(n)) >= target:
        n += 1
    return n


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        base = Path(cls.td.name)
        (base / "site").mkdir()
        (base / "site" / "index.html").write_text("CADP test site", encoding="utf-8")
        cfg = {
            "listen_host": "127.0.0.1",
            "listen_port": 18081,
            "root": "site",
            "pool_size": 50,
            "challenge_groups": [
                {"id": "pow", "type": "pow_fnv", "bits": 8, "count": 1},
                {"id": "arith", "type": "arith", "count": 1},
            ],
            "admin": {"password_hash": cadp._hash_password("testpw")},
        }
        cls.cfg_path = base / "config.json"
        cls.cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        cadp.STATE = cadp.State(cls.cfg_path)
        cls.httpd = cadp.Server(("127.0.0.1", 18081), cadp.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.td.cleanup()

    def test_flow(self):
        base = "http://127.0.0.1:18081"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        # challenge page
        r = opener.open(base + "/", timeout=10)
        body = r.read().decode()
        self.assertIn("CADP", body)

        # start
        req = urllib.request.Request(base + "/__cadp/api/start",
                                     data=json.dumps({"next": "/"}).encode(),
                                     headers={"Content-Type": "application/json"})
        d = json.loads(opener.open(req, timeout=10).read())
        sid = d["sid"]
        for _ in range(6):
            ch = d["challenge"]
            if ch["type"] in ("pow_fnv", "mine", "pow_hard"):
                ans = solve_pow(ch)
            elif ch["type"] == "arith":
                ans = ch["answer"]
            else:
                self.fail(ch["type"])
            req = urllib.request.Request(base + "/__cadp/api/answer",
                                         data=json.dumps({"sid": sid, "answer": ans}).encode(),
                                         headers={"Content-Type": "application/json"})
            d = json.loads(opener.open(req, timeout=10).read())
            if d.get("done"):
                break
        self.assertTrue(d.get("done"), d)

        # pass cookie now allows static
        body = opener.open(base + "/", timeout=10).read().decode()
        self.assertIn("CADP test site", body)

        # admin login + stats
        admin_jar = http.cookiejar.CookieJar()
        admin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(admin_jar))
        data = urllib.parse.urlencode({"password": "testpw"}).encode()
        r = admin.open(urllib.request.Request(base + "/__cadp/admin/login", data=data), timeout=10)
        self.assertIn("CADP Admin", r.read().decode())
        stats = json.loads(admin.open(base + "/__cadp/admin/api/stats", timeout=10).read())
        self.assertIn("stats", stats)
        self.assertGreaterEqual(stats["stats"]["challenge_pass"], 2)

        # admin ban/unban
        req = urllib.request.Request(base + "/__cadp/admin/api/ban",
                                     data=json.dumps({"ip": "8.8.8.8", "seconds": 60}).encode(),
                                     headers={"Content-Type": "application/json"})
        self.assertTrue(json.loads(admin.open(req, timeout=10).read())["ok"])
        self.assertTrue(cadp.STATE.is_banned("8.8.8.8"))
        req = urllib.request.Request(base + "/__cadp/admin/api/unban",
                                     data=json.dumps({"ip": "8.8.8.8"}).encode(),
                                     headers={"Content-Type": "application/json"})
        admin.open(req, timeout=10).read()
        self.assertFalse(cadp.STATE.is_banned("8.8.8.8"))


class MonetizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        base = Path(cls.td.name)
        (base / "site").mkdir()
        (base / "site" / "index.html").write_text("CADP monetized site", encoding="utf-8")
        cfg = {
            "listen_host": "127.0.0.1",
            "listen_port": 18082,
            "root": "site",
            "pool_size": 30,
            "challenge_groups": [
                {"id": "pow", "type": "pow_fnv", "bits": 8, "count": 1},
            ],
            "monetization": {
                "enabled": True,
                "consent_ttl": 60,
                "groups": [
                    {"id": "work", "type": "mine", "bits": 8, "count": 1},
                ],
            },
            "admin": {"password_hash": cadp._hash_password("testpw")},
        }
        cls.cfg_path = base / "config.json"
        cls.cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        cadp.STATE = cadp.State(cls.cfg_path)
        cls.httpd = cadp.Server(("127.0.0.1", 18082), cadp.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.td.cleanup()

    def test_notice_consent_and_work(self):
        base = "http://127.0.0.1:18082"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        page = opener.open(base + "/", timeout=10).read().decode()
        self.assertIn("同意并继续", page)
        self.assertIn("如您不同意，请关闭页面", page)

        req = urllib.request.Request(base + "/__cadp/api/start",
                                     data=json.dumps({"next": "/"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            opener.open(req, timeout=10)
        self.assertEqual(ctx.exception.code, 403)

        req = urllib.request.Request(base + "/__cadp/api/consent",
                                     data=json.dumps({"agree": True}).encode(),
                                     headers={"Content-Type": "application/json"})
        self.assertTrue(json.loads(opener.open(req, timeout=10).read())["ok"])

        req = urllib.request.Request(base + "/__cadp/api/start",
                                     data=json.dumps({"next": "/"}).encode(),
                                     headers={"Content-Type": "application/json"})
        d = json.loads(opener.open(req, timeout=10).read())
        sid = d["sid"]
        for _ in range(6):
            ch = d["challenge"]
            if ch["type"] in ("pow_fnv", "mine", "pow_hard"):
                ans = solve_pow(ch)
            elif ch["type"] == "arith":
                ans = ch["answer"]
            else:
                self.fail(ch["type"])
            req = urllib.request.Request(base + "/__cadp/api/answer",
                                         data=json.dumps({"sid": sid, "answer": ans}).encode(),
                                         headers={"Content-Type": "application/json"})
            d = json.loads(opener.open(req, timeout=10).read())
            if d.get("done"):
                break
        self.assertTrue(d.get("done"), d)

        body = opener.open(base + "/", timeout=10).read().decode()
        self.assertIn("CADP monetized site", body)
        work = Path(self.td.name) / "work.jsonl"
        self.assertTrue(work.exists())
        self.assertIn('"group": "work"', work.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
