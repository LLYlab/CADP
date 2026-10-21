"""CADP core self-tests (stdlib unittest, no third-party deps)."""

from __future__ import annotations

import json
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cadp  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent


def _path(name: str) -> Path:
    return TESTS_DIR / f"_cadp_{name}_{uuid.uuid4().hex}"


class StubPool:
    def __init__(self):
        self.i = 0

    def next(self):
        self.i += 1
        return {"id": f"{self.i:016x}", "salt": "abcdef0123456789"}


def solve_pow(ch):
    bits = int(ch["bits"])
    target = 1 << (32 - bits)
    n = 0
    while cadp.fnv1a(ch["id"] + ch["salt"] + str(n)) >= target:
        n += 1
    return n


def train_linear(ch):
    w1 = w2 = b = 0.0
    lr = float(ch["lr"])
    for _ in range(int(ch["epochs"])):
        for x, y in zip(ch["X"], ch["y"]):
            pred = w1 * x[0] + w2 * x[1] + b
            err = pred - y
            w1 -= lr * err * x[0]
            w2 -= lr * err * x[1]
            b -= lr * err
    return [w1, w2, b]


class CadpTests(unittest.TestCase):
    def test_fnv(self):
        self.assertEqual(cadp.fnv1a("a"), 0xE40C292C)

    def test_pow_and_mine(self):
        for typ in ("pow_fnv", "mine", "pow_hard"):
            ch = {"type": typ, "id": "0011223344556677",
                  "salt": "8899aabbccddeeff", "bits": 8}
            n = solve_pow(ch)
            self.assertTrue(cadp.verify_challenge(ch, n)[0])
            self.assertFalse(cadp.verify_challenge(ch, n + 1)[0])

    def test_arith(self):
        ch = cadp.build_challenge({"type": "arith"}, StubPool())
        self.assertTrue(cadp.verify_challenge(ch, ch["answer"])[0])
        self.assertFalse(cadp.verify_challenge(ch, ch["answer"] + 1)[0])

    def test_linear_train(self):
        ch = cadp.build_challenge(
            {"type": "linear_train", "samples": 30, "epochs": 120,
             "lr": 0.05, "threshold": 0.01}, StubPool())
        weights = train_linear(ch)
        ok, detail = cadp.verify_challenge(ch, weights)
        self.assertTrue(ok, detail)
        self.assertFalse(cadp.verify_challenge(ch, [0, 0, 0])[0])

    def test_pool_rotation(self):
        pool_path = _path("pool").with_suffix(".json")
        try:
            pool = cadp.ChallengePool(pool_path, 8)
            seen = {pool.next()["id"] for _ in range(8)}
            self.assertEqual(len(seen), 8)
            self.assertIn(pool.next()["id"], seen)
        finally:
            for p in (pool_path, pool_path.with_name(pool_path.stem + "_state.json")):
                try:
                    p.unlink()
                except OSError:
                    pass

    def test_password_hash(self):
        stored = cadp._hash_password("hunter2")
        self.assertTrue(cadp._verify_password("hunter2", stored))
        self.assertFalse(cadp._verify_password("hunter3", stored))

    def test_state_multi_group(self):
        cfg_path = _path("config").with_suffix(".json")
        cfg = {
            "root": ".",
            "pool_size": 10,
            "challenge_groups": [
                {"id": "pow", "type": "pow_fnv", "bits": 8, "count": 1},
                {"id": "arith", "type": "arith", "count": 1},
            ],
            "admin": {"password_hash": cadp._hash_password("pw")},
        }
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        try:
            st = cadp.State(cfg_path)
            res = st.start("1.2.3.4", "/")
            sid = res["sid"]
            self.assertFalse(res["done"])
            for _ in range(6):
                ch = res["challenge"]
                if ch["type"] in ("pow_fnv", "mine", "pow_hard"):
                    ans = solve_pow(ch)
                elif ch["type"] == "arith":
                    ans = ch["answer"]
                elif ch["type"] == "linear_train":
                    ans = train_linear(ch)
                else:
                    self.fail(ch["type"])
                res = st.answer(sid, ans)
                if res.get("done"):
                    break
            self.assertTrue(res.get("done"), res)

            token = st.make_pass("1.2.3.4")
            self.assertTrue(st.verify_pass(token, "1.2.3.4"))
            self.assertFalse(st.verify_pass(token, "5.6.7.8"))

            st.ban("9.9.9.9", "test", 60)
            self.assertTrue(st.is_banned("9.9.9.9"))
            st.unban("9.9.9.9")
            self.assertFalse(st.is_banned("9.9.9.9"))
        finally:
            for name in ("config", "challenge_pool", "challenge_pool_state",
                         "bans", "cadp_secret", "access", "security"):
                for p in TESTS_DIR.glob(f"_cadp_{name}_*"):
                    try:
                        p.unlink()
                    except OSError:
                        pass
            for p in (TESTS_DIR / "challenge_pool.json",
                      TESTS_DIR / "challenge_pool_state.json",
                      TESTS_DIR / "bans.json",
                      TESTS_DIR / "cadp_secret",
                      TESTS_DIR / "access.log",
                      TESTS_DIR / "security.log"):
                try:
                    p.unlink()
                except OSError:
                    pass
            try:
                cfg_path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
