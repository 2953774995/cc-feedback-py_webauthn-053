#!/usr/bin/env python3
"""验收探针：WebAuthn 注册响应批量审计（6 条契约）。响应现场构造，纯离线。"""
import sys, time, json, base64, hashlib
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from webauthn.audit import audit_registrations
    return audit_registrations

CHALLENGE = base64.urlsafe_b64encode(b"challenge-0123456789").decode().rstrip("=")
ORIGIN = "https://vault.example.com"
RPID = "vault.example.com"

def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def response(*, typ="webauthn.create", challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID,
             flags=0x41, counter=0):
    cd = json.dumps({"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": False})
    auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big") \
        + b"\x00" * 16 + b"\x00\x00" + b"\x00" * 64
    return {"clientDataJSON": b64u(cd.encode()), "authData": b64u(auth)}

@probe("P01 批量入口与合规响应")
def p01():
    fn = api(); out = fn([response()], challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID)
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "type", "origin", "user_present", "user_verified", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合规响应应 ok，实际 {item['reason']}"
    assert item["origin"] == ORIGIN and item["user_present"] is True and item["user_verified"] is False

@probe("P02 challenge 不匹配")
def p02():
    fn = api(); item = fn([response(challenge=b64u(b"another-challenge"))], challenge=CHALLENGE,
                          origin=ORIGIN, rp_id=RPID).items[0]
    assert item["reason"] == "challenge_mismatch", f"应为 challenge_mismatch，实际 {item['reason']}"

@probe("P03 origin 与 type 不符")
def p03():
    fn = api(); out = fn([response(origin="https://evil.example.com"),
                          response(typ="webauthn.get")], challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID)
    assert out.items[0]["reason"] == "origin_mismatch", f"应为 origin_mismatch，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "bad_type", f"应为 bad_type，实际 {out.items[1]['reason']}"

@probe("P04 rpIdHash 与 UP 标志")
def p04():
    fn = api(); out = fn([response(rp_id="other.example.com"), response(flags=0x40)],
                          challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID)
    assert out.items[0]["reason"] == "rp_id_mismatch", f"应为 rp_id_mismatch，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "user_not_present", f"应为 user_not_present，实际 {out.items[1]['reason']}"

@probe("P05 结构损坏")
def p05():
    fn = api(); bad = response(); bad["clientDataJSON"] = "!!not-base64!!"
    out = fn([bad, {"clientDataJSON": b64u(b"{}"), "authData": b64u(b"short")}],
             challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID)
    assert out.items[0]["reason"] == "malformed", f"应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "malformed", f"authData 过短应 malformed，实际 {out.items[1]['reason']}"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api(); good = response()
    out = fn([good, response(origin="https://evil.example.com"), "junk"], challenge=CHALLENGE,
             origin=ORIGIN, rp_id=RPID)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("origin_mismatch") == 1 and st["by_reason"].get("malformed") == 1, st["by_reason"]
    empty = fn([], challenge=CHALLENGE); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    recs = [dict(good) for _ in range(200)]
    t0 = time.perf_counter(); out2 = fn(recs, challenge=CHALLENGE, origin=ORIGIN, rp_id=RPID)
    cost = time.perf_counter() - t0
    assert len(out2.items) == 200 and cost < 1.0, f"200 条耗时 {cost:.2f}s 超过 1s"

def main():
    print("=" * 60); print("验收探针：WebAuthn 注册响应批量审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
