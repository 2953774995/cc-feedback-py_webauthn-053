"""离线批量审计 WebAuthn 注册响应（clientDataJSON + authData）。

只做结构完整性与一致性复检：challenge / origin / rpIdHash / 用户在场标志，
不做签名验签、不解析 attestation、不联网。单条失败不抛异常，整批聚合返回。
"""

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# clientDataJSON.type 期望值（注册）
_TYPE_CREATE = "webauthn.create"

# authData 最小长度：rpIdHash(32) + flags(1) + signCount(4)
_AUTH_DATA_MIN_LEN = 37

# flags 位
_FLAG_UP = 0x01  # User Present
_FLAG_UV = 0x04  # User Verified

# 检查顺序即 reason 优先级：结构损坏优先于语义不符
_REASON_ORDER = (
    "malformed",
    "bad_type",
    "challenge_mismatch",
    "origin_mismatch",
    "rp_id_mismatch",
    "user_not_present",
    "user_not_verified",
)


@dataclass
class AuditResult:
    """批量审计结果：items 为逐条明细，stats 为聚合统计。"""

    items: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(
        default_factory=lambda: {"ok": 0, "bad": 0, "by_reason": {}}
    )


def _b64url_decode(value: Any) -> bytes:
    """解码 base64url（无填充）。非法输入抛异常，由调用方归类为 malformed。"""
    if not isinstance(value, str):
        raise ValueError("not a base64url string")
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)


def _audit_one(
    record: Any,
    index: int,
    challenge: Optional[str],
    origin: Optional[str],
    rp_id_hash: Optional[bytes],
    require_user_verification: bool,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "index": index,
        "ok": False,
        "reason": "ok",
        "type": None,
        "origin": None,
        "user_present": False,
        "user_verified": False,
        "issues": [],
    }
    issues: List[str] = item["issues"]

    # ---- 结构检查：任一失败即 malformed，不再做语义检查 ----
    if not isinstance(record, dict):
        issues.append("malformed")
    else:
        try:
            client_data_raw = _b64url_decode(record.get("clientDataJSON"))
            client_data = json.loads(client_data_raw.decode("utf-8"))
            if not isinstance(client_data, dict):
                raise ValueError("clientDataJSON is not a JSON object")
            auth_data = _b64url_decode(record.get("authData"))
            if len(auth_data) < _AUTH_DATA_MIN_LEN:
                raise ValueError("authData too short")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            issues.append("malformed")
        else:
            # ---- 语义检查：按优先级收集全部命中项 ----
            item["type"] = client_data.get("type")
            item["origin"] = client_data.get("origin")

            flags = auth_data[32]
            item["user_present"] = bool(flags & _FLAG_UP)
            item["user_verified"] = bool(flags & _FLAG_UV)

            if item["type"] != _TYPE_CREATE:
                issues.append("bad_type")
            if challenge is not None and client_data.get("challenge") != challenge:
                issues.append("challenge_mismatch")
            if origin is not None and item["origin"] != origin:
                issues.append("origin_mismatch")
            if rp_id_hash is not None and auth_data[:32] != rp_id_hash:
                issues.append("rp_id_mismatch")
            if not item["user_present"]:
                issues.append("user_not_present")
            if require_user_verification and not item["user_verified"]:
                issues.append("user_not_verified")

    if issues:
        # reason 取优先级最高的命中项
        item["reason"] = next(r for r in _REASON_ORDER if r in issues)
    else:
        item["ok"] = True
    return item


def audit_registrations(
    responses: List[Dict[str, Any]],
    challenge: Optional[str] = None,
    origin: Optional[str] = None,
    rp_id: Optional[str] = None,
    require_user_verification: bool = False,
) -> AuditResult:
    """批量复检注册响应。

    Args:
        responses: 字典列表，每项含 clientDataJSON / authData（base64url，无填充）。
        challenge: 期望的 challenge（base64url 字符串，逐字符比对）。
        origin: 期望的 origin（含协议与端口，完全一致）。
        rp_id: 本站 RP ID，用于比对 authData 前 32 字节的 rpIdHash。
        require_user_verification: 为 True 时要求 UV 标志置位。

    Returns:
        AuditResult，含 items（逐条明细）与 stats（ok/bad/by_reason）。
    """
    result = AuditResult()
    if not responses:
        return result

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest() if rp_id else None

    for index, record in enumerate(responses):
        item = _audit_one(record, index, challenge, origin, rp_id_hash,
                          require_user_verification)
        result.items.append(item)
        if item["ok"]:
            result.stats["ok"] += 1
        else:
            result.stats["bad"] += 1
            by_reason = result.stats["by_reason"]
            by_reason[item["reason"]] = by_reason.get(item["reason"], 0) + 1

    return result
