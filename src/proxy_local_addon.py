"""mitmdump 捕获 addon（local 模式子进程方案）

由 mitmdump 以 `-s` 加载，运行在独立子进程中（绕开服务进程内嵌 DumpMaster
的 local redirector IPC 握手卡死问题）。捕获到的请求/响应以 JSONL 追加写入
MINIHUNT_CAPTURE_FILE 环境变量指定的文件，由主服务 tail 解析入库。

每行一条 JSON，字段与 ProxyCapture 内存条目保持一致：
    type / ts / url / method / headers / postData / status / result | error
会话凭证单独放在 _creds（主服务解析后并入 session_credentials）。
"""

import json
import os
import re
import time

_OUT = os.environ.get("MINIHUNT_CAPTURE_FILE", "")
_MAX_BODY = 4000

_CRED_HEADERS = {
    "cookie", "authorization", "x-token", "token", "access-token",
    "x-session-id", "sessionid", "x-csrf-token", "x-xsrf-token",
}

# 值特征识别疑似凭证（自定义签名头无白名单可用时的自动兜底，与主服务同规则）
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$")
_RAND_RE = re.compile(r"^[A-Za-z0-9+/=_.\-]{32,}$")
_CRED_NAME_HINTS = ("token", "sign", "auth", "key", "session", "ticket", "secret", "nonce")
_NON_CRED_NAMES = {"user-agent", "referer", "accept", "if-none-match",
                   "if-modified-since", "etag", "content-md5"}
# 微信宿主环境头（r9）：宿主进程自用的上报/会话头，不是小程序业务凭证——
# x-wx-wxareportob-token（名字含 token 命中值特征）实测混入 session_credentials
# 被自动随重放携带，no_credentials 未授权测试屏蔽名单又不含它 → 测试不纯。
# 宿主头一律不收编（业务后端不认这些头，不收编不影响测试能力）
_HOST_NAME_HINTS = ("x-wx-", "wx-", "pass_ticket", "passid", "softid", "weixinuin")


def _is_host_header(name_lower):
    return any(name_lower.startswith(p) or name_lower == p for p in _HOST_NAME_HINTS)


def _looks_like_cred(name_lower, value):
    """值长得像凭证 → 疑似凭证头；JWT 三段式命中即判，
    其余要求 ≥32 位无空格随机串 + 名字带凭证意味"""
    if name_lower in _NON_CRED_NAMES or _is_host_header(name_lower):
        return False
    if not value or len(value) < 24 or " " in value.strip():
        return False
    v = value.strip()
    if _JWT_RE.match(v):
        return True
    name_cred = any(t in name_lower for t in _CRED_NAME_HINTS)
    return bool(name_cred and _RAND_RE.match(v))


class MinihuntCapture:
    def response(self, flow):
        self._write(flow, error=None)

    def error(self, flow):
        self._write(flow, error=str(getattr(flow, "error", None) or "连接失败"))

    def _write(self, flow, error):
        if not _OUT:
            return
        try:
            req = flow.request
            entry = {
                "type": "proxy",
                "ts": time.time(),
                "url": req.pretty_url,
                "method": req.method,
                "headers": dict(req.headers),
                "postData": req.get_text() or "",
            }
            resp = getattr(flow, "response", None)
            if resp is not None and error is None:
                try:
                    body = resp.get_text(strict=False) or ""
                except Exception:
                    body = ""
                entry["status"] = resp.status_code
                entry["result"] = {
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": body[:_MAX_BODY],
                }
            else:
                entry["status"] = "error"
                entry["error"] = error
            creds = {}
            try:
                for k, v in req.headers.items():
                    kl = k.lower()
                    if v and not _is_host_header(kl) and (kl in _CRED_HEADERS or _looks_like_cred(kl, v)):
                        creds[k] = v
            except Exception:
                pass
            if creds:
                entry["_creds"] = creds
            with open(_OUT, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass


addons = [MinihuntCapture()]
