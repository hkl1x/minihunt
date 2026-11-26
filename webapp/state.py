"""
全局应用状态 — 连接管理、事件推送、组件绑定
"""
import asyncio
import json
from typing import Optional


class AppState:
    def __init__(self):
        self.engine = None
        self.navigator = None
        self.cloud_auditor = None
        self.wxapi_auditor = None
        self.logger = None
        self.ai_manager = None
        self.agent = None
        self.report_builder = None
        # 内嵌 HTTP 捕获代理（方案 A：解密代理抓业务流量）
        self.proxy_capture = None

        self.ws_clients = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # 数据缓存
        self.cloud_calls = []
        self.wxapi_calls = []
        self.agent_messages = []
        self.report_data = {}

        # Skill 列表（可持久化）：[{name, description, prompt, enabled}]
        self.skills = []

        # 敏感信息汇总（agent 反编译/扫描后入库）
        # {category: [values]}  category: api_path / secret / mobile / mail / jwt / sfz / url / custom:xxx
        self.sensitive_findings = {}
        self.sensitive_meta = {"source": "", "appid": "", "files_scanned": 0, "updated_at": ""}

    # ── Skill / 敏感信息 ──

    def add_sensitive(self, results: dict, source: str = "", appid: str = "", files_scanned: int = 0):
        """合并一次扫描结果入库，并通过 WebSocket 通知前端刷新"""
        merged = {
            "path": "api_path",      # 路径 → API 路径
            "incomplete_path": "api_path",
            "url": "url",
            "ip_port": "url",
            "secret": "secret",
            "jwt": "jwt",
            "mobile": "mobile",
            "mail": "mail",
            "sfz": "sfz",
        }
        for cat, items in (results or {}).items():
            if not items:
                continue
            bucket = merged.get(cat, f"custom:{cat}" if not cat.startswith("custom:") else cat)
            self.sensitive_findings.setdefault(bucket, [])
            for v in items:
                if v not in self.sensitive_findings[bucket]:
                    self.sensitive_findings[bucket].append(v)
        if source:
            self.sensitive_meta["source"] = source
        if appid:
            self.sensitive_meta["appid"] = appid
        if files_scanned:
            self.sensitive_meta["files_scanned"] = files_scanned
        import time as _t
        self.sensitive_meta["updated_at"] = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime())
        total = sum(len(v) for v in self.sensitive_findings.values())
        self.push_event({"type": "sensitive", "data": {"total": total, "meta": self.sensitive_meta}})

    def enabled_skills(self):
        return [s for s in self.skills if s.get("enabled")]

    def bind(self, engine, navigator, cloud_auditor, wxapi_auditor, logger, ai_manager, agent, report_builder):
        self.engine = engine
        self.navigator = navigator
        self.cloud_auditor = cloud_auditor
        self.wxapi_auditor = wxapi_auditor
        self.logger = logger
        self.ai_manager = ai_manager
        self.agent = agent
        self.report_builder = report_builder

    # ── 推送 ──

    def push_log(self, level: str, text: str):
        self.push_event({"type": "log", "data": {"level": level, "text": text, "ts": _now()}})

    def push_event(self, event: dict):
        """线程安全推送事件到所有 WebSocket 客户端"""
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._broadcast(event), self._loop)
        except RuntimeError:
            pass

    async def _broadcast(self, event: dict):
        text = json.dumps(event, ensure_ascii=False, default=str)
        dead = []
        for ws in list(self.ws_clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ws_clients.discard(ws)

    def push_event_sync(self, event: dict):
        """在已有 event loop 上下文中直接调用"""
        asyncio.ensure_future(self._broadcast(event))


def _now():
    import time
    return int(time.time() * 1000)
