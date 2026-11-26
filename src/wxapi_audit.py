"""
WxApiAuditor — 全局 wx.* API Hook 捕获 + 手动重放
重构版（对应原闭源 WxApiAuditor 类）
"""
import asyncio
import json
from pathlib import Path

_WXAPI_JS = (Path(__file__).parent / "wxapi_audit_inject.js").read_text(encoding="utf-8")


class WxApiAuditor:
    """wx.* API 调用捕获与重放"""

    def __init__(self, engine):
        self.engine = engine
        self._seen_count = 0
        self._enabled = False

    async def _ensure_injected(self):
        await self.engine.evaluate_js(_WXAPI_JS, timeout=10.0)

    async def start(self, capture_request=False, capture_storage=False, capture_bridge=False):
        """启动全局 Hook"""
        self._seen_count = 0
        await self._ensure_injected()
        cfg = json.dumps({
            "captureRequest": capture_request,
            "captureStorage": capture_storage,
            "captureBridge": capture_bridge,
        }, ensure_ascii=False)
        result = await self.engine.evaluate_js(
            f"window.wxApiAudit._cfg({cfg})", timeout=5.0)
        value = self._extract_value(result)
        if value:
            try:
                info = json.loads(value)
                if info.get("ok"):
                    self._enabled = True
                return info
            except (json.JSONDecodeError, TypeError):
                pass
        return {"ok": False}

    async def stop(self):
        if not self._enabled:
            return
        self._enabled = False
        try:
            await self._ensure_injected()
            await self.engine.evaluate_js("window.wxApiAudit.uninstall()", timeout=5.0)
        except Exception:
            pass

    async def poll(self):
        """拉取新捕获的 wx.* 调用（增量）"""
        if not self._enabled:
            return []
        try:
            await self._ensure_injected()
            # getCalls() 本身已返回 JSON 字符串，不能再包一层 JSON.stringify，
            # 否则 json.loads 后得到的是字符串，len()/切片会变成按字符拆解
            result = await self.engine.evaluate_js(
                "window.wxApiAudit.getCalls()", timeout=5.0)
            value = self._extract_value(result)
            if not value:
                return []
            calls = json.loads(value)
            if isinstance(calls, str):  # 兼容历史双序列化
                calls = json.loads(calls)
            if not isinstance(calls, list):
                return []
            if len(calls) <= self._seen_count:
                return []
            new_calls = calls[self._seen_count:]
            self._seen_count = len(calls)
            return new_calls
        except Exception:
            return []

    async def clear(self):
        self._seen_count = 0
        try:
            await self._ensure_injected()
            await self.engine.evaluate_js("window.wxApiAudit.clear()", timeout=3.0)
        except Exception:
            pass

    async def replay(self, api_name, data):
        """重放任意 wx.* API 调用。

        对异步回调型 API（request 等）自动注入 success/fail 回调捕获业务响应，
        修复「只返回 uniqueId、响应无法回读」的问题。
        """
        await self._ensure_injected()
        safe_name = api_name.replace("'", "\\'")
        opts = dict(data or {})
        # 回调型 API：注入回调以便回读业务响应（不覆盖调用方已传的回调）
        is_async_api = api_name in ("request", "uploadFile", "downloadFile",
                                    "connectSocket", "requestPayment", "login")
        if is_async_api and isinstance(opts.get("data", None), (dict, list, str, int, float, bool, type(None))) or is_async_api:
            opts.setdefault("success", "__REPLAY_OK__")
            opts.setdefault("fail", "__REPLAY_ERR__")
        safe_data = json.dumps(opts, ensure_ascii=False)
        await self.engine.evaluate_js("window._wxApiReplayResult=null", timeout=3.0)
        js = (
            f"(function(){{"
            f"try{{"
            f"var nav=window.nav;"
            f"var wxObj=nav&&nav.wxFrame?nav.wxFrame.wx:window.wx;"
            f"if(!wxObj){{window._wxApiReplayResult=JSON.stringify({{ok:false,status:'fail',error:'no wx'}});return;}}"
            f"var fn=wxObj['{safe_name}'];"
            f"if(!fn){{window._wxApiReplayResult=JSON.stringify({{ok:false,status:'fail',error:'api not found'}});return;}}"
            f"var opts={safe_data};"
            # 把哨兵字符串替换为真实回调，捕获响应/错误
            f"if(opts.success==='__REPLAY_OK__'){{opts.success=function(r){{"
            f"try{{window._wxApiReplayResult=JSON.stringify({{ok:true,status:'success',result:r}})}}catch(e){{"
            f"window._wxApiReplayResult=JSON.stringify({{ok:true,status:'success',result:String(r)}})}}}};}}"
            f"if(opts.fail==='__REPLAY_ERR__'){{opts.fail=function(e){{"
            f"window._wxApiReplayResult=JSON.stringify({{ok:false,status:'fail',error:(e&&(e.errMsg||e.message))||String(e)}})}};}}"
            f"var ret=fn.call(wxObj,opts);"
            f"if(ret&&ret.then){{"
            f"ret.then(function(r){{if(!window._wxApiReplayResult)window._wxApiReplayResult=JSON.stringify({{ok:true,status:'success',result:r}})}})"
            f"['catch'](function(e){{if(!window._wxApiReplayResult)window._wxApiReplayResult=JSON.stringify({{ok:false,status:'fail',error:e.message||String(e)}})}});"
            f"}}else if(ret&&typeof ret.abort!=='function'&&!window._wxApiReplayResult){{"
            f"window._wxApiReplayResult=JSON.stringify({{ok:true,status:'sync',result:String(ret).slice(0,2000)}});"
            f"}}"
            f"}}catch(e){{window._wxApiReplayResult=JSON.stringify({{ok:false,status:'fail',error:e.message||String(e)}})}}"
            f"}})()"
        )
        await self.engine.evaluate_js(js, timeout=10.0)
        for _ in range(24):
            await asyncio.sleep(0.5)
            result = await self.engine.evaluate_js("window._wxApiReplayResult", timeout=5.0)
            value = self._extract_value(result)
            if value:
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return {"ok": False, "status": "fail", "reason": "parse error"}
        return {"ok": False, "status": "fail",
                "reason": "重放超时（回调未触发）；可用 get_wxapi_calls 的 url_filter 查看该请求是否实际发出"}

    @staticmethod
    def _extract_value(result):
        if not result:
            return None
        r = result.get("result", {})
        inner = r.get("result", {})
        return inner.get("value")
