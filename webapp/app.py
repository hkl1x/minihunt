"""
Minihunt — 微信小程序 AI 自动化渗透测试平台
基于 Frida + CDP 架构，使用 FastAPI 提供服务
"""
import asyncio
import sys
from pathlib import Path

# 确保 src 模块可导入
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from src.cli import CliOptions, CDP_PORT
from src.logger import Logger
from src.engine import DebugEngine
from src.navigator import MiniProgramNavigator
from src.cloud_audit import CloudAuditor
from src.wxapi_audit import WxApiAuditor

from webapp.state import AppState
from webapp.routes import api_router, register_engine_hooks
from webapp.ws import websocket_endpoint
from webapp.ai.providers import AIProviderManager
from webapp.ai.agent import PenetrationAgent
from webapp.pentest.report import ReportBuilder

app = FastAPI(title="Minihunt", version="1.0.0")

# ── 全局状态 ──
options = CliOptions(cdp_port=CDP_PORT, debug_main=False, debug_frida=False)
logger = Logger(options)
state = AppState()

engine = DebugEngine(options, logger, userscript_list := [])
navigator = MiniProgramNavigator(engine)
cloud_auditor = CloudAuditor(engine)
wxapi_auditor = WxApiAuditor(engine)
ai_manager = AIProviderManager()
report_builder = ReportBuilder()
agent = PenetrationAgent(ai_manager, state, engine, navigator, cloud_auditor, wxapi_auditor)

# 内嵌 HTTP 捕获代理（方案 A）
from src.proxy_capture import ProxyCapture
proxy_capture = ProxyCapture(logger)

state.bind(engine, navigator, cloud_auditor, wxapi_auditor, logger, ai_manager, agent, report_builder)
state.proxy_capture = proxy_capture

# 日志回传 WebSocket（英文日志统一翻译为中文）
from webapp.log_cn import translate_log
logger.set_output_callback(lambda level, text: state.push_log(level, translate_log(text)))

# 状态变化推送
def _on_status(status):
    state.push_event({"type": "status", "data": status})
engine.on_status_change(_on_status)

register_engine_hooks(app, state, engine, navigator, cloud_auditor, wxapi_auditor, ai_manager, agent)
app.include_router(api_router, prefix="/api")


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket_endpoint(websocket, state)


# ── 前端页面 ──
_FRONTEND_DIR = Path(__file__).parent / "frontend"


@app.get("/", response_class=HTMLResponse)
async def index():
    # 静态资源带 mtime 版本号：文件更新后浏览器自动拉新版，避免旧缓存
    def _v(name: str) -> str:
        try:
            return str(int((_FRONTEND_DIR / name).stat().st_mtime))
        except OSError:
            return "0"
    html = (_FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(
        html.replace('/static/app.js', f'/static/app.js?v={_v("app.js")}')
            .replace('/static/style.css', f'/static/style.css?v={_v("style.css")}')
    )


app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")


@app.on_event("startup")
async def startup():
    # 恢复 AI 配置
    from webapp.routes import _load_ai_config, load_skills
    saved = _load_ai_config()
    if saved:
        ai_manager.config.update(saved)
        state.push_log("info", "[服务] AI 配置已从 webapp_config.json 恢复")
    # 恢复 Skill 列表
    load_skills(state)
    if state.skills:
        enabled = sum(1 for s in state.skills if s.get("enabled"))
        state.push_log("info", f"[服务] 已加载 {len(state.skills)} 个 Skill（启用 {enabled} 个）")
    state.push_log("info", "[服务] Minihunt Web 已启动")
    state.push_log("info", "[服务] 浏览器访问 http://127.0.0.1:8800")


@app.on_event("shutdown")
async def shutdown():
    try:
        await engine.stop()
    except Exception:
        pass
    try:
        await proxy_capture.stop()
    except Exception:
        pass
