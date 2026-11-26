"""
REST API 路由 — Minihunt Web 端全部功能
控制台 / 路由导航 / Hook / 云扫描 / WxAPI / 敏感信息提取 / 调试开关 / AI
"""
import asyncio
import json
import os

from fastapi import APIRouter, Request, HTTPException, UploadFile
from pydantic import BaseModel
from typing import List, Optional

api_router = APIRouter()

# 由 register_engine_hooks 注入
_refs = {}


def register_engine_hooks(app, state, engine, navigator, cloud_auditor, wxapi_auditor, ai_manager, agent):
    _refs.update({
        "state": state,
        "engine": engine,
        "navigator": navigator,
        "cloud": cloud_auditor,
        "wxapi": wxapi_auditor,
        "ai": ai_manager,
        "agent": agent,
    })

    @app.on_event("startup")
    async def _grab_loop():
        state._loop = asyncio.get_event_loop()


def _require_engine():
    engine = _refs["engine"]
    if not engine or not engine.miniapp_clients:
        raise HTTPException(400, "小程序未连接 — 请先启动调试并在微信中打开目标小程序")
    return engine


# ════════════════════════════════
#  模型
# ════════════════════════════════

class AIConfigModel(BaseModel):
    provider: Optional[str] = None
    openai_base_url: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_model: Optional[str] = None
    anthropic_base_url: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    anthropic_model: Optional[str] = None
    ollama_base_url: Optional[str] = None
    ollama_model: Optional[str] = None


class AgentTaskModel(BaseModel):
    message: str
    mode: Optional[str] = ""       # 已弃用：为空时后端按用户输入自动判断执行模式
    provider: Optional[str] = ""   # 运行时临时指定协议
    model: Optional[str] = ""      # 运行时临时指定模型


class ModelEntryModel(BaseModel):
    provider: str
    model: str
    label: Optional[str] = ""
    # 条目自带连接配置（快照自添加时的表单），删除模型即彻底清除其凭据
    base_url: Optional[str] = ""
    api_key: Optional[str] = ""


class NavigateModel(BaseModel):
    route: str


class CloudCallModel(BaseModel):
    name: str
    data: dict = {}


class ReplayModel(BaseModel):
    api_name: str
    data: dict = {}


class EvalModel(BaseModel):
    expression: str


class HookScriptModel(BaseModel):
    filename: str
    content: str = ""
    action: str = "run"  # save / run / delete


class DecompileModel(BaseModel):
    appid: str
    packages_dir: Optional[str] = None


class ScanModel(BaseModel):
    scan_dir: str
    custom_patterns: dict = {}


class SkillModel(BaseModel):
    name: str
    description: str = ""
    prompt: str = ""
    enabled: bool = False
    index: Optional[int] = None  # 用于更新/删除定位


# ════════════════════════════════
#  控制台
# ════════════════════════════════

@api_router.get("/status")
async def get_status():
    engine = _refs["engine"]
    return {
        "frida": engine.status.get("frida", False),
        "miniapp": engine.status.get("miniapp", False),
        "devtools": engine.status.get("devtools", False),
        "agent_running": _refs["agent"].running,
        # 运行中任务所属会话（前端据此区分「哪个会话在跑」，别的会话删除/查看不受全局锁影响）
        "agent_running_sid": getattr(_refs["agent"], "_task_sid", "") if _refs["agent"].running else "",
        "cdp_port": engine.options.cdp_port,
        # 小程序运行时版本 + 对应偏移量是否就绪（None=尚未注入；
        # 版本在 Frida 注入过程中随进程检测一并得出，不再单独探测）
        "wmpf_version": engine.status.get("wmpf_version"),
        "offset_ready": engine.status.get("offset_ready"),
    }


@api_router.post("/engine/start")
async def engine_start():
    engine = _refs["engine"]
    if engine.status.get("frida"):
        return {"ok": True, "already": True}
    try:
        await engine.start()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))


@api_router.post("/engine/stop")
async def engine_stop():
    engine = _refs["engine"]
    await engine.stop()
    return {"ok": True}


@api_router.post("/engine/restart")
async def engine_restart():
    engine = _refs["engine"]
    try:
        await engine.stop()
    except Exception:
        pass
    await asyncio.sleep(1)
    try:
        await engine.start()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))


# ════════════════════════════════
#  路由导航
# ════════════════════════════════

@api_router.get("/navigator/config")
async def navigator_config():
    _require_engine()
    nav = _refs["navigator"]
    await nav.fetch_config()
    return {
        "pages": nav.pages,
        "tabBar": nav.tab_bar_pages,
        "app_info": nav.app_info,
    }


@api_router.post("/navigator/navigate")
async def navigator_navigate(body: NavigateModel):
    _require_engine()
    nav = _refs["navigator"]
    await nav._ensure(force=True)
    await nav.go_to(body.route)
    return {"ok": True, "route": body.route}


@api_router.post("/navigator/redirect")
async def navigator_redirect(body: NavigateModel):
    _require_engine()
    nav = _refs["navigator"]
    await nav._ensure(force=True)
    await nav.redirect_to(body.route)
    return {"ok": True, "route": body.route}


@api_router.post("/navigator/relaunch")
async def navigator_relaunch(body: NavigateModel):
    _require_engine()
    nav = _refs["navigator"]
    await nav._ensure(force=True)
    await nav.relaunch_to(body.route)
    return {"ok": True, "route": body.route}


@api_router.post("/navigator/back")
async def navigator_back():
    _require_engine()
    engine = _refs["engine"]
    await engine.evaluate_js(
        "(function(){try{var wxObj=window.nav&&window.nav.wxFrame?window.nav.wxFrame.wx:window.wx;"
        "wxObj.navigateBack();return 'ok'}catch(e){return e.message}})()", timeout=5.0)
    return {"ok": True}


# ════════════════════════════════
#  Hook 脚本 (eval 注入)
# ════════════════════════════════

_HOOK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "hook_scripts")


@api_router.get("/hook/scripts")
async def hook_list():
    os.makedirs(_HOOK_DIR, exist_ok=True)
    files = [f for f in os.listdir(_HOOK_DIR) if f.endswith(".js")]
    return {"scripts": files}


@api_router.post("/hook/scripts")
async def hook_manage(body: HookScriptModel):
    os.makedirs(_HOOK_DIR, exist_ok=True)
    path = os.path.join(_HOOK_DIR, os.path.basename(body.filename))
    if body.action == "save":
        if not body.filename.endswith(".js"):
            raise HTTPException(400, "文件名必须以 .js 结尾")
        with open(path, "w", encoding="utf-8") as f:
            f.write(body.content)
        return {"ok": True}
    elif body.action == "delete":
        if os.path.exists(path):
            os.remove(path)
        return {"ok": True}
    elif body.action == "run":
        _require_engine()
        if not os.path.exists(path):
            raise HTTPException(404, f"脚本不存在: {body.filename}")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        result = await _refs["engine"].evaluate_js(content, timeout=15.0)
        value = None
        if result:
            inner = result.get("result", {}).get("result", {})
            value = inner.get("value") or inner.get("description")
        return {"ok": True, "result": value}
    raise HTTPException(400, f"未知 action: {body.action}")


@api_router.get("/hook/scripts/{filename}")
async def hook_get(filename: str):
    path = os.path.join(_HOOK_DIR, os.path.basename(filename))
    if not os.path.exists(path):
        raise HTTPException(404, "not found")
    with open(path, "r", encoding="utf-8") as f:
        return {"content": f.read()}


# ════════════════════════════════
#  云函数
# ════════════════════════════════

@api_router.post("/cloud/start")
async def cloud_start():
    _require_engine()
    result = await _refs["cloud"].start()
    return result


@api_router.post("/cloud/stop")
async def cloud_stop():
    await _refs["cloud"].stop()
    return {"ok": True}


@api_router.get("/cloud/calls")
async def cloud_calls():
    _require_engine()
    calls = await _refs["cloud"].poll()
    st = _refs["state"]
    st.cloud_calls.extend(calls)
    return {"calls": st.cloud_calls}


@api_router.delete("/cloud/calls")
async def cloud_clear():
    st = _refs["state"]
    st.cloud_calls.clear()
    await _refs["cloud"].clear()
    return {"ok": True}


@api_router.post("/cloud/call")
async def cloud_call(body: CloudCallModel):
    _require_engine()
    result = await _refs["cloud"].call_function(body.name, body.data)
    return result


@api_router.post("/cloud/static-scan")
async def cloud_static_scan():
    _require_engine()
    results = await _refs["cloud"].static_scan(
        on_progress=lambda msg: _refs["state"].push_log("info", f"[云扫描] {msg}"))
    return {"results": results}


# ════════════════════════════════
#  WxAPI 捕获
# ════════════════════════════════

@api_router.post("/wxapi/start")
async def wxapi_start(capture_request: bool = False, capture_storage: bool = False, capture_bridge: bool = False):
    _require_engine()
    result = await _refs["wxapi"].start(
        capture_request=capture_request,
        capture_storage=capture_storage,
        capture_bridge=capture_bridge,
    )
    return result


@api_router.post("/wxapi/stop")
async def wxapi_stop():
    await _refs["wxapi"].stop()
    return {"ok": True}


@api_router.get("/wxapi/calls")
async def wxapi_calls():
    _require_engine()
    calls = await _refs["wxapi"].poll()
    st = _refs["state"]
    st.wxapi_calls.extend(calls)
    return {"calls": st.wxapi_calls}


@api_router.delete("/wxapi/calls")
async def wxapi_clear():
    st = _refs["state"]
    st.wxapi_calls.clear()
    await _refs["wxapi"].clear()
    return {"ok": True}


@api_router.post("/wxapi/replay")
async def wxapi_replay(body: ReplayModel):
    _require_engine()
    result = await _refs["wxapi"].replay(body.api_name, body.data)
    return result


# ════════════════════════════════
#  调试开关 (vConsole)
# ════════════════════════════════

@api_router.get("/debug/state")
async def debug_state():
    _require_engine()
    nav = _refs["navigator"]
    await nav._ensure(force=True)
    result = await _refs["engine"].evaluate_js(
        "(function(){"
        "try{"
        "var f=window.nav&&window.nav.wxFrame?window.nav.wxFrame:window;"
        "var c=f.__wxConfig||{};"
        "var d=!!c.debug;"
        "var v=!!(f.document&&f.document.getElementById('__vconsole'));"
        "return JSON.stringify({debug:d,vconsole:v})"
        "}catch(e){return JSON.stringify({err:e.message})}"
        "})()", timeout=5.0)
    value = None
    if result:
        value = result.get("result", {}).get("result", {}).get("value")
    if value:
        return json.loads(value)
    return {"debug": False, "vconsole": False}


@api_router.post("/debug/enable")
async def debug_enable(enable: bool = True):
    _require_engine()
    val = "true" if enable else "false"
    nav = _refs["navigator"]
    await nav._ensure(force=True)
    result = await _refs["engine"].evaluate_js(
        "(function(){"
        "try{"
        "var nav=window.nav;"
        "if(!nav||!nav.wxFrame||!nav.wxFrame.wx)return JSON.stringify({err:'no wxFrame'});"
        f"nav.wxFrame.wx.setEnableDebug({{enableDebug:{val},"
        "success:function(){},fail:function(e){}});"
        "return JSON.stringify({ok:true})"
        "}catch(e){return JSON.stringify({err:e.message})}"
        "})()", timeout=5.0)
    value = None
    if result:
        value = result.get("result", {}).get("result", {}).get("value")
    if value:
        info = json.loads(value)
        if info.get("err"):
            raise HTTPException(500, info["err"])
    return {"ok": True, "enable": enable}


# ════════════════════════════════
#  敏感信息提取 / 解包
# ════════════════════════════════

def _resolve_packages_dirs(packages_dir: Optional[str] = None) -> List[str]:
    """解析小程序包目录：用户传参 / minihunt_config.json 配置路径（唯一生效）> 自动扫描所有用户目录"""
    dirs: List[str] = []
    if packages_dir and os.path.isdir(packages_dir):
        dirs.append(packages_dir)
        return dirs
    cfg_dir = (_load_minihunt_config().get("packages_dir") or "").strip()
    if cfg_dir and os.path.isdir(cfg_dir):
        dirs.append(cfg_dir)
        return dirs
    from src.wxapkg import get_all_packages_dirs
    return get_all_packages_dirs()


@api_router.get("/wxapkg/packages")
async def wxapkg_list(packages_dir: Optional[str] = None):
    from src.wxapkg import find_wxapkg_files_multi
    dirs = _resolve_packages_dirs(packages_dir)
    if not dirs:
        return {"packages": [], "packages_dir": None, "packages_dirs": []}
    return {
        "packages_dir": dirs[0],
        "packages_dirs": dirs,
        "packages": find_wxapkg_files_multi(dirs),
    }


# ── Minihunt 配置（minihunt_config.json：用户自填的小程序包路径/框架路径） ──

_MINIHUNT_CFG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "minihunt_config.json")


def _load_minihunt_config() -> dict:
    try:
        with open(_MINIHUNT_CFG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@api_router.get("/config/packages_dir")
async def get_packages_dir():
    cfg = _load_minihunt_config()
    configured = (cfg.get("packages_dir") or "").strip()
    from src.wxapkg import get_all_packages_dirs, find_wxapkg_files_multi
    detected = get_all_packages_dirs()
    dirs = [configured] if configured and os.path.isdir(configured) else detected
    appids = sorted({p["appid"] for p in find_wxapkg_files_multi(dirs)})
    return {
        "configured": configured,
        "detected": detected,
        "appids": appids,
    }


@api_router.post("/wxapkg/decompile")
async def wxapkg_decompile(body: DecompileModel):
    from src.wxapkg import find_wxapkg_files_multi, extract_wxapkg
    dirs = _resolve_packages_dirs(body.packages_dir)
    if not dirs:
        raise HTTPException(400, "未找到小程序包目录")
    pkgs = [p for p in find_wxapkg_files_multi(dirs) if p["appid"] == body.appid]
    if not pkgs:
        raise HTTPException(404, f"未找到 appid={body.appid} 的包")
    out_dir = os.path.join("decompiled", body.appid)
    os.makedirs(out_dir, exist_ok=True)
    all_files = []
    errors = []
    for pkg in pkgs:
        try:
            files = extract_wxapkg(pkg["path"], out_dir, body.appid)
            all_files.extend(f.replace("\\", "/") for f in files)
        except Exception as e:
            errors.append(f"{pkg['name']}: {e}")
    return {"ok": len(all_files) > 0, "output_dir": out_dir,
            "file_count": len(all_files), "files": all_files[:200], "errors": errors}


# ════════════════════════════════
#  内嵌 HTTP 捕获代理（方案 A）
# ════════════════════════════════

class ProxyStartModel(BaseModel):
    host: Optional[str] = "127.0.0.1"
    port: Optional[int] = 16823
    mode: Optional[str] = "local"   # local=进程级透明捕获（无需系统代理），regular=系统代理模式


@api_router.post("/proxy/start")
async def proxy_start(body: ProxyStartModel):
    pc = _refs["state"].proxy_capture
    if not pc:
        raise HTTPException(500, "代理模块未初始化")
    return await pc.start(host=body.host, port=body.port, mode=body.mode)


@api_router.post("/proxy/stop")
async def proxy_stop():
    pc = _refs["state"].proxy_capture
    if not pc:
        raise HTTPException(500, "代理模块未初始化")
    return await pc.stop()


@api_router.get("/proxy/status")
async def proxy_status():
    pc = _refs["state"].proxy_capture
    if not pc:
        return {"running": False, "capture_count": 0, "credentials": []}
    return pc.status()


@api_router.get("/proxy/captures")
async def proxy_captures(limit: int = 30, url_filter: Optional[str] = None):
    pc = _refs["state"].proxy_capture
    if not pc:
        return {"total": 0, "count": 0, "captures": []}
    return pc.get_captures(limit=limit, url_filter=url_filter)


@api_router.get("/fs/list")
async def fs_list(path: str = "decompiled"):
    if not os.path.exists(path):
        return {"entries": []}
    if not os.path.isdir(path):
        raise HTTPException(400, "not a directory")
    entries = []
    for name in sorted(os.listdir(path))[:500]:
        full = os.path.join(path, name)
        entries.append({
            "name": name,
            "is_dir": os.path.isdir(full),
            "size": os.path.getsize(full) if os.path.isfile(full) else 0,
        })
    return {"entries": entries}


@api_router.get("/fs/read")
async def fs_read(path: str):
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    size = os.path.getsize(path)
    if size > 2_000_000:
        raise HTTPException(400, f"文件过大 ({size} bytes)")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {"path": path, "size": size, "content": f.read()}


@api_router.post("/extract/scan")
async def extract_scan(body: ScanModel):
    from src.extractor import Extractor
    if not os.path.isdir(body.scan_dir):
        raise HTTPException(404, f"目录不存在: {body.scan_dir}")
    ext = Extractor()
    for name, pattern in body.custom_patterns.items():
        ext.add_custom_pattern(name, pattern)
    result = ext.scan_directory(
        body.scan_dir,
        on_progress=lambda msg: _refs["state"].push_log("info", f"[敏感信息] {msg}"))
    return result


# ════════════════════════════════
#  Skill 列表
# ════════════════════════════════

@api_router.get("/skills")
async def skills_list():
    st = _refs["state"]
    return {"skills": st.skills}


@api_router.post("/skills")
async def skills_add(body: SkillModel):
    """添加 Skill（名称重复时拒绝）"""
    st = _refs["state"]
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Skill 名称不能为空")
    if any(s.get("name") == name for s in st.skills):
        raise HTTPException(400, f"Skill 已存在: {name}")
    st.skills.append({
        "name": name,
        "description": body.description.strip(),
        "prompt": body.prompt,
        "enabled": body.enabled,
    })
    _save_skills(st.skills)
    return {"ok": True, "count": len(st.skills)}


@api_router.post("/skills/upload")
async def skills_upload(file: UploadFile):
    """
    上传 Skill 文件导入，支持：
    - .json：单个 {"name","description","prompt","enabled"} 或数组批量导入
    - .txt / .md：纯文本，首行 # 标题作为名称（无标题则用文件名），正文作为 prompt
    """
    st = _refs["state"]
    name = file.filename or ""
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "文件为空")
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(400, "文件过大（限制 2MB）")
    text = raw.decode("utf-8", errors="replace")

    ext = os.path.splitext(name)[1].lower()
    if ext == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"JSON 解析失败: {e}")
        items = data if isinstance(data, list) else [data]
        imported, skipped = [], []
        for i, item in enumerate(items):
            if not isinstance(item, dict) or not item.get("name"):
                skipped.append(f"第 {i + 1} 项缺少 name")
                continue
            skill = {
                "name": str(item["name"]).strip(),
                "description": str(item.get("description", "")).strip(),
                "prompt": str(item.get("prompt", "")),
                "enabled": bool(item.get("enabled", False)),
            }
            if not skill["name"]:
                skipped.append(f"第 {i + 1} 项 name 为空")
                continue
            if any(s.get("name") == skill["name"] for s in st.skills) or \
               any(s["name"] == skill["name"] for s in imported):
                skipped.append(f"{skill['name']}（重名跳过）")
                continue
            imported.append(skill)
        if not imported:
            raise HTTPException(400, "无可导入的 Skill: " + "; ".join(skipped or ["文件格式不正确"]))
        st.skills.extend(imported)
        _save_skills(st.skills)
        return {"ok": True, "imported": [s["name"] for s in imported],
                "skipped": skipped, "count": len(st.skills)}
    elif ext in (".txt", ".md", ".markdown"):
        lines = text.splitlines()
        prompt, sname, sdesc = text.strip(), "", ""
        # 首个 # 标题行作为名称
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("#"):
                sname = s.lstrip("#").strip()
                # 去掉标题行后的剩余正文作为 prompt
                prompt = "\n".join(lines[lines.index(ln) + 1:]).strip()
            break
        if not sname:
            sname = os.path.splitext(name)[0]
        # ## 描述 行可选识别
        for ln in prompt.splitlines():
            s = ln.strip()
            if s.startswith("##"):
                sdesc = s.lstrip("#").strip()
                break
        if not prompt:
            raise HTTPException(400, "文件内容为空")
        if any(s.get("name") == sname for s in st.skills):
            raise HTTPException(400, f"Skill 已存在: {sname}")
        st.skills.append({"name": sname, "description": sdesc, "prompt": prompt, "enabled": False})
        _save_skills(st.skills)
        return {"ok": True, "imported": [sname], "skipped": [], "count": len(st.skills)}
    else:
        raise HTTPException(400, "不支持的文件类型，请上传 .json / .txt / .md")


@api_router.put("/skills/{index}")
async def skills_update(index: int, body: SkillModel):
    """更新 Skill 内容或启用/关闭状态"""
    st = _refs["state"]
    if index < 0 or index >= len(st.skills):
        raise HTTPException(404, "Skill 不存在")
    st.skills[index].update({
        "name": body.name.strip() or st.skills[index]["name"],
        "description": body.description.strip(),
        "prompt": body.prompt,
        "enabled": body.enabled,
    })
    _save_skills(st.skills)
    return {"ok": True, "skill": st.skills[index]}


@api_router.post("/skills/{index}/toggle")
async def skills_toggle(index: int):
    """切换 Skill 启用/关闭"""
    st = _refs["state"]
    if index < 0 or index >= len(st.skills):
        raise HTTPException(404, "Skill 不存在")
    st.skills[index]["enabled"] = not st.skills[index].get("enabled", False)
    _save_skills(st.skills)
    return {"ok": True, "enabled": st.skills[index]["enabled"]}


@api_router.delete("/skills/{index}")
async def skills_delete(index: int):
    st = _refs["state"]
    if index < 0 or index >= len(st.skills):
        raise HTTPException(404, "Skill 不存在")
    removed = st.skills.pop(index)
    _save_skills(st.skills)
    return {"ok": True, "removed": removed.get("name", "")}


# ════════════════════════════════
#  敏感信息汇总
# ════════════════════════════════

@api_router.get("/sensitive")
async def sensitive_get():
    st = _refs["state"]
    return {
        "findings": st.sensitive_findings,
        "meta": st.sensitive_meta,
        "total": sum(len(v) for v in st.sensitive_findings.values()),
    }


@api_router.delete("/sensitive")
async def sensitive_clear():
    st = _refs["state"]
    st.sensitive_findings = {}
    st.sensitive_meta = {"source": "", "appid": "", "files_scanned": 0, "updated_at": ""}
    return {"ok": True}


# ════════════════════════════════
#  AI / Agent
# ════════════════════════════════

@api_router.get("/ai/config")
async def ai_config_get():
    return _refs["ai"].get_config()


@api_router.post("/ai/config")
async def ai_config_set(body: AIConfigModel):
    d = body.dict(exclude_none=True)
    # base_url 必须带协议，防止存入垃圾值后 chat 请求报「missing protocol」
    for k in ("openai_base_url", "anthropic_base_url", "ollama_base_url"):
        v = (d.get(k) or "").strip()
        if v and not v.startswith(("http://", "https://")):
            raise HTTPException(400, f"{k} 必须以 http:// 或 https:// 开头")
    _refs["ai"].update_config(d)
    _save_ai_config(_refs["ai"].config.to_dict())
    return {"ok": True}


@api_router.post("/ai/test")
async def ai_test(body: dict = None):
    """测试 AI 连接（可指定 provider/model）"""
    b = body or {}
    try:
        resp = await _refs["ai"].chat(
            [{"role": "user", "content": "回复 ok"}], max_tokens=10,
            provider=b.get("provider", ""), model=b.get("model", ""))
        return {"ok": True, "reply": resp.get("content", "")}
    except Exception as e:
        raise HTTPException(500, f"AI 连接失败: {e}")


# ── 已接入模型列表（持久化到 webapp_models.json）──

_MODELS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webapp_models.json")


def _load_models():
    try:
        with open(_MODELS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_models(models):
    try:
        with open(_MODELS_PATH, "w", encoding="utf-8") as f:
            json.dump(models, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


@api_router.get("/ai/models")
async def ai_models_list():
    return {"models": _load_models()}


@api_router.post("/ai/models")
async def ai_models_add(body: ModelEntryModel):
    models = _load_models()
    # 同 provider+model 去重
    models = [m for m in models if not (m.get("provider") == body.provider and m.get("model") == body.model)]
    # 连接配置快照进条目：该模型使用自己的 base_url/api_key，与全局配置解耦
    models.append({
        "provider": body.provider, "model": body.model,
        "label": body.label or body.model,
        "base_url": (body.base_url or "").strip(),
        "api_key": (body.api_key or "").strip(),
    })
    _save_models(models)
    return {"ok": True, "models": models}


@api_router.delete("/ai/models/{index}")
async def ai_models_delete(index: int):
    models = _load_models()
    if 0 <= index < len(models):
        models.pop(index)
        _save_models(models)
    return {"ok": True, "models": models}


@api_router.post("/agent/task")
async def agent_task(body: AgentTaskModel):
    # 查模型条目，取其自带的连接配置（base_url/api_key）传给 agent
    entry_override = {}
    if body.provider and body.model:
        for m in _load_models():
            if m.get("provider") == body.provider and m.get("model") == body.model:
                entry_override = {
                    "openai_base_url": m.get("base_url", ""),
                    "openai_api_key": m.get("api_key", ""),
                    "anthropic_base_url": m.get("base_url", ""),
                    "anthropic_api_key": m.get("api_key", ""),
                    "ollama_base_url": m.get("base_url", ""),
                }
                break
    result = await _refs["agent"].run_task(
        body.message, provider=body.provider, model=body.model,
        mode=body.mode or "", entry_override=entry_override)
    return result


@api_router.post("/agent/stop")
async def agent_stop():
    """请求停止当前 Agent 任务（协作式取消，当前工具执行完即中断）"""
    stopped = _refs["agent"].stop()
    return {"ok": True, "stopped": stopped}


@api_router.delete("/agent/history")
async def agent_clear():
    """清空当前会话的对话内容"""
    agent = _refs["agent"]
    sid = agent.current_sid
    agent.clear_session(sid)
    _refs["state"].push_event({"type": "session_cleared", "data": {"sid": sid}})
    return {"ok": True, "sid": sid}


@api_router.delete("/agent/sessions/{sid}/messages/{idx}")
async def agent_message_delete(sid: str, idx: int):
    """删除会话中指定消息所属对话轮次及其后所有内容（截断式删除，AI 上下文同步回溯）"""
    agent = _refs["agent"]
    if agent.running:
        raise HTTPException(409, "Agent 执行中，无法删除消息")
    if not agent.delete_from(sid, idx):
        raise HTTPException(404, "消息不存在")
    _refs["state"].push_event({"type": "session_truncated", "data": {"sid": sid}})
    return {"ok": True, "sid": sid, "display": agent.sessions[sid]["display"]}


@api_router.post("/agent/sessions/{sid}/messages/delete-rounds")
async def agent_rounds_delete(sid: str, body: dict = None):
    """批量删除多个对话轮次（round_starts: 各轮次起始下标），AI 上下文同步删除"""
    starts = (body or {}).get("round_starts") or []
    if not isinstance(starts, list) or not starts:
        raise HTTPException(400, "round_starts 不能为空")
    agent = _refs["agent"]
    if agent.running:
        raise HTTPException(409, "Agent 执行中，无法删除消息")
    if not agent.delete_rounds(sid, starts):
        raise HTTPException(404, "消息不存在")
    _refs["state"].push_event({"type": "session_truncated", "data": {"sid": sid}})
    return {"ok": True, "sid": sid, "display": agent.sessions[sid]["display"]}


# ════════════════════════════════
#  Agent 会话管理
# ════════════════════════════════

@api_router.get("/agent/sessions")
async def agent_sessions():
    return {"sessions": _refs["agent"].session_summary()}


@api_router.post("/agent/sessions")
async def agent_session_create(body: dict = None):
    agent = _refs["agent"]
    title = (body or {}).get("title", "")
    sid = agent.create_session(title)
    agent.switch_session(sid)
    return {"ok": True, "sid": sid, "sessions": agent.session_summary()}


@api_router.get("/agent/sessions/{sid}")
async def agent_session_detail(sid: str):
    d = _refs["agent"].session_detail(sid)
    if d is None:
        raise HTTPException(404, "会话不存在")
    return d


@api_router.post("/agent/sessions/{sid}/switch")
async def agent_session_switch(sid: str):
    agent = _refs["agent"]
    if not agent.switch_session(sid):
        raise HTTPException(404, "会话不存在")
    return {"ok": True, "sid": sid, "sessions": agent.session_summary()}


@api_router.post("/agent/sessions/{sid}/rename")
async def agent_session_rename(sid: str, body: dict = None):
    title = ((body or {}).get("title") or "").strip()
    if not title:
        raise HTTPException(400, "标题不能为空")
    if not _refs["agent"].rename_session(sid, title):
        raise HTTPException(404, "会话不存在")
    return {"ok": True, "sessions": _refs["agent"].session_summary()}


@api_router.delete("/agent/sessions/{sid}")
async def agent_session_delete(sid: str):
    agent = _refs["agent"]
    try:
        if not agent.delete_session(sid):
            raise HTTPException(404, "会话不存在")
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "current": agent.current_sid, "sessions": agent.session_summary()}


@api_router.get("/agent/tools")
async def agent_tools():
    return {"tools": _refs["agent"].registry.get_tool_schemas()}


@api_router.post("/agent/eval")
async def agent_eval(body: EvalModel):
    """手动执行 JS（JS 分析页）"""
    _require_engine()
    result = await _refs["agent"].registry.execute("evaluate_js", {"expression": body.expression})
    if "error" in result:
        raise HTTPException(500, result["error"])
    return result


# ════════════════════════════════
#  渗透画板
# ════════════════════════════════

@api_router.get("/board")
async def board_get(sid: str = ""):
    """画板思维导图数据（按会话；默认当前会话）"""
    agent = _refs["agent"]
    view = agent.board.view(sid or None)
    summary = agent.board.summary(sid or None)

    def _counts(s):
        recon = len(s.get("board") or [])
        reg = s.get("feature_registry") or []
        return {"recon": recon, "test": len(reg),
                # 与画板节点同口径（逐动作判定），列表徽章 = 详情图例 = 鸟瞰红点数
                "vuln": agent.board.vuln_count(s["id"])}

    return {
        "sid": view["sid"],
        "root": view["root"],
        "recon": view["recon"],
        "test": view["test"],
        "summary": summary,
        "sessions": [
            {"id": x["id"], "title": x["title"],
             "counts": _counts(x),
             "has_board": bool(x.get("board")) or bool(x.get("feature_registry"))}
            for x in sorted(agent.sessions.values(),
                            key=lambda s: s.get("updated_at", ""), reverse=True)
        ] + [
            # 已删除会话的归档画板（只读留档，删会话不丢画板）
            {"id": sid, "title": f'{a.get("title", "已删除会话")}（已归档）',
             "counts": {"recon": len(a.get("board") or []),
                        "test": len(a.get("feature_registry") or []), "vuln": 0},
             "has_board": True, "archived": True}
            for sid, a in sorted(getattr(agent, "boards_archive", {}).items(),
                                 key=lambda kv: kv[1].get("archived_at", ""), reverse=True)
        ],
    }


@api_router.post("/board")
async def board_add(body: dict = None):
    b = body or {}
    result = _refs["agent"].board.add(
        b.get("type", "recon"), b.get("title", ""),
        detail=b.get("detail", ""), source=b.get("source", ""),
        evidence=b.get("evidence"), sid=b.get("sid") or None)
    if result.get("error"):
        raise HTTPException(400, result["error"])
    return result


@api_router.get("/board/evidence")
async def board_evidence(entry_id: str, sid: str = ""):
    """画板溯源详情：信息搜集条目→当时的数据包/反编译文件行号；测试动作→当时收发的数据包"""
    data = _refs["agent"].board.evidence(entry_id, sid or None)
    if data.get("error"):
        raise HTTPException(404, data["error"])
    return data


@api_router.delete("/board/{entry_id}")
async def board_remove(entry_id: str):
    if not _refs["agent"].board.remove(entry_id):
        raise HTTPException(404, "条目不存在")
    return {"ok": True}


@api_router.delete("/board")
async def board_clear(sid: str = ""):
    _refs["agent"].board.clear(sid or None)
    return {"ok": True}


# ════════════════════════════════
#  报告
# ════════════════════════════════

@api_router.get("/report/current")
async def report_current():
    return {"report": _refs["state"].report_data}


@api_router.get("/reports")
async def report_list():
    """全部报告索引（独立存储：会话删除后报告仍在）"""
    agent = _refs["agent"]
    items = []
    for sid, r in agent.reports_store.items():
        if not r or not r.get("title"):
            continue
        summ = r.get("summary", {})
        sess = agent.sessions.get(sid)
        items.append({
            "sid": sid,
            # 会话还在显示会话名；会话已删则显示报告标题兜底
            "title": (sess.get("title", "") if sess else "") or r.get("title", ""),
            "session_exists": bool(sess),
            "report_title": r.get("title", ""),
            "generated_at": r.get("generated_at", ""),
            "total_findings": r.get("total_findings", 0),
            "summary": {k: v for k, v in summ.items() if v},
        })
    items.sort(key=lambda x: x["generated_at"], reverse=True)
    return {"reports": items, "current_sid": agent.current_sid}


@api_router.get("/report/session/{sid}")
async def report_by_session(sid: str):
    """按会话取报告（会话删除后仍可取）"""
    agent = _refs["agent"]
    r = agent.get_report(sid)
    if not r:
        raise HTTPException(404, "该会话暂无报告")
    s = agent.sessions.get(sid)
    return {"sid": sid, "session_title": (s.get("title", "") if s else ""), "report": r}


@api_router.delete("/report/session/{sid}")
async def report_delete(sid: str):
    """删除指定会话的报告（仅删报告，不动会话）"""
    agent = _refs["agent"]
    if not agent.get_report(sid):
        raise HTTPException(404, "该会话暂无报告")
    agent.delete_report(sid)
    return {"ok": True}


@api_router.post("/report/save")
async def report_save(fmt: str = "md", sid: str = ""):
    """导出报告；sid 为空时导出当前选中会话的报告"""
    st = _refs["state"]
    agent = _refs["agent"]
    report = None
    if sid:
        report = agent.get_report(sid)
        if report is None:
            raise HTTPException(404, "该会话暂无报告")
    else:
        report = st.report_data
    if not report or not report.get("title"):
        raise HTTPException(400, "暂无报告")
    rb = st.report_builder
    if fmt == "json":
        path = rb.save_json(report)
    else:
        path = rb.save_markdown(report)
    return {"ok": True, "path": path}


# ════════════════════════════════
#  AI 配置持久化
# ════════════════════════════════

_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webapp_config.json")


def _load_ai_config():
    try:
        with open(_CFG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_ai_config(data):
    try:
        with open(_CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ── Skills 持久化 ──

_SKILLS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills.json")


def load_skills(state):
    try:
        with open(_SKILLS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            state.skills = [s for s in data if isinstance(s, dict) and s.get("name")]
    except Exception:
        pass


def _save_skills(skills):
    try:
        with open(_SKILLS_PATH, "w", encoding="utf-8") as f:
            json.dump(skills, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# 启动时恢复配置由 app.py startup 钩子处理
