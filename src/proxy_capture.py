"""内嵌 HTTP 捕获代理（方案 A）

基于 mitmproxy DumpMaster，在本机起一个 HTTP/HTTPS 解密代理：
- 微信 PC 小程序（WeChatAppEx）的 wx.request 走系统代理时，业务流量在此被解密捕获
- 捕获内容包括完整请求头（Cookie/签名）、请求体、响应状态、响应体摘要
- 会话凭证（Cookie/Authorization/token 类头）单独提炼，供 http_request / concurrent_request
  重放时自动携带，打通「抓包 → 篡改 → 重放 → 对比」证据链

使用方式（异步任务内）:
    pc = ProxyCapture(logger)
    await pc.start()          # 默认 127.0.0.1:16823
    ...
    await pc.stop()

证书说明：首次使用需在系统里安装并信任 mitmproxy CA 证书
（启动代理后访问 http://mitm.it 下载，或直接运行 `mitmproxy` 一次自动生成）。
证书位于 %USERPROFILE%/.mitmproxy/mitmproxy-ca-cert.cer
"""

import asyncio
import ctypes
import json
import logging
import os
import re
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional

# 业务域名的静态资源噪音过滤（这些不是可测的 API 接口）
_NOISE_PREFIXES = ("data:", "blob:")


class _CaptureAddon:
    """mitmproxy addon：把请求/响应推给 ProxyCapture 的回调"""

    def __init__(self, on_request: Callable, on_response: Callable,
                 on_error: Optional[Callable] = None):
        self._on_request = on_request
        self._on_response = on_response
        self._on_error = on_error

    def request(self, flow):
        try:
            self._on_request(flow)
        except Exception:
            pass

    def response(self, flow):
        try:
            self._on_response(flow)
        except Exception:
            pass

    def error(self, flow):
        if self._on_error:
            try:
                self._on_error(flow)
            except Exception:
                pass


class ProxyCapture:
    """本机解密代理，捕获小程序业务 HTTP 流量

    - captures: 请求/响应记录列表（线程安全，经由主循环 marshal）
    - session_credentials: 从流量中提炼的会话凭证 {header_name: value}
    """

    def __init__(self, logger=None, host: str = "127.0.0.1", port: int = 16823,
                 max_captures: int = 3000):
        self.logger = logger
        self.host = host
        self.port = port
        self.max_captures = max_captures
        self.captures: List[dict] = []
        self.session_credentials: Dict[str, str] = {}
        self.last_appid: Optional[str] = None   # 最近一次确认身份的小程序（切换检测）
        self.running = False
        self.mode = "regular"        # regular=系统代理模式, local=进程级透明捕获
        self.process_spec = "WeChatAppEx"  # local 模式下要拦截的进程名
        self._master = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._pending: Dict[str, dict] = {}  # flow id -> capture entry
        self._proc: Optional[subprocess.Popen] = None   # local 模式 mitmdump 子进程
        self._child_log = None                          # 子进程日志文件句柄
        self._tail_thread: Optional[threading.Thread] = None  # JSONL 落盘解析线程
        self._tail_stop = threading.Event()
        self._jsonl_pos = 0          # JSONL 已读偏移（tail 增量解析）
        self._local_ready = threading.Event()   # local 模式守护进程就绪信号
        # 凭证相关请求头（小写），抓到就提炼
        self._cred_headers = {
            "cookie", "authorization", "x-token", "token", "access-token",
            "x-session-id", "sessionid", "x-csrf-token", "x-xsrf-token",
        }
        # 微信宿主环境头（r9，与 proxy_local_addon 同规则）：宿主自用上报头
        # 不是业务凭证，不收编（x-wx-wxareportob-token 名字含 token 曾被
        # 值特征误收进 session_credentials 自动随重放，污染未授权测试）
        self._host_name_hints = ("x-wx-", "wx-", "pass_ticket", "passid",
                                 "softid", "weixinuin")

    # ── 日志辅助 ──

    def _log(self, level: str, msg: str):
        if self.logger:
            try:
                # 自定义 Logger 只有 info/error；warn/debug 等级别统一落 info
                fn = getattr(self.logger, level, None)
                if fn is None:
                    fn = self.logger.info
                fn(f"[proxy] {msg}")
            except Exception:
                pass

    @staticmethod
    def _is_elevated() -> bool:
        """当前进程是否以管理员权限运行（local 模式硬性要求）"""
        try:
            if os.name != "nt":
                return os.geteuid() == 0
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def _redirector_alive() -> bool:
        try:
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq windows-redirector.exe", "/NH"],
                capture_output=True, text=True, timeout=5).stdout or ""
            return "windows-redirector.exe" in out.lower()
        except Exception:
            return False

    def _tail_jsonl(self):
        """后台线程：增量解析 addon 写出的 JSONL 捕获文件，入库"""
        path = self._LOCAL_CAPTURE_FILE
        while not self._tail_stop.is_set():
            try:
                if os.path.exists(path):
                    size = os.path.getsize(path)
                    if size < self._jsonl_pos:
                        self._jsonl_pos = 0  # 文件被截断/轮转，从头读
                    if size > self._jsonl_pos:
                        with open(path, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(self._jsonl_pos)
                            chunk = f.read()
                            self._jsonl_pos = f.tell()
                        for line in chunk.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            self._ingest_local_entry(entry)
            except Exception:
                pass
            self._tail_stop.wait(0.5)

    def _ingest_local_entry(self, entry: dict):
        """把 addon 的一条捕获记录并入内存结构（等价于 _on_request/_on_response）"""
        creds = entry.pop("_creds", None)
        if creds:
            for k, v in creds.items():
                self.session_credentials[k] = v
        entry.setdefault("type", "proxy")
        url = entry.get("url") or ""
        if url.startswith(_NOISE_PREFIXES) or "://mitm.it" in url:
            return
        self.captures.append(entry)
        if len(self.captures) > self.max_captures:
            del self.captures[: len(self.captures) - self.max_captures]

    def _stop_master_sync(self):
        """同步停止 master（启动失败清理用）。

        mitmproxy 12 的 Master.shutdown() 是同步且线程安全的
        （内部 event_loop.call_soon_threadsafe(should_exit.set)），
        直接调用即可；不能包进 run_coroutine_threadsafe（它不是协程）。
        """
        try:
            if self._master:
                self._master.shutdown()
        except Exception:
            pass

    # ── local 模式：mitmdump 独立子进程方案 ──
    # 嵌入 DumpMaster 在 FastAPI 服务进程内会卡死在 local redirector 的
    # IPC 握手（standalone 同代码正常），故 local 模式改用独立子进程运行
    # mitmdump --mode local:<进程> -s addon，捕获经 JSONL 落盘回传。

    _LOCAL_CAPTURE_FILE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "local_capture.jsonl")
    _LOCAL_CHILD_LOG = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "mitmdump_child.log")
    _LOCAL_LOG_PREFIX = "[mitmdump] "

    def _mitmdump_exe(self) -> str:
        """定位 mitmdump 可执行文件（Scripts 目录或 PATH）"""
        import shutil
        import sys
        cand = os.path.join(os.path.dirname(sys.executable), "Scripts", "mitmdump.exe")
        if os.path.exists(cand):
            return cand
        found = shutil.which("mitmdump")
        return found or "mitmdump"

    def _spawn_mitmdump(self):
        """启动 mitmdump 子进程（local 模式），输出直接落盘便于诊断"""
        addon = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "proxy_local_addon.py")
        env = dict(os.environ)
        env["MINIHUNT_CAPTURE_FILE"] = self._LOCAL_CAPTURE_FILE
        env["PYTHONIOENCODING"] = "utf-8"
        # stdout 重定向到文件时 Python 默认块缓冲，"Local redirector started"
        # 会滞留缓冲区导致就绪检测永远超时，必须强制无缓冲
        env["PYTHONUNBUFFERED"] = "1"
        exe = self._mitmdump_exe()
        self._child_log = open(self._LOCAL_CHILD_LOG, "w",
                               encoding="utf-8", errors="replace", buffering=1)
        self._proc = subprocess.Popen(
            [exe,
             "--listen-host", self.host, "--listen-port", str(self.port),
             "--mode", f"local:{self.process_spec}",
             # 禁用 HTTP/2：有赞等网关返回带尾随空格的 h2 响应头，
             # mitmproxy 严格校验直接断连（"header value surrounded by
             # whitespace"），降级 HTTP/1.1 可正常转发，抓包能力不变
             "--no-http2",
             "-s", addon],
            stdout=self._child_log, stderr=subprocess.STDOUT,
            env=env, cwd=os.path.dirname(os.path.abspath(__file__)),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def _poll_child_log(self):
        """从子进程日志文件识别就绪信号（子进程输出已落盘，无需管道）"""
        try:
            with open(self._LOCAL_CHILD_LOG, "r",
                      encoding="utf-8", errors="replace") as f:
                content = f.read()
            if "Local redirector started" in content:
                self._local_ready.set()
            lines = [ln for ln in content.splitlines() if ln.strip()]
            if lines and lines[-1] != getattr(self, "_drain_last_line", None):
                self._drain_last_line = lines[-1]
                if any(m in lines[-1] for m in ("ERROR", "Traceback", "error")):
                    self._log("warn", self._LOCAL_LOG_PREFIX + lines[-1])
        except Exception:
            pass

    def _proc_alive(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)

    def diagnostics(self) -> dict:
        """链路健康状态（0 流量排查用）：子进程存活/捕获文件大小/提权状态"""
        try:
            jsonl_size = os.path.getsize(self._LOCAL_CAPTURE_FILE) \
                if os.path.exists(self._LOCAL_CAPTURE_FILE) else 0
        except Exception:
            jsonl_size = 0
        return {
            "mode": self.mode,
            "mitmdump_alive": self._proc_alive() if self.mode == "local" else None,
            "jsonl_size": jsonl_size if self.mode == "local" else None,
            "jsonl_pos": getattr(self, "_jsonl_pos", 0) if self.mode == "local" else None,
            "elevated": self._is_elevated(),
            "child_log_tail": self._child_log_tail(),
        }

    def _child_log_tail(self, lines: int = 5) -> Optional[str]:
        """子进程日志最后几行（local 模式诊断用）"""
        if self.mode != "local":
            return None
        try:
            with open(self._LOCAL_CHILD_LOG, "r",
                      encoding="utf-8", errors="replace") as f:
                content = f.read()
            lg = [ln for ln in content.splitlines() if ln.strip()]
            return "\n".join(lg[-lines:]) if lg else None
        except Exception:
            return None

    # ── mitmproxy 回调（在代理线程执行，需 marshal 回主循环）──

    def _is_host_header(self, kl: str) -> bool:
        """微信宿主环境头：宿主自用上报/会话头，不是小程序业务凭证"""
        return any(kl.startswith(p) or kl == p for p in self._host_name_hints)

    def _on_request(self, flow):
        entry = {
            "type": "proxy",
            "id": id(flow),
            "ts": time.time(),
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "postData": flow.request.get_text() or "",
            "status": "pending",
            "result": None,
            "error": None,
        }
        self._pending[entry["id"]] = entry
        # 提炼会话凭证：白名单 + 值特征识别（自定义签名头自动收编），宿主头除外
        try:
            for k, v in flow.request.headers.items():
                kl = k.lower()
                if v and not self._is_host_header(kl) and (kl in self._cred_headers or self._looks_like_cred(kl, v)):
                    self.session_credentials[k] = v
        except Exception:
            pass

    def _on_response(self, flow):
        entry = self._pending.pop(id(flow), None)
        if not entry:
            return
        try:
            body = flow.response.get_text() or ""
        except Exception:
            body = ""
        entry["status"] = flow.response.status_code
        entry["result"] = {
            "status": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": body[:4000],  # 截断防上下文爆炸
        }
        self._push(entry)

    def _on_error(self, flow):
        entry = self._pending.pop(id(flow), None)
        if not entry:
            return
        entry["status"] = "error"
        entry["error"] = str(getattr(flow, "error", None) or "连接失败")
        self._push(entry)

    def _push(self, entry: dict):
        """入库（截断防御，过滤噪音与代理自身流量）"""
        url = entry.get("url") or ""
        if url.startswith(_NOISE_PREFIXES):
            return
        # mitmproxy 自身的证书分发域名，不算业务流量
        if "://mitm.it" in url:
            return
        self.captures.append(entry)
        if len(self.captures) > self.max_captures:
            del self.captures[: len(self.captures) - self.max_captures]

    # ── 生命周期 ──

    def _reset_buffers(self):
        """清空内存捕获与凭证（代理停止/重启时调用）。

        ProxyCapture 是全局单例、captures 零自动清理（环形滚动仅控上限），
        跨目标测试不重启代理 = 上一个小程序的几百条旧包与全套 token/Cookie
        残留进下一个小程序的抓包与重放（旧 token 会被 _replay_headers 自动
        带进新目标的请求 → 未授权类判定失真）。停止 = 捕获窗口结束，清库。
        """
        self.captures = []
        self.session_credentials = {}
        self._pending = {}

    async def start(self, host: Optional[str] = None, port: Optional[int] = None,
                    mode: Optional[str] = None):
        """启动代理（独立线程跑 mitmproxy 事件循环，不阻塞主服务）

        mode:
          - "regular": 常规代理，需要系统代理/程序主动指向该端口
          - "local":   进程级透明捕获（类似 Proxifier），直接拦截指定进程流量，
                       无需任何系统代理设置；需要管理员权限
        """
        if self.running:
            return {"ok": True, "message": f"代理已在运行 0.0.0.0:{self.port}",
                    "proxy": f"{self.host}:{self.port}", "mode": self.mode}
        if host:
            self.host = host
        if port:
            self.port = port
        if mode in ("regular", "local"):
            self.mode = mode
        # 启动 = 新捕获窗口开场：清上窗口残留（异常退出路径兜底，正常
        # 停止时已清过；last_appid 保留——切换检测靠它跨重启对比）
        self._reset_buffers()

        # local 模式依赖 windows-redirector.exe（WinDivert 驱动），必须管理员权限
        if self.mode == "local" and not self._is_elevated():
            return {"ok": False, "error": "local 模式（进程级透明拦截）需要管理员权限："
                    "请以管理员身份重新运行本系统，或改用 regular 模式（需设置系统代理）"}

        if self.mode == "local":
            return await self._start_local()

        # regular 模式：等待代理端口可连（直接探测端口，不依赖 master.server 内部结构）
        self._thread = threading.Thread(target=self._run_master, daemon=True)
        self._thread.start()

        import socket as _socket
        alive = False
        for _ in range(40):
            await asyncio.sleep(0.25)
            try:
                with _socket.create_connection((self.host, self.port), timeout=0.5):
                    alive = True
                    break
            except OSError:
                continue
        if not alive:
            self.running = False
            return {"ok": False,
                    "error": "代理端口未能监听，启动失败（详见服务日志）"}
        self.running = True

        # 启动自检：经代理请求 mitmproxy 本地证书服务（不依赖外网），
        # 能收到响应说明代理事件循环真正在转发流量
        await asyncio.to_thread(self._selfcheck)

        self._log("info", f"捕获代理已启动 http://{self.host}:{self.port}")
        return {"ok": True, "proxy": f"{self.host}:{self.port}", "mode": "regular",
                "message": "捕获代理已启动；请将系统代理或微信进程代理指向该地址，"
                           "首次 HTTPS 解密需安装 mitmproxy CA 证书（http://mitm.it）"}

    async def _start_local(self) -> dict:
        """local 模式启动：mitmdump 独立子进程 + JSONL 落盘回传"""
        # 清掉上次残留的捕获文件，避免旧数据混入
        try:
            if os.path.exists(self._LOCAL_CAPTURE_FILE):
                os.remove(self._LOCAL_CAPTURE_FILE)
        except Exception:
            pass
        self._jsonl_pos = 0
        self._tail_stop.clear()
        self._local_ready.clear()

        try:
            self._spawn_mitmdump()
        except Exception as e:
            return {"ok": False, "error": f"mitmdump 子进程启动失败: {e}"}
        self._drain_last_line = None

        # 等就绪：轮询子进程日志文件，"Local redirector started" 即就绪
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 60
        while loop.time() < deadline:
            self._poll_child_log()
            if self._local_ready.is_set():
                break
            if not self._proc_alive():
                err_tail = getattr(self, "_drain_last_line", "") or "无输出"
                self.running = False
                return {"ok": False,
                        "error": f"mitmdump 子进程提前退出（code={self._proc.returncode}）；"
                                 f"最后输出: {err_tail}"}
            await asyncio.sleep(0.5)
        else:
            self._stop_local()
            self.running = False
            return {"ok": False, "error": "local 模式就绪等待超时（60s），"
                                          "详见 mitmdump_child.log 与服务日志"}

        self.running = True
        self._tail_stop.clear()
        self._tail_thread = threading.Thread(target=self._tail_jsonl, daemon=True)
        self._tail_thread.start()
        self._log("info", f"捕获代理已启动（local 模式，独立子进程）— 正在透明拦截进程 "
                          f"{self.process_spec} 的全部流量，无需设置系统代理")
        return {"ok": True, "proxy": f"{self.host}:{self.port}", "mode": "local",
                "message": f"已透明拦截 {self.process_spec} 进程流量（无需系统代理）；"
                           f"HTTPS 解密需已安装 mitmproxy CA 证书"}

    def _stop_local(self):
        """停止 mitmdump 子进程与解析线程"""
        self._tail_stop.set()
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    self._proc.kill()
        except Exception:
            pass
        # mitmdump 退出时不会带走 windows-redirector（设计上避免 UAC），
        # 但它会把拦截规则置空；仅当残留时才需要提权清理
        # 若是 terminate 硬杀（没有优雅退出机会），拦截规则可能残留形成
        # 流量黑洞（小程序白屏），服务已提权，直接补杀 redirector 兜底
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "windows-redirector.exe"],
                capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            if self._child_log:
                self._child_log.close()
        except Exception:
            pass
        self._child_log = None
        self._proc = None
        self._tail_thread = None
        self._jsonl_pos = 0
        try:
            if os.path.exists(self._LOCAL_CAPTURE_FILE):
                os.remove(self._LOCAL_CAPTURE_FILE)
        except Exception:
            pass

    def _selfcheck(self):
        """走代理请求一次 http://mitm.it，验证转发链路"""
        try:
            import httpx
            r = httpx.get("http://mitm.it/",
                          proxy=f"http://{self.host}:{self.port}", timeout=8)
            self._log("info", f"代理自检: mitm.it -> HTTP {r.status_code}")
        except Exception as e:
            self._log("warn", f"代理自检失败: {e}")

    def _run_master(self):
        """代理线程（regular 模式专用）：新建事件循环，并在【该循环运行的协程内】
        构造与运行 DumpMaster。

        两个已踩过的坑：
        1. DumpMaster.__init__ 调 asyncio.get_running_loop()，必须在协程内构造
        2. ErrorCheck addon 会因启动期 ERROR 日志直接 sys.exit 杀死线程且
           Exception 接不住，嵌入场景必须移除；错误转为落日志

        local 模式不再走此函数（嵌入 DumpMaster 会在服务进程内卡死在
        redirector IPC 握手），改用 mitmdump 独立子进程，见 _start_local()。
        """
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # 启动期 ERROR 日志收集
        errors: List[str] = []

        class _ErrCollector(logging.Handler):
            def emit(self, record):
                errors.append(record.getMessage())

        collector = _ErrCollector(level=logging.ERROR)
        root = logging.getLogger()
        root.addHandler(collector)

        async def _setup_and_run():
            opts = options.Options(listen_host=self.host, listen_port=self.port)
            self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            # 移除 ErrorCheck：嵌入运行不允许静默 sys.exit
            try:
                ec = self._master.addons.get("errorcheck")
                if ec:
                    self._master.addons.remove(ec)
            except Exception:
                pass
            self._master.addons.add(
                _CaptureAddon(self._on_request, self._on_response, self._on_error))
            for msg in errors:
                self._log("error", f"mitmproxy 启动错误: {msg}")
            errors.clear()
            await self._master.run()

        try:
            self._loop.run_until_complete(_setup_and_run())
        except Exception as e:
            self._log("error", f"代理循环退出: {e}")
            for msg in errors:
                self._log("error", f"mitmproxy 错误: {msg}")
        finally:
            root.removeHandler(collector)
            # 主循环已退出：必须同步清状态，否则 redirector 可能残留劫持流量
            # 而状态却显示运行中（流量黑洞 → 小程序白屏）。
            # regular 模式无 redirector，此保护仅对历史 local 兼容场景有意义
            if self.mode == "local" and self.running:
                self._log("warn", "代理线程已退出，local 拦截随之失效；"
                                  "如小程序断网请停止/重启代理或重启微信")
            self.running = False

    async def stop(self):
        if self.mode == "local":
            if not self.running:
                return {"ok": True, "message": "代理未在运行"}
            self.running = False
            self._stop_local()
            self._reset_buffers()   # 停止 = 捕获窗口结束，清内存残留
            self._log("info", "捕获代理已停止")
            return {"ok": True, "message": "捕获代理已停止"}
        if not self.running:
            return {"ok": True, "message": "代理未在运行"}
        try:
            if self._master:
                # Master.shutdown() 同步且线程安全，直接调用设置退出标志
                self._master.shutdown()
        except Exception as e:
            self._log("warn", f"停止代理异常: {e}")
        # 等代理线程真正退出（master.run() 返回后线程结束），避免旧线程
        # 占着 redirector 单例导致下次启动流量不进新 master
        if self._thread:
            self._thread.join(timeout=10)
        self._master = None
        self.running = False
        self._reset_buffers()   # 停止 = 捕获窗口结束，清内存残留
        self._log("info", "捕获代理已停止")
        return {"ok": True, "message": "捕获代理已停止"}

    # ── 查询 ──

    def status(self) -> dict:
        running = self.running
        if running and self.mode == "local" and not self._proc_alive():
            # mitmdump 子进程意外死亡：同步纠正状态，避免 UI 显示运行中却无流量
            running = False
            self.running = False
            self._log("warn", "mitmdump 子进程已退出，local 拦截失效；"
                              "如小程序断网请重启微信")
        return {
            "running": running,
            "proxy": f"{self.host}:{self.port}" if running else None,
            "mode": self.mode if running else None,
            "capture_count": len(self.captures),
            "credentials": sorted(self.session_credentials.keys()),
        }

    def get_captures(self, limit: int = 30, url_filter: Optional[str] = None,
                     slim: bool = True) -> dict:
        """查询捕获记录；url_filter 按 URL 关键字子串过滤（不区分大小写）

        slim 输出策略（上下文成本与可见性平衡）：
        - 全部头名字可见（自定义签名头如 X-Localid-Flag 不再隐身）
        - 已知凭证头 + 值特征识别出的疑似凭证头回全文（重放数据源）
        - 其余值超 80 字符截预览（完整值经 get_capture_detail 按 capture_id 下钻）
        - 每条带 capture_id（本轮从 -N 开始倒序编号，负数避免与列表索引混淆）
        """
        items = self.captures
        if url_filter:
            kw = url_filter.lower()
            items = [c for c in items
                     if kw in (c.get("url") or "").lower()
                     or kw in (c.get("name") or c.get("postData") or "").lower()]
        selected = items[-limit:] if limit and limit > 0 else items
        if slim:
            start_id = -len(selected)   # 负数序号：capture_id=-1 是最新一条
            out = []
            for c in selected:
                req_h = c.get("headers") or {}
                h_view = {}
                cred_hints = []
                for k, v in req_h.items():
                    kl = k.lower()
                    if kl in ("host", "content-length", "connection",
                              "accept-encoding", "accept-language"):
                        continue  # 纯协议头，测试无用不占上下文
                    vv = str(v)
                    if kl in self._cred_headers or self._looks_like_cred(kl, vv):
                        h_view[k] = vv          # 凭证类：全文（重放要原文）
                        if kl not in self._cred_headers:
                            cred_hints.append(k)
                    elif len(vv) > 80:
                        h_view[k] = vv[:60] + f"...[{len(vv)}字符，get_capture_detail 下钻]"
                    else:
                        h_view[k] = vv
                out.append({
                    "capture_id": start_id,
                    "url": (c.get("url") or "")[:300],
                    "method": c.get("method"),
                    "status": c.get("status"),
                    "request_headers": h_view,
                    **({"suspect_cred_headers": cred_hints} if cred_hints else {}),
                    "postData": (c.get("postData") or "")[:1000],
                    "response": (c.get("result") or {}).get("body", "")[:1500]
                    if isinstance(c.get("result"), dict) else c.get("status"),
                })
                start_id += 1
            return {"total": len(items), "count": len(out), "captures": out}
        return {"total": len(items), "count": len(selected), "captures": selected}

    def get_capture(self, capture_id: int) -> Optional[dict]:
        """按 capture_id 取单条完整记录（capture_id 为 get_captures 里分配的负数序号）"""
        idx = int(capture_id)
        if idx >= 0 or -idx > len(self.captures):
            return None
        return self.captures[idx]

    # 值特征识别疑似凭证（自定义签名头无白名单可用时的自动兜底）
    _JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$")
    _RAND_RE = re.compile(r"^[A-Za-z0-9+/=_.\-]{32,}$")

    @classmethod
    def _looks_like_cred(cls, name_lower: str, value: str) -> bool:
        """值长得像凭证 → 疑似凭证头（自动识别，免人工白名单）。

        排除明显非凭证头（缓存/签名完整性/UA 等长 base64 是正常内容）；
        JWT 三段式命中即判；其余要求 ≥32 位无空格随机串 + 名字有凭证意味。
        """
        if name_lower in ("user-agent", "referer", "accept", "if-none-match",
                          "if-modified-since", "etag", "content-md5"):
            return False
        # 宿主环境头（x-wx-*/pass_ticket 等）不是业务凭证（值特征识别把
        # x-wx-wxareportob-token 误判成凭证头，r9 修复）；白名单头先于本判定，
        # 上层 _on_request 已先挡宿主头，此处类方法无实例上下文不重复判
        if not value or len(value) < 24 or " " in value.strip():
            return False
        if cls._JWT_RE.match(value.strip()):
            return True
        name_cred = any(t in name_lower for t in ("token", "sign", "auth", "key",
                                                  "session", "ticket", "secret", "nonce"))
        return bool(name_cred and cls._RAND_RE.match(value.strip()))
