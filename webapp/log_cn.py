"""
日志中文化 — 把引擎输出的英文日志映射为中文
只影响 Web 端显示，原 CLI/GUI 输出不变
"""
import re

# 前缀映射：[server] → [服务] 等
_PREFIX = {
    "[server]": "[服务]",
    "[frida]": "[注入]",
    "[frida client]": "[注入客户端]",
    "[miniapp]": "[小程序]",
    "[cdp]": "[CDP]",
    "[userscript]": "[用户脚本]",
    "[anti-debug]": "[反调试]",
    "[offsets]": "[偏移]",
}

# 完整文案映射（支持 {0} {1}... 占位符，按原文中出现顺序填充）
_PATTERNS = [
    # server
    (r"^\[server\] engine stopped$", "[服务] 引擎已停止"),
    (r"^\[server\] debug server running on ws://localhost:(\d+)$", "[服务] 调试服务已启动 ws://localhost:{0}"),
    (r"^\[server\] debug server waiting for miniapp to connect\.\.\.$", "[服务] 调试服务已就绪，等待小程序连接…"),
    (r"^\[server\] proxy server running on ws://localhost:(\d+)$", "[服务] CDP 代理已启动 ws://localhost:{0}"),
    (r"^\[server\] link: devtools://devtools/bundled/inspector\.html\?ws=([\d.]+):(\d+)$",
     "[服务] 调试面板链接: devtools://devtools/bundled/inspector.html?ws={0}:{1}"),
    # miniapp
    (r"^\[miniapp\] miniapp client connected$", "[小程序] 小程序已连接"),
    (r"^\[miniapp\] miniapp client disconnected$", "[小程序] 小程序已断开"),
    (r"^\[miniapp\] miniapp client err: (.*)$", "[小程序] 小程序连接出错: {0}"),
    (r"^\[miniapp\] registering scripts immediately on connection\.\.\.$", "[用户脚本] 连接建立，立即注册脚本…"),
    # cdp
    (r"^\[cdp\] CDP client connected$", "[CDP] 调试客户端已接入"),
    (r"^\[cdp\] CDP client disconnected$", "[CDP] 调试客户端已断开"),
    (r"^\[cdp\] CDP client err: (.*)$", "[CDP] 调试客户端出错: {0}"),
    # userscript
    (r"^\[userscript\] registering scripts immediately on connection\.\.\.$", "[用户脚本] 连接建立，立即注册脚本…"),
    (r"^\[userscript\] registered \(persistent\): (.*)$", "[用户脚本] 已注册（持久）: {0}"),
    (r"^\[userscript\] registration done, scripts will run on page load$", "[用户脚本] 注册完成，脚本将在页面加载时自动执行"),
    (r"^\[userscript\] registration error: (.*)$", "[用户脚本] 注册失败: {0}"),
    (r"^\[userscript\] immediate inject \(Runtime\.evaluate\): (.*)$", "[用户脚本] 即时注入 (Runtime.evaluate): {0}"),
    (r"^\[userscript\] immediate inject warning: (.*)$", "[用户脚本] 即时注入警告: {0}"),
    # anti-debug
    (r"^\[anti-debug\] Debugger\.enable sent$", "[反调试] 已发送 Debugger.enable"),
    (r"^\[anti-debug\] Debugger\.setSkipAllPauses\(true\) sent$", "[反调试] 已发送 Debugger.setSkipAllPauses(true)"),
    (r"^\[anti-debug\] Debugger\.setSkipAllPauses re-sent after setupContext$", "[反调试] setupContext 后已重发 Debugger.setSkipAllPauses"),
    # frida
    (r"^\[frida\] injected pid=(\d+), version=(\d+)$", "[注入] 已注入进程 pid={0}，WMPF 版本 {1}"),
    (r"^\[frida\] failed to inject pid=(\d+): (.*)$", "[注入] 注入进程 pid={0} 失败: {1}"),
    (r"^\[frida\] ready \(win\), version=(\d+), (\d+) process\(es\)$", "[注入] 就绪（Windows），WMPF 版本 {0}，共 {1} 个进程"),
    (r"^\[frida\] ready \(mac\), version=(\d+), (\d+) process\(es\)$", "[注入] 就绪（macOS），WMPF 版本 {0}，共 {1} 个进程"),
    (r"^\[frida\] you can now open any miniapps$", "[注入] 完成！现在可以打开任意小程序了"),
    (r"^\[frida\] WeChatAppEx\.exe process not found$", "[注入] 未找到 WeChatAppEx.exe 进程，请先打开微信 PC 版"),
    (r"^\[frida\] WeChatAppEx\.exe main process not found$", "[注入] 未找到 WeChatAppEx.exe 主进程"),
    (r"^\[frida\] could not locate main WMPF process$", "[注入] 无法定位 WMPF 主进程"),
    (r"^\[frida\] cannot detect WMPF version from path$", "[注入] 无法从路径解析 WMPF 版本号"),
    (r"^\[frida\] invalid WMPF version$", "[注入] WMPF 版本号无效"),
    (r"^\[frida\] version config not found: (\w+)/(\d+)$", "[注入] 缺少偏移配置: {0}/{1} — 重启引擎将自动从上游获取（或检查网络后重试）"),
    (r"^\[frida\] hook script not found$", "[注入] 未找到 hook 脚本文件"),
    (r"^\[frida client\] (.*)$", "[注入客户端] {0}"),
]

_COMPILED = [(re.compile(p), t) for p, t in _PATTERNS]


def translate_log(text: str) -> str:
    """把引擎英文日志翻译成中文；无法识别的仅替换前缀标签"""
    text = text.strip()
    for pat, tpl in _COMPILED:
        m = pat.match(text)
        if m:
            return tpl.format(*m.groups())
    # 未匹配：替换已知前缀，其余保持原样
    out = text
    for en, zh in _PREFIX.items():
        if out.startswith(en):
            out = zh + out[len(en):]
            break
    return out
