---
name: wmpf-offset-extraction
description: 从新版微信 Windows 小程序运行时 flue.dll 自动提取 WMPFDebugger 所需 Hook 偏移并生成 addresses.<ver>.json。当用户提到 WMPFDebugger 版本适配、微信小程序更新后偏移失效、提取 LoadStartHookOffset、CDPFilterHookOffset、CastToJsonHookOffset 或 SceneOffsets 时使用。不适用于非微信小程序的二进制逆向。
---

# WMPF flue.dll Hook 偏移自动提取

为新版微信小程序运行时 `flue.dll` 生成 WMPFDebugger 兼容的 `addresses.<版本号>.json`。核心管线已经过 26134(回归)与 26513(实测)双版本验证，8/8 字段命中。

## 快速使用

1. 找到目标 DLL：`%APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\<版本号>\extracted\runtime\flue.dll`
2. 依赖：Python + `pip install pefile capstone`
3. 执行（本技能自带脚本，约 3-5 分钟，主要耗时是 .text 全段扫描）：

```powershell
python <skill_dir>/scripts/extract_offsets.py "<flue.dll 路径>" <版本号>
```

4. 产物：`addresses.<版本号>.json`（可直接放入 WMPFDebugger 的 `frida/config/`）+ `addresses.<版本号>.evidence.txt`（每条结论的指令级证据，供人工复核）。

## 方法论（五步管线）

详细原理、锚点表与决策树见 [references/methodology.md](references/methodology.md)。概要：

1. **字符串锚定** — 在 `.rdata` 中定位 3 组锚点串：`AppletIndexContainer::OnLoadStart(bool, const std::string &)` + `applet_index_container.cc`（LoadStart 双锚点）、`CastToJson\x00`（唯一引用）、`SendToClientFilter\x00`。
2. **交叉引用扫描** — 对 `.text` 全段做滑动窗口 disp32 扫描（±256MB 范围），把每个可能位置当 rip 相对引用解引用。不要假设指令长度（6/7 字节定长窗口会漏掉 10+ 字节 lea）。
3. **锚点区间扩展** — `lea` 常指向日志串的中间片段（前缀部分），锚点区间必须扩展为"完整日志串"（向前回溯到 `\x00` 之后，向后到 `\x00`），否则正确函数会漏配。
4. **`.pdata` 函数回溯** — 用异常表 RUNTIME_FUNCTION 把 xref 地址映射回所属函数起始，配置里的偏移 = 函数起始 RVA。LoadStart 取"同时引用两个锚点且引用次数最高"的函数；CDPFilter 取引用锚点的最大函数体（外层过滤函数）；CastToJson 取引用次数最高者。
5. **结构体魔法数字** — 在三个 hook 函数及其直接 callee 中扫描特征位移：`0x40/0x650/0x8`（LaunchConfig）、`0x608/0x10`（RemoteDebugConfig）、`0x1E0`（Scene，伴随 `cmp ..., 0x44D` 即场景 1101）、`0x288`（WebSocketURL）、`0x2EC`（RemoteDebugMode）。

## 失败时的人工介入点

- 证据文件出现"未找到，需人工分析" → 微信改了字符串。用 IDA/字符串搜索找新锚点，更新脚本 `ANCHORS` 表（新版本常只改字符串前缀路径，语义不变）。
- Hook 连接后立即断开 → LoadStart 偏移错误；小程序无法加载 → SceneOffsets 错误。
- 结构体偏移跨版本通常不变（26134→26513 未变），版本适配只漂移三个函数地址。
