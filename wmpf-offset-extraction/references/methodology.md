# WMPF flue.dll 偏移提取方法论

> 本文是 `wmpf-offset-extraction` 技能的深度参考。管线已在 26134（回归，对照已知配置 8/8 命中）与 26513（实测，独立语义验证通过）双版本验证。

## 背景

WMPFDebugger 通过 Frida hook 微信 Windows 小程序运行时（WMPF）里的三个函数实现远程调试。微信每次更新重新编译 `flue.dll`，函数地址漂移，但**代码语义结构稳定**——这就是自动提取可行的根基。

三个 hook 点（版本 ≥ 18891 的现代格式）：

| 配置字段 | 目标函数 | 提取锚点 |
|---|---|---|
| `LoadStartHookOffset` | `applet::AppletIndexContainer::OnLoadStart(bool, const std::string&)` | 日志签名串 + 源文件路径串（双锚点） |
| `CastToJsonHookOffset` | 新版把 protobuf 消息转 JSON 的序列化函数 | `"CastToJson"` 字符串（全 DLL 唯一引用） |
| `CDPFilterHookOffset` | Chrome DevTools 协议过滤器（拦截 SendToClient） | `"SendToClientFilter"` 字符串（取外层最大函数） |

输出格式（全部为 RVA = VA - ImageBase，hex 大写数字）：

```json
{
  "Version": 26513,
  "LoadStartHookOffset": "0x2F4D760",
  "CDPFilterHookOffset": "0x3B6A9C0",
  "CastToJsonHookOffset": "0xCB331E0",
  "MiniAppConfigStructOffsets": {
    "LaunchConfigOffsets": [64, 1616, 8],
    "RemoteDebugConfigOffsets": [1544, 16],
    "SceneOffset": 480,
    "WebSocketURLStringOffset": 648,
    "RemoteDebugModeOffset": 748
  }
}
```

## 五步管线详解

### 第 1 步：字符串锚定

对 DLL 原始字节做 `bytes.find` 定位锚点串，经 PE 节表（`pefile`）换算文件偏移 → VA：

- `b"AppletIndexContainer::OnLoadStart(bool, const std::string &)"` — OnLoadStart 日志调用打印的函数签名，唯一
- `b"applet_index_container.cc"` — 源文件路径串，OnLoadStart 日志前缀的一部分
- `b"CastToJson\x00"` — 必须 `\x00` 结尾，防止匹配到 `CastToJsonXxx` 之类更长符号
- `b"SendToClientFilter\x00"` — CDP 过滤函数的日志标签

### 第 2 步：交叉引用扫描（最容易踩坑的一步）

x86-64 用 `lea rax, [rip + disp32]` 引用字符串，disp32 是**指令尾到目标**的差。坑点：

1. **不要假设指令长度**。6/7 字节定长窗口会漏掉前缀更长的 lea（实测正确函数的引用是 10 字节指令里的 disp32）。正确做法：对 `.text` 每个字节位置 i，把 `[i, i+4)` 当 disp32 解一次，目标 = `VA(i) + 4 + disp`。
2. **disp 范围必须 ±256MB**。`.text`(RVA~0x1000) 到 `.rdata`(RVA~0xBD43000) 跨度近 200MB，正向 disp 可达 268MB，64MB 窗口会把 CDPFilter 的引用滤掉。
3. **目标是"完整日志串"区间**。编译器经常让 `lea` 指向日志串的中间（如只取 `AppletIndexContainer::OnLoadStart(...)` 而不带 `virtual void applet::` 前缀），所以匹配区间要向前回溯到上一条 `\x00` 之后、向后到本串 `\x00`。只匹配锚点本身会漏掉正确函数，盲目扩 256 字节又会把相邻字符串池全部误报。

### 第 3 步：`.pdata` 函数回溯

x64 PE 的 `.pdata` 节是 RUNTIME_FUNCTION 数组（每项 12 字节：StartRVA/EndRVA/UnwindInfoRVA），等价于 IDA 的函数边界表。二分查找 xref 所在函数。**配置里的偏移 = 函数起始 RVA**，不是 xref 指令地址。

三个 hook 点的函数选择策略不同：

- **LoadStart**：双锚点交集 — 取"同时引用签名串和 .cc 路径串"的函数（日志前缀共享导致多个函数都引用路径串，交集是强判别），若交集多个则取引用次数最高者。实测交集恰好 1 个候选。
- **CastToJson**：引用次数最高者（`"CastToJson"` 全 DLL 唯一引用，无需复杂策略）。
- **CDPFilter**：取引用它的**最大函数体**。`"SendToClientFilter"` 被 1 个大过滤函数（~0x34D0 字节）和若干内嵌小函数（普通日志点，几百字节）引用，最大者即目标。

### 第 4 步：结构体魔法数字

WMPFDebugger 的 `hook.js` 用固定偏移读写"小程序启动配置结构体"字段。在三个 hook 函数及其直接 callee（call 目标，函数体 8B~32KB）里反汇编，统计 `+ disp]` 形式的正位移：

| disp | 含义 | 典型指令形态 |
|---|---|---|
| `0x40`, `0x650`, `0x8` | LaunchConfigOffsets[0..2] | `mov rax, [rsi + 0x40]` |
| `0x608`, `0x10` | RemoteDebugConfigOffsets[0..1] | `mov rcx, [rax + 0x608]` |
| `0x1E0` | SceneOffset | `cmp dword ptr [rcx + 0x1e0], 0x44d` ← 场景 1101，最强证据 |
| `0x288` | WebSocketURLStringOffset | `mov rdx, [rax + 0x288]` |
| `0x2EC` | RemoteDebugModeOffset | `cmp dword ptr [rcx + 0x2ec], 1` |

注意 capstone 对小位移输出十进制（`[rdi + 8]`），正则要同时接 `0x[0-9a-f]+` 和 `\d+`（`int(m, 0)`）。

**版本间规律**：结构体偏移跨版本几乎不变（26134→26513 五组全同），漂移的只有三个函数地址。所以真正决定成败的是第 1-3 步。

## 语义自检清单（产出后必做）

不依赖提取器自身逻辑，用独立脚本验证：

1. 三个 RVA 都是 `.pdata` 中的函数起始（`bisect` 查表）
2. LoadStart 函数体内出现 `cmp dword ptr [rcx+0x1E0], 0x44D`（场景 1101 = 远程调试）
3. CastToJson 函数内存在 `lea` 指向 `"CastToJson"` 串 VA
4. CDPFilter 函数开头附近有 `cmp dword ptr [rdi+8], 6`（hook.js 依赖的过滤谓词，语义 = vtable type 6 时置 0 放行）

4 项全过才可信。任何一项失败 → 回到证据文件人工复核。

## 人工介入决策树

```
证据文件出现"未找到,需人工分析"
├─ LoadStart 未找到
│   ├─ 签名串变了 → IDA 搜 "OnLoadStart" 看新串, 更新 ANCHORS[0]
│   └─ .cc 路径变了 → 搜 "applet_index_container", 更新 ANCHORS[1]
├─ CastToJson 未找到
│   └─ 新版可能改名为 CastToJsonV2/ToJson → 搜字符串池 "Cast", 人工确认唯一引用函数
└─ CDPFilter 未找到
    └─ 搜 "SendToClient"/"DevTools" 相关新串, 取引用它的最大函数
```

运行时症状对照（来自 WMPFDebugger 社区经验）：

- 连接后立即断开 → LoadStartHookOffset 错（函数签名不匹配）
- 小程序无法加载/场景识别错误 → SceneOffsets 错
- CDP 消息不透传 → CDPFilterHookOffset 错
- DevTools 面板空白无消息 → CastToJsonHookOffset 错（新版专用 hook 点）

## 环境要求

- Python 3.8+
- `pip install pefile capstone`
- 无需 IDA Pro——整套管线纯静态解析 PE + 反汇编，脚本约 250 行

## 版本历史验证记录

- 26134：回归测试，8/8 字段与已知配置逐字段一致
- 26513：实测提取，4 项语义自检全过，结构体偏移与 26134 完全相同
