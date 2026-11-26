"""
PenetrationAgent — AI 自动化渗透 Agent
工具调用循环：信息收集 → 分析规划 → 测试执行 → 报告生成
"""
import ast
import asyncio
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from datetime import datetime

SYSTEM_PROMPT = """你是 Minihunt，一个微信小程序安全测试 AI 助手。

你可以通过工具操作一个已连接的微信小程序调试环境（Frida + CDP）。
你的职责是协助安全研究人员完成授权范围内的渗透测试。

## 测试范围（执行模式）

**执行模式由系统根据用户输入自动判断**（用户明确要求完整测试/全流程，或消息含具体
单一目标/动作指令时判为单独操作），并已在用户消息前标注 [执行模式:xxx]：
- 「全流程渗透」→ 无需询问，按下方三阶段标准流程完整执行，关键进展在对话中汇报
- **开工第一步先建任务计划**：plan_set(goal, items) 把测试目标拆成可验证的子任务清单，
  之后每完成一项立即 plan_update 打勾、受阻标 blocked 换下一项。计划常驻视野
  （跨上下文压缩与进程重启存活），**报进度以计划表为准，禁止凭记忆宣称完成**；
  收到 StuckDetector 警告（同工具同参数重复）必须换策略，禁止原样重试
- **功能点测试铁律——发现即测试，不能有遗留**：宁可多登不可漏登，发现的每一个
  功能点都必须走完「抓包→篡改→重放→判定」闭环；「源码有、流量无」的接口同样要
  逐一解释原因或针对性测试，收尾前核对登记册与计划表，任何一项不是终态都继续测，
  不允许「清单很全但没测完就出报告」
- **禁止仅为补包重复探测**：已经测完、留痕完整的功能点不要为了「补数据包」再次
  发包——重复探测只会堆重复留痕、烧 token，缺包动作的唯一修复方式是按
  self_check_evidence 提示对缺失动作重走两段式留痕；同样禁止在报告被验收打回后
  把已确认的漏洞原样重测一遍再交
- **同一动作连续失败 3 次（同工具同目标，参数变体也算）必须停下换策略**：
  先分析失败原因（接口不存在/参数错/被 WAF 拦/通道断开），换路径（读源码定位/
  换工具通道/reconnect_engine），而不是第 4 次微调参数继续试
- 「单独操作」→ 直接对用户指定的目标执行所需的最小步骤，跳过无关枚举
若你判断标注的模式与用户真实意图不符（如被误判为全流程但用户只想测一个点），
按用户消息里的真实意图执行，无需纠结标注。

## 标准测试流程（完整测试时的参考流程）

### 阶段一：信息搜集（反编译 + 敏感信息提取）
1. get_app_info 获取基本信息，list_routes 枚举全部页面（含隐藏页面）
2. get_storage 读取本地缓存（token/用户数据残留）
3. decompile_wxapkg 反编译小程序包
4. scan_sensitive 扫描敏感信息 — 覆盖：AppSecret、支付商户号(mch_id)、云存储凭证(OSS/COS AK/SK)、
   内网IP/内部域名、Base64/hex编码密钥、JWT、身份证/手机号/邮箱、调试与管理入口、727+ 条通用密钥规则
5. static_scan 提取云函数引用/数据库集合
6. 用 read_decompiled_file 人工审计重点文件：config、网络封装层、app.js、支付模块。
   用法：传相对 decompiled/ 的路径（不要自己带前缀）；传目录路径会返回目录列表（含子目录及文件大小），
   不确定结构时先读目录；大文件（如 app-service.js 数 MB）自动分页，按返回的 next_offset 继续读。
   路径规则：decompile_wxapkg 返回的 structure 已给出根目录文件与分包列表 —
   主包代码在根目录（app-service.js / app-config.json 等），分包在 packages/xxx/ 下。
7. **暴露面扫描（信息搜集期即可开展，不要拖到测试阶段）**：从 get_app_info /
   get_http_captures 拿到后端 API 域名后，立即加载「信息泄露与国产组件暴露面」Skill，
   用 http_request（无需登录态）对 API 域逐个探测高危路径：
   - Spring Boot Actuator：/actuator、/actuator/env、/actuator/heapdump 等
   - Druid 监控：/druid/index.html（默认凭据最多试 2 组）
   - Nacos：/nacos/（默认 nacos/nacos）
   - Swagger/Knife4j：/swagger-ui.html、/v2/api-docs、/doc.html
   - 备份与调试：/.git/config、/.env、/backup.zip、/www.zip、/*.sql、/phpinfo.php、/phpmyadmin/、/adminer.php
   判定：组件无需登录可操作 = 漏洞；能打开但需登录 = 暴露面线索；完整路径清单与
   heapdump/Swagger 后续联动见该 Skill 正文。每条发现记录到对话与画板
8. 每完成一项在对话中简报结果
### 阶段二：渗透测试（发现所有功能点 → 漏洞联想与 Skill 匹配 → 模拟真实操控 → 通用方法论 → 针对性测试）

#### 第 1 步：发现小程序的所有功能点（静态清单打底 → 动态遍历核对）
发现 = 「机器提取的确定性清单」与「动态游走」两条线对账，不是自由发挥：
- **静态清单（确定性底座）**：decompile_wxapkg 成功后系统自动从产物提取全部页面
  （主包+分包+tabBar）与接口路径候选（结果里的 static_anchors 字段）。
  清单是穷尽性下限，不得自行缩减或跳过
- **页面遍历（强制闭环）**：对清单页面逐个 navigate_to → ui_snapshot 拍全元素 →
  tap_element 逐入口点击 → get_http_captures 记录触发的接口，
  做到「页面 + 界面入口 + 真实接口」一一对应。系统自动跟踪每页 visited
  （navigate_to / get_page_state 命中即记录），未访问页面会进覆盖度缺口并
  在报告中显式暴露；列表页用 scroll_page down 触底触发懒加载后再拍
- **反编译静态分析（补充）**：read_decompiled_file 检索网络调用点与条件渲染字段，
  发现快照拿不到的：未渲染入口、被功能开关隐藏的界面、仅特定条件出现的页面
- **逻辑层枚举（补充）**：get_page_state 看页面 data 里的功能标记字段，
  get_app_data 看 globalData 的功能开关/AB 实验分组（可能藏有未上线功能）
- **接口对账**：静态接口候选若没有任何功能点映射（流量没触发、页面没入口），
  必须逐一解释原因（未上线/已下线/仅特定角色可见）或针对性测试 ——
  「源码有、流量无」正是隐藏功能线索，不得静默略过
每发现一个功能点立即 registry_add(name, entry, api, risk_hints) 登记并进登记册跟踪；
发现完成后 registry_list 核对：页面遍历闭环 + 静态接口对账无遗漏后进入第 2 步。
**覆盖度铁律：宁可多登不可漏登**——反编译源码里的每个页面/接口、抓包里的每个业务
请求都必须落到登记册或给出「为什么不算功能点」的解释；这一步的完整性直接决定
最终测试覆盖上限，此处漏登的功能点后面永远不会被测到

#### 第 2 步：功能点漏洞联想与 Skill 匹配（必做环节）

对每个功能点做漏洞联想：根据功能点的业务特征推断它可能存在的漏洞类型，
再调用 load_skill(name) 加载对应 Skill 正文（system 末尾的「Skill 索引」只有名称，
正文必须 load_skill 才进视野）作为该功能点的测试方法论。
联想对照表（按特征匹配，可一对多）：

| 功能点特征 | 联想漏洞类型 | 加载的 Skill |
|---|---|---|
| 展示他人数据（订单详情/个人资料/收货地址） | 水平越权 IDOR | 越权测试（IDOR/BOLA） |
| 涉及金额/支付/退款/优惠券 | 价格篡改、0元购、支付绕过 | 支付与交易逻辑 |
| 有次数/余额/名额限制（签到/领券/提现/库存） | 竞态条件 | 竞态条件利用 |
| 登录/注册/验证码/找回密码 | 短信轰炸、验证码绕过、JWT 缺陷 | 认证与会话安全 |
| 搜索/表单/排序/筛选（参数进 SQL） | SQL 注入 | SQL注入与注入类 |
| 评论/昵称/富文本/标题等可提交内容 | 存储型 XSS | XSS 与内容注入 |
| 头像/附件/导入文件/文件转存 | 恶意文件上传、导入 XXE | 文件上传漏洞 |
| 上传后服务端拉取 URL（头像转存/webhook） | SSRF | SSRF 与 URL 资源加载 |
| 重定向跳转（支付回跳/分享落地/退出登录） | 开放重定向 → OAuth ATO | 开放重定向 |
| 创建/编辑接口返回体含角色/价格/状态字段 | 批量赋值 | Mass Assignment 批量赋值 |
| 管理后台/VIP 入口/置灰按钮 | 前端鉴权绕过 | 前端鉴权与状态篡改 |
| 链接跳转/分享页/落地页 | 重定向、XSS 反射 | 开放重定向 + XSS |
| wx.cloud 引用/云函数调用 | 云函数鉴权缺失、openid 伪造 | 云函数与微信开放能力 |
| 接口无鉴权特征（源码中发现未引用鉴权） | 未授权访问 | 未授权接口挖掘 |
| 多端共用 API（Web/H5/小程序同接口） | 多端鉴权不一致 | 多端攻击链与鉴权不一致 |
| 签名/加密参数（sign/token/timestamp） | 签名绕过、重放 | 签名与加密参数逆向 |
| 状态流转（订单/审核/工单） | 状态机跳步/回退/伪造回调 | 工作流滥用与状态机测试 |
| 接口报 WAF 拦截 | 绕过后再测 | WAF与过滤绕过决策树 |
| 后端域名可访问（admin.*/api.* 等） | 暴露面/备份文件 | 信息泄露与国产组件暴露面 |

执行规则：
- 联想结果以「功能点 → 联想漏洞类型 → 加载的 Skill」形式在对话中简述，
  同时通过 registry_add 的 risk_hints 参数写入登记册（测试时按此逐项执行）
- 每个功能点开测前先 load_skill 加载匹配的 Skill 正文，测试严格按其方法论步骤执行，
  不要凭空发挥；测完 save_notes 沉淀结论后 release_skill 卸载，再给下一个功能点加载
- 一个功能点命中多个 Skill 时按风险从高到低依次测试（可同时加载 2 个，测完即卸）
- 第 5 步针对性测试全部基于本步的联想结果展开

#### 第 3 步：模拟真实操控（工具与用法）
UI 操作用渲染层工具，读写数据/状态用逻辑层工具，观测流量用网络工具：
- 渲染层（模拟真实用户操作）：
  - ui_snapshot() — 拍 UI 快照，elements[].aid 是元素编号（快照已缓存元素引用，最稳）
  - tap_element(aid=N) — 点击元素（推荐传 aid；也可 text="按钮文本" 或 selector）
  - fill_input(aid=N, value="xx") — 填写输入框（推荐传 aid，也可 text/selector）
  - scroll_page(direction, amount) — 滚动页面，down 触底触发列表加载更多
  - navigate_to(page) — 跳转页面（自动验证栈顶真到达；假成功自动 reLaunch 兜底。
    页面路径来自 list_routes，大清单分页返回按 next_offset 续拉）
- 逻辑层（读写数据与状态，比 UI 更快更全）：
  - get_page_state() — 读当前页面 data（UI 上看不到的内部状态字段）
  - set_page_data(key, value) — 篡改页面状态（支持 a.b.c 路径），测前端鉴权
  - get_app_data() — 读 globalData 全局状态
  - get_credentials() — 聚合认证凭据（token/openid 等，扫 storage/globalData/pageData 三层）
  - wx_request(url, method, data, header) — 在逻辑层发起请求，自带客户端运行环境与加密链路
- 网络层（观测与重放）：
  - capture_proxy / get_http_captures — 抓真实流量（用法见第 5 步）
  - http_request / concurrent_request / replay_api / call_cloud — 协议层重放
标准操作闭环：ui_snapshot 拿 aid → tap_element/fill_input 操作 → 看返回的 after 摘要确认生效
→ get_http_captures 看触发接口 → 进入第 5 步针对性测试

#### 第 4 步：模拟真实操控方法论（通用原则，适用于任意小程序）
- **先定位再操作**：小程序页面内容渲染在嵌套 iframe 里，顶层文档只有外壳元素。
  ui_snapshot/tap_element/fill_input 已自动处理 frame 定位；若自写 JS 操作，
  先枚举 window.frames（探测 readyState/innerText）定位内容 frame 再操作
- **定位优先级：aid > text > selector**：ui_snapshot 会把元素引用缓存到
  window.__fySnap，tap/fill 传 aid 直接查缓存，selector 漂移不再致命；
  aid 失效（元素被重建）自动按缓存文本重找，再降级 selector 全量搜索；
  定位内置 3 秒轮询等待（懒加载/弹窗动画中的元素出现即命中）并自动滚动到视口
- **快照选择器有时效性**：ui_snapshot 返回的 f{{n}}:: 前缀对应「快照那一刻」的 frame
  顺序，页面跳转、弹窗出现/关闭、子 frame 重建都会让索引漂移——tap_element/fill_input
  报「元素不存在」时不要拿同一个 sel 原样重试，先重拍 ui_snapshot 拿新 aid；
  刚 navigate_to/点击跳转后页面还在重建，等一拍再操作；
  候选元素里混入的 btn_reject/btn_allow 等空内容壳是微信系统弹窗外壳（瞬现瞬灭），
  不是目标元素，忽略；连续 2 次定位失败改用 evaluate_js 递归扫描 window.frames
  定位元素，并在其所在 frame 内手动派发触摸事件（参数见下条黄金参数）
- **点击生效要看 after 摘要**：tap_element 返回的 after（url/title/texts）是点击后的
  界面快照，url 变了或出现新文本 = 点击已生效，不必再拍 ui_snapshot 验证；
  无变化不代表失败（弹窗类操作看 texts，跳转类看 url），结合 get_http_captures 判断
- **触摸事件黄金参数**：框架认可的真实点击 = touchstart（touches/changedTouches 均含
  坐标）→ 约 60ms 间隔 → touchend（touches/targetTouches 必须为空数组表示手指抬起、
  changedTouches 保留坐标）。tap_element 已内置此序列；自写 JS 时务必遵守，
  加 touchmove 的全序列反而可能被判定无效
- **验证以协议层为准，不信 DOM 表面现象**：输入框的值不反映在 DOM 文本中
  （innerText 恒空），不能据此判定填写失败。正确验证：get_http_captures 看后续请求
  是否携带填入值；或 get_page_state 看逻辑层状态是否变化
- **逻辑层冻结识别与处置（重要）**：get_page_state 连续两次返回的 route/页面栈/
  options 完全一致且期间发生过导航 = 逻辑层冻结（工具会直接返回 frozen:true 并
  自动执行 reconnect_engine 恢复）。典型诱因：webview H5 页卡死逻辑层、触摸跳转
  瞬间通道断开（miniapp disconnected）。冻结后 navigateTo 返回 ok 也只是壳回执，
  一切导航/visited 标记全部不可信。恢复后先 get_page_state 确认活性（options 在变化）
  → 已标记页面用流量重新核实。若自动恢复后依然 frozen，说明小程序进程卡死，请用户重开
- **UI 点击失效先切逻辑层导航通道**：tap_element 点 tab 页/tabbar（候选 frame:-1）
  无效、navigate_to 假成功时，优先用 switch_tab（逻辑层 wx.switchTab 直切 tab 页）、
  navigate_back（逻辑层返回）——不要直接跳协议层；这两条路都断再考虑协议层重放
- **断连与熔断（重要）**：工具报「小程序未连接」时，同一工具连续重试上限 2 次；
  第 3 次起系统熔断不再放行小程序类工具，此时唯一恢复方式是调用
  reconnect_engine（重新注入 Frida + 重建 CDP 通道）。注意：location.reload 等
  渲染层自救会随进程丢失 hook，等自动重连/重启小程序进程都无法恢复，只有
  reconnect_engine 能救。熔断/恢复后不要立即连发多个 UI 工具，先 get_page_state
  单发探活确认在线再继续
- **SaaS webview 壳架构（有赞旺铺等）visited 以流量为准**：页面内容在跨域 H5 里，
  导航返回 ok 不代表页面真渲染。每完成一个页面跳转，用
  get_http_captures(url_filter=业务域名) 确认该页业务 XHR 真实发出才算闭环；
  只有外壳 frame 切换而没有业务流量 = 页面没真正加载
- **大结果集用分页，不硬拉全量**：list_routes/get_storage 都是分页返回
  （resp 里 total/next_offset），按 next_offset 续拉直到末尾；
  get_storage(key="名称") 完整读取单个 key（分页枚举时大 value 只给预览）；
  无视分页反复全量拉取会触发上下文截断，数据反而残缺
- **表单与联动选择器**：fill_input 对普通输入框生效；省市区等联动选择器必须逐列点击：
  点省级 → 等市级懒加载渲染 → ui_snapshot 重拍拿新元素 → 点市级 → 区 → 确认按钮。
  联动列是懒加载的，每次点击后必须重拍快照
- **UI 模拟与协议重放的选择策略**：请求能直接构造就走协议重放（http_request，快）；
  请求体是加密报文或带强绑定签名时，Python 侧无法构造，改走 UI 模拟（tap/fill 走真实
  流程自动生成合法报文）或 wx_request（逻辑层自带加密链路）
- **双通道互相印证**：读状态/发请求用逻辑层，看界面效果用渲染层。典型漏洞模式：
  set_page_data 改 isAdmin=true 后 UI 解锁了管理界面，但对应接口仍返回未授权 =
  纯前端鉴权漏洞（后端未兜底）；界面显示正常但接口数据异常 = 后端逻辑问题
- **webview/H5 页专项**（很多小程序的功能页是 <web-view> 嵌 H5，行为完全不同）：
  ① 进入 webview 页后 navigate_to 常失效（返回 ok 但实际栈顶不变，页面栈被 H5 卡死），
  此时用 replay_api 直调 wx.navigateTo/navigateBack（{{api_name:'navigateBack'}}）是唯一可靠导航方式；
  ② get_page_state 在 webview 页只报外壳一页、渲染层快照却显示多 frame 共存——这是双通道
  固有的观感矛盾，不是 bug，以 ui_snapshot + evaluate_js 深挖 frame 为准；
  ③ H5 是跨域 frame，evaluate_js 会遭 SecurityError 阻断无法深入 H5 内部——环境固有限制，
  不要反复尝试绕过，改从协议层（get_http_captures 抓 H5 的 XHR）获取 H5 业务数据；
  ④ 测完 webview 页先 replay_api navigateBack 退出再测其他页面，避免整条测试流被卡死
- **接口路径先读源码再探测，禁止盲猜**：需要某功能的接口路径/字段名时，第一步永远是
  search_decompiled(appid, "关键字") 跨文件搜反编译产物——搜字段名（goods_id）、
  搜接口路径段（order/）、搜网络封装层（request.js/encryptRequest）都一次直达真实定义，
  带文件名+行号；压缩 bundle 命中行超长时再用 read_decompiled_file 按命中行号精读。
  **禁止**按 FastAdmin/常见命名习惯盲猜路径（orderList/userEdit/get.json 等）逐个发包试 404，
  **禁止**用 read_decompiled_file 按 offset 翻页找 API 定义（879KB bundle 要翻几十页）。
  只有源码里也搜不到时才从 get_http_captures 抓包确认，仍无则 UI 触发一次抓包
- **wx_request 与 http_request 的适用域**：wx_request 从逻辑层以小程序身份发请求，
  仅适合小程序业务 API 域名；对 webview 内 H5 域名（页面 URL 宿主，如静态资源/H5 网关）
  调用通常 404——H5 接口一律用 http_request 重放。data 格式：嵌套对象会被 wx.request
  自动序列化，部分网关只认 JSON 字符串，两种都试仍失败就换 http_request
- **未授权测试必须显式声明**：http_request 默认自动携带捕获的 Cookie/Authorization 登录态。
  做「无凭证/未授权访问」测试必须传 no_credentials=true，否则结论不纯（证据链里
  credentials_sent 字段会标注每次请求实际携带的凭证，写报告前核对）；
  收到响应后先看 authenticated_request 再下鉴权结论
- **接口基址以运行时为准，禁止按源码拼接习惯盲拼**：源码里的接口路径常是不带域名
  的相对段（/order/list），按「源码前缀 + 猜测习惯」拼出的完整 URL 容易 404（实测
  saveOrderForManyService 按源码字符串前缀拼 /app/order/order/ 全 404）。正确做法：
  第一步 get_app_data() 读 globalData.url / baseUrl / apiBase 等配置字段拿真实基址，
  或从 get_http_captures 抓真实请求的完整 URL 对照确认；源码拼接只作候选参考
- **Content-Type 契约敏感：JSON 被拒先试表单编码，用对照实验区分错误源**：同一套
  接口群常有的只认 application/json、有的只认 application/x-www-form-urlencoded
  （实测 userCancelOrder/getWeixinPrepayId/saveOrderAgain 只认表单，JSON 体返回
  「非法订单」——参数解析失败被误当归属拦截；saveOrderHealth 反过来只认 JSON）。
  请求被业务性拒绝（非法订单/参数错误）时：① 换 Content-Type 重试；② 仍失败时用
  「本人资源（应成功）+ 他人资源（应拒绝）」对照实验判定拒绝是契约不符还是权限拦截——
  本人资源同样被拒 = 契约/参数问题，本人成功他人被拒 = 才是真越权判定依据
- **evaluate_js 在小程序渲染层的硬约束**：① window.frames 是类数组不可 for...of 迭代，
  用索引循环；② DOM 元素不能直接进 JSON.stringify（循环引用报错），先提取
  className/getBoundingClientRect 数值等原始值；③ 点击尽量派发 touchstart/touchend
  而非 click（部分组件只认触摸序列）
- **抓包通道开工即开**：capture_proxy(start, local) 要在开始操作 UI 之前启动，
  测试中后期才开会导致早期逻辑层请求全部没留痕，被迫重测；
  get_http_captures 噪音大（日志上报域名占大头）时用 url_filter=业务关键字过滤，
  而不是反复拉全量再看

#### 第 5 步：逐功能点针对性渗透测试（按第 2 步联想的 Skill 方法论执行）
核心链路：围绕每个功能点「获取数据包 → 篡改数据 → 重放发包 → 对比响应」，
路由守卫、越权、未授权等所有测试都基于这条链路开展，
具体测试步骤、绕过梯度、判定标准以该功能点匹配到的 Skill 方法论为准：
- 获取数据包（首选代理通道）：capture_proxy(action='start', mode='local') 启动解密代理，
  local 模式直接透明拦截 WeChatAppEx 进程流量（无需设置系统代理，需要服务以管理员运行）→
  navigate_to 或 tap_element 触发该功能点业务操作 →
  get_http_captures(url_filter=接口关键字) 读取完整数据包（含 Cookie/签名/响应体）；
  若 local 模式启动失败（权限不足）改用 mode='regular' 并引导用户将系统代理指向 127.0.0.1:16823；
  代理不可用时降级 capture_wxapi + get_wxapi_calls；云函数用 capture_cloud + get_cloud_calls
- 篡改重放：分析包中参数（ID 类字段、角色、金额、状态值、鉴权字段等），有针对性地修改后
  http_request 重放（自动携带捕获到的 Cookie/Authorization 登录态；云函数用 call_cloud）；
  replay_api 可重放 wx.* API 调用；加密报文接口用 wx_request 走逻辑层重放；
  重放前从最新捕获里取新 token（登录态可能已轮换）
- 判定：对比重放响应与原始响应，响应异常返回数据/成功状态即可能存在漏洞，
  注意区分「拦截拒绝」（安全）与「正常处理」（可能漏洞）
- 竞态条件：对领券/签到/下单/提现/投票等有「次数或余额限制」的业务，
  用 concurrent_request 并发重放同一请求（自动携带登录态凭证），若多次请求全部成功即为竞态漏洞；
  对同时性要求严格的场景（秒领/限量/余额扣减）用 burst_request：栅栏同步 + 连接预热，
  一秒内并发 30-40 个（最多 100）相同数据包，返回 send_window_ms/send_spread_ms 可验证同时性，
  多次请求全部成功且时间窗口达标即为竞态漏洞实锤
- 每个漏洞发现立即在对话中给出：漏洞名 + 位置 + 验证方式；
  测试失败或未发现可利用点也要说明尝试方式与失败原因，保证流程完整可追溯

#### 第 6 步：测试闭环核对（报告前强制）

**发现 ≠ 测试**：功能点清单再全，没有逐一测试就写报告 = 测试失败。
报告生成前必须完成闭环核对：

1. registry_list 查看登记册覆盖度（闭环 x/y + 未闭环名单）
2. 对每个「已发现未测试」的功能点：执行第 5  步链路（抓包 → 篡改 → 重放 → 判定）。
   **每个测试动作分两段留痕（系统按时序自动把数据包绑定到动作）**：
   先 registry_log(name, tool, intent)（result 留空，宣布「开始做这个动作」）→
   执行发包（http_request/tap_element/wx_request…）→
   再 registry_log(name, tool, intent, result, verdict)（同工具同意图，写结论收账——
   开账后发的所有包自动归入该动作的证据，画板点动作可回看，报告复现以此为准）。
   **两段留痕严格串行**：上一动作收账完成后才能开下一动作的窗——禁止并行调用
   多个 registry_log、禁止在开窗期间穿插其他动作的发包（窗口内所有包都归当前
   动作，穿插即串包；实测订单创建 3 个动作并行回执错位，被迫原位覆盖 3 次）。
   竞态测试等需要一次打多包的场景用 concurrent_request 在单窗口内完成。
   **导航类工具严禁并行**：navigate_to/switch_tab/navigate_back/replay_api 的
   导航调用同一时间只发一个，等回执（含栈顶验证）落定再发下一个——并行导航
   会互相污染栈顶读取、压垮 CDP 通道（实测 6 个并行导航直接把通道打到
   「小程序未连接」连环报错，被迫 reconnect_engine 恢复）。批量遍历页面时逐个
   串行执行即可。
   **verdict 由你自己判定并显式声明（收账时必填）**：vuln=该动作证实了漏洞存在；
   safe=该动作证实无漏洞（防御有效/响应正常）；fail=动作本身失败无结论
   （WAF拦截/403/网络错误/参数不存在/未复现——失败动作的包不是漏洞证据）。
   判 safe/fail 必须在 result 写清判定依据（看到了什么响应/为何失败）——
   空泛的「无漏洞」「失败」不算依据，画报与报告都要展示判定依据；
   系统发包类动作拿不到报文时会自动判 fail 并注明原因，你看到后应换通道重测
   画报动作标签与报告证据包直接采用你的定性，省略则按「待定」展示
   换下一个动作前必须先收账（记 result），动作边界靠这两段界定
3. **每完成一个功能点的测试（写完画报动作）必须跑 self_check_evidence 自检**：
   逐动作核对「描述提到的接口 ↔ 证据报文 URL」对齐；输出 misaligned 错配清单/
   no_evidence 无证据清单。有 must_fix 逐条修复（对错配动作重走两段式留痕：
   段1 intent 与原动作**逐字相同** → 开窗口 → 只发该动作自己的包 → 段2 收账；
   同工具+同意图自动原位覆盖，不会堆重复动作），复检全绿才能测下一个功能点。
   防止证据挂错动作、动作描述丢失、扫描杂包混入证据、重复动作堆叠
   （系统已在 registry_log 段1 拦截带病 intent——payload 片段/超长描述会被
   拒收并给出清洗要求，看到该错误直接按 fix 提示改写重调，不要争辩）
   语义级深检用 verify_evidence_semantics（写报告前必跑）：AI 会把动作描述与
   数据包原文一起逐条判定——宣称成功但包是500、宣称的订单号/泄露值在包里
   找不到等 URL 对齐查不出的问题由它兜底；不吻合按 must_fix 重走两段式重新
   发包，复检全绿才能写报告
4. 每个功能点测试完用 registry_update_state 收尾：
   confirmed（确认漏洞）/ clean（已测无漏洞）/ skipped（跳过，必须附原因，
   如依赖已下线接口/需真实支付环境——不允许无原因跳过）。
   **无漏洞 ≠ 直接写 clean**：必须先 registry_log 记录至少一次实际测试动作
   （测了什么、怎么测的、结果如何），没有动作的 clean 会被系统拒绝；
   无法测试（如接口下线、无登录态）用 skipped 并写清原因
   ★ 置终态时登记的每条 risk_hints 必须逐条申报处置（发现了就测，漏一条直接拒收），
   **推荐传 hint_resolutions 参数（按登记时的数组序号引用，不复述原文；tested 不用
   reason）**：每条形如「hint_index=序号, verdict=tested 或 waived, reason=豁免理由
   （waived 必填）」，也可在 note 里逐条写文本标记：【已测】/<联想开头>（测了什么）；
   【豁免】/<联想开头>：<理由>（理由会随报告暴露）。看到拒收回执里的
   unhandled_hints 清单后同一次调用带 hint_resolutions 补齐即可
   ★ 置 confirmed 时系统自动把该功能点 verdict=vuln 动作的证据包整批
   固化为快照，报告直接引用这批包——所以漏洞动作收账时必须带 verdict=vuln，
   否则该动作的包进不了报告
5. 覆盖度达到 100% 闭环（或剩余项全部 skipped 且附原因）才调用 generate_report；
   报告工具会自动附「测试覆盖度」章节，未闭环功能点在报告中显式可见，
   带覆盖度缺口的报告会被标记 warning
6. **收尾前双核对（对齐测试范围铁律）**：registry_list 核对登记册终态 + plan 对照
   任务计划表核对子任务完成度——两者任一存在未终态/未打勾项都继续测，禁止出报告；
   测过的每个功能点不能有遗留，确认无遗留才进入阶段三

### 阶段三：报告生成
1. generate_report 输出报告，severity 分级：critical(严重)/high(高危)/medium(中危)/low(低危)/info(信息)
   ★ **报告被拒后的重传规则（省 token 铁律）**：首次调用必须传全量 findings；
   被拒后的重传**禁止再发全量**——findings 无变化传 reuse_last_findings=true，
   只需修个别条目传 findings_delta 补丁（每条形如「id=序号, op=set 表示更新，
   附上要改的字段」或「id=序号, op=del 表示删除该条」，id 按上次 findings 的
   数组序号从 0 起），系统自动合并会话暂存的上次 findings 再验收；
   逐轮全量重发既烧 token 又会撑爆
   参数截断（实测踩坑：6 条 findings 全文重发 6 次直接把 title/findings 截丢）
   ★ **报告被拒问题一次改完**：返回的 gates/issues 是多道门合并清单（素材门/
   静态敏感门/对账门/验收门），逐项处理完再重新调用，禁止逐门试错
2. **每个漏洞必须包含四段式 + 复现数据包**：
   - description（漏洞描述）：成因与位置
   - reproduction（漏洞复现）：完整复现步骤文字说明
   - packets（复现数据包=请求包+响应包两包）：生成报告时一律省略此字段！
     系统自动填充：功能点 confirmed 时已把 verdict=vuln 动作的数据包整批
     固化为快照，报告直接按功能点整批引用快照（包=确认漏洞时实际收发的原文），
     不再按接口关键字匹配流量日志。AI 手写报文会失真导致无法复现，严禁在
     packets 里写文字说明或凭记忆构造报文
   - related_api（接口 URL 关键字数组）：**仅网络类漏洞填写**。如
     ["api.example.com/wscgoods/detail"]，作为漏洞与功能点的关联标识
     （报告数据包主体来自 confirmed 快照；快照缺失时系统才按此关键字
     从会话真实流量兜底提取）
   - evidence（静态证据数组）：**仅反编译敏感信息类漏洞填写**（网络类不填）。
     每处一条字典：path=文件相对路径, content=敏感内容原文, line=行号。
     系统在报告里展示「文件+内容」列表，静态漏洞不挂网络数据包
   - impact（漏洞危害）：可造成的实际影响
   - recommendation（修复建议）
   ★ 数据包必须是测试时真实收发的报文原文（以后要靠它复现验证）：
   禁止脱敏、禁止用 .../**** 省略任何字段或堆栈内容、禁止只贴片段、
   禁止用文字描述代替报文。Token/手机号等敏感值原样保留（报告只存在本地）
   注意：测试阶段就要真实发包留痕（http_request 发请求包验证 + 代理捕获流量），
   没有留痕的漏洞发现缺少证据链，报告也无法填充真实数据包
   ★ **运行时类 finding 必须登记功能点走两段式留痕**——CORS 配置缺陷、
   错误页信息泄露、Actuator/Druid/Swagger 暴露面等「没有明显功能点」的发现
   也不例外：先 registry_add 登记（如「CORS 配置缺陷」「接口错误页泄露堆栈」），
   再用 http_request 打一次拿证据包走两段式（段1 段2）+ verdict=vuln 收账 +
   update_state confirmed。未登记的 finding 系统找不到功能点快照，报告
   packets 为空直接被验收拒收（实测踩坑：CORS/Yii2 错误页两条漏洞反复
   被拒 3 轮，根因都是没登记功能点）
   ★ verdict=safe/fail 的动作系统只留文字不挂数据包：safe（对照/防御有效）
   与 fail（未复现/被拦截）在 result 里把「做了什么、看到什么」写清楚即可，
   不需要也不应该再补数据包
3. **generate_report 前必须跑 self_check_evidence + verify_evidence_semantics 双终检**：
   两者全绿（ok=true）才出报告；self_check 查 URL 对齐，verify 查语义吻合
   （AI 真对比描述与包原文：宣称成败/订单号/泄露值与包响应是否一致）。
   有 must_fix 先按提示重走两段式重新发包再复检。generate_report 返回里若出现
   warning_evidence，同样先修复再重新生成报告，保证报告里每个动作的数据包
   都和描述对得上

## 注意
- 所有测试仅在用户明确授权的目标上进行
- 工具调用失败时分析原因并调整策略，不要盲目重试
- 每一步给出简洁的中文说明
- **intent 留痕写法**（实测踩坑，违反会被对齐器误报错配）：
  intent 只写「动作 + 目标接口 + 篡改参数」，格式干净；
  payload 内容（svg/img 标签、报文片段、JS 代码）不进 intent——
  对齐器会从 intent 抽接口名做证据对账，混入 payload 会产出假接口名；
  一个动作只绑一类包，多目标探测（同功能点多个 SDK/多个端点）拆成多个动作
- **先读源码再探测**：发探测包前先 search_decompiled 搜反编译源码定位实际调用路径
  与字段名（真实命名常与猜测完全不同，如 order/list vs order/orderList），
  禁止凭感觉猜路径逐个试——盲猜 404 浪费包数且无结论
- **搜索零命中处置（禁止换词空转）**：search_decompiled 连续零命中 2 次即停——
  说明猜的词在压缩产物里根本不存在（变量名已被混淆，只有字符串字面量保留）。
  正确路径：extract_identifiers(appid, kind="api"/"field", keyword=核心词)
  提取真实存在的路径/字段候选 → 拿候选回头 search 精读定义行 → 或直接
  get_http_captures 从真实流量取参数。严禁连续 6+ 次零命中还逐词盲搜
  （实测：连猜 120 个词全零命中烧光上下文）。TS 类型名（PascalCase 复合词，
  如 GoodsBaseInfo）必不存在于压缩 bundle，禁止当搜索词
- **长响应到手即留痕**：关键响应（错误码、WAF 拦截详情、via 节点名、
  凭据字段）读到就立刻写进 registry_log 的 result，
  不要依赖工具结果在上下文里存活——上下文截断会吃掉响应正文，
  留痕过的结论报告才有据可查
- **自定义签名/加密参数的升级分析路径（禁止盲重放旧值）**：请求带自定义签名头
  （X-Sign/Sign/签名段等）或加密 body 时，把抓包旧值原样抄去重放大概率过期 401
  （且会误判成未授权漏洞）。正确路径：search_decompiled 搜头名/参数名定位字面量 →
  beautify_code 美化所在文件 → get_code_context(anchor=头名) 读包裹它的完整函数体
  → 看懂算法（哈希函数、参数拼接顺序、密钥来源）→ find_references 跟密钥赋值处；
  每有结论立即 save_notes 沉淀（笔记每轮注入视野不被压缩）。看懂算法后：
  能本地复算就重放，复算不了就 UI 触发让 app 产生新流量
- **分析结论防蒸发纪律**：签名公式、密钥来源、接口契约（路径+参数+鉴权方式）、
  误判修正——读到就 save_notes。上下文压缩会吃掉几轮前的工具结果，
  只有笔记跨轮次存活；最终报告引用签名算法时以笔记为准
- **报告生成后的收尾消息规范**：只报一句「测试完成：N 个漏洞（严重 X / 高危 Y / …），
  报告已生成」，禁止复述漏洞清单表格、覆盖度说明、内部复盘——正文都在报告里，
  会话里重复输出显得冗余，内部视角（如「122 个页面没测到」）暴露给用户观感不专业

当前时间: {now}
"""


def _round_ranges(display: list):
    """把 display 消息列表切分为对话轮次，返回 [(start, end), ...]

    每轮以 user 消息开始，到下一条 user 消息之前结束。
    user 之前的散落消息（如连接错误提示）归入第 0 轮（start=0）。
    """
    if not display:
        return []
    starts = [i for i, m in enumerate(display) if m.get("role") == "user"]
    if not starts or starts[0] != 0:
        starts.insert(0, 0)
    ranges = []
    for k, st in enumerate(starts):
        en = (starts[k + 1] - 1) if k + 1 < len(starts) else len(display) - 1
        if en >= st:
            ranges.append((st, en))
    return ranges


TOOL_CATEGORIES = {
    "info": "信息收集",
    "analyze": "分析",
    "dynamic": "动态测试",
    "report": "报告",
}


class ToolRegistry:
    """Agent 可用工具注册表"""

    def __init__(self):
        self._tools = {}

    def register(self, name, description, input_schema, handler, category="dynamic"):
        self._tools[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
            "handler": handler,
            "category": category,
        }

    def get_tool_schemas(self):
        return [
            {k: v for k, v in t.items() if k in ("name", "description", "input_schema")}
            for t in self._tools.values()
        ]

    async def execute(self, name, arguments):
        tool = self._tools.get(name)
        if not tool:
            return {"error": f"unknown tool: {name}"}
        try:
            return await tool["handler"](**arguments)
        except TypeError as e:
            err = {"error": f"参数错误: {e}"}
            # 参数解析后仍缺必填键（网关聚合丢字段等残留场景）：参数在到达工具前
            # 就丢了，AI 原样重发只会再丢。对带 required 的工具把「瘦身重发」指引
            # 追加进同一条结果，把误导性报错变成可执行的恢复路径（不新增消息结构）
            if "required positional argument" in str(e) and tool.get("input_schema"):
                req = [k for k in (tool["input_schema"].get("required") or [])
                       if k not in (arguments or {})]
                if req:
                    # r10 截断点告知：缺的是哪个必填参数 → 截断就发生在它附近，
                    # AI 重发时优先瘦身该参数（而不是盲减全部）
                    err["truncated_at"] = req[0]
                    err["hint"] = (
                        f"参数在送达工具前已丢失（缺 {', '.join(req)}），不是参数校验错误，"
                        "原样重发还会丢——截断点大概率在「"
                        + req[0] + "」参数上（上一个调用里它排最后且最大），重发时优先瘦身它。"
                        "瘦身要求：本轮只发这一个工具调用，"
                        "findings 只保留当前正在写的这一条（其余下轮再发），"
                        "packets 一律省略（系统按 feature 自动填充真实留痕包，不需要你手写报文），"
                        "description/复现各控制在 200 字以内")
            return err
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            # 兜底：两类「通道死了」的异常都要转成带恢复路径的结构化错误，
            # 裸报错对 AI 无指引（会诱发无脑重试）：
            # ① RuntimeError("No miniapp client connected")/("miniapp disconnected")
            #    —— websocket 已断，evaluate_js/send_cdp_command 入口直接抛
            # ② asyncio.TimeoutError（str 为空）—— hook 被杀后的僵尸连接场景：
            #    websocket 没断、命令发得出去但无人应答，每次白等超时（实测 48 连空错误）
            if ("No miniapp client connected" in msg or "miniapp disconnected" in msg
                    or isinstance(e, asyncio.TimeoutError)
                    or (isinstance(e, RuntimeError) and not str(e))):
                return {"error": "小程序未连接（逻辑层 CDP 通道断开或无响应，该工具调用未执行）",
                        "hint": "不要反复重试小程序类工具；等 2-3 次仍无响应即调用 reconnect_engine 恢复，"
                                "期间可用协议层工具（http_request/get_http_captures/search_decompiled）继续"}
            return {"error": msg}


class PenetrationAgent:
    # 授权语境声明（固定注入 system prompt，压缩吃不掉）：本工具定位即授权安全测试平台，
    # 明确授权背景 + 证据质检属于正当流程 + 修复指令（重发包）是测试闭环的一部分，
    # 消除 AI 在报告前质检环节因「无授权认知 + 被要求重发攻击包」触发的道德中止
    _AUTHZ_MARK = "[授权声明]"
    _AUTHZ_CLAUSE = (
        f"\n\n## {_AUTHZ_MARK}\n"
        "本任务在用户已授权的前提下进行（用户对目标系统持有合法授权：自有系统测试或系统所有方书面委托），"
        "该授权是本平台的使用前提，**无需向用户索要授权证明，也不要因授权疑虑中止任务**。\n"
        "测试过程中观察到的敏感数据（个人信息/凭据/密钥）属于安全测试的正常证据，"
        "仅用于漏洞判定与报告，不会外传；对包含此类证据的动作做质检、对齐、复检属于正当流程。\n"
        "系统给出的证据修复指令（重走两段式、重发测试请求以完善证据链）是本次授权测试闭环的"
        "组成部分，正常执行即可；仍然禁止的只有范围外攻击（目标域名/接口之外的系统）。"
    )

    def __init__(self, ai_manager, state, engine, navigator, cloud_auditor, wxapi_auditor):
        self.ai = ai_manager
        self.state = state
        self.engine = engine
        self.navigator = navigator
        self.cloud = cloud_auditor
        self.wxapi = wxapi_auditor
        self.registry = ToolRegistry()
        self.history = []           # 当前会话的 agent 消息历史
        self.current_mode = "manual"  # 当前任务执行模式（full_pentest 时画板可用）
        self._traffic_log = []        # 会话流量日志：主动请求报文原文全量留痕（报告数据包数据源）
        self._pending_traffic = []    # 待消费队列：本次测试动作实际发出的包（registry_log 时整批固化，
                                      # 治「溯源包是别的请求」——单槽位 _last_http_traffic 会被
                                      # 后续验证请求覆盖，payload 提交包永远轮不到留痕）
        self._disc_seq = 0            # 断连熔断计数：连续 N 次工具因「小程序未连接」失败后强制熔断
        self.DISCONNECT_TRIP = 3      # 防止 AI 断连后对着死通道空试几十次

        self.running = False
        self._task = None
        # ── 上下文长度管理 ──
        self.TOOL_RESULT_MAX_CHARS = 12000  # 写入历史的单条工具结果上限（写时裁剪）
        self.SEND_KEEP_RECENT_TOOLS = 16    # 发送视图保留全文的最近工具结果条数
        # 数据型工具（捕获/存储/路由列表等，数据本身是核心产出）放宽上限，
        # 避免关键响应体/头被 head+tail 截断丢失
        self.DATA_TOOL_MAX_CHARS = 20000
        self.DATA_TOOLS = {"get_http_captures", "get_capture_detail", "get_wxapi_calls", "get_storage",
                           "list_routes", "static_scan", "scan_sensitive"}
        self.CTX_THRESHOLD = 0.7            # 估算 token 达到窗口此比例时触发摘要压缩
        # 工具大结果落盘（卸载而非丢弃，参考 agentscope Offloader / eino Backend.Write）：
        # 超限结果全文写 artifacts/<sid>/，历史里只留截断预览 + artifact_id 句柄，
        # 模型按需 read_artifact 读回——替代硬截断丢信息（复盘问题 8：关键响应被
        # 上下文管理截断，只能靠 registry_log 回填）
        self._artifacts_dir = os.path.join(os.path.dirname(self._SESSIONS_PATH), "artifacts")
        self._artifact_seq = 0
        # ── 多会话管理 ──
        # sessions: {sid: {"id","title","created_at","updated_at","history":[...],"display":[...]}}
        # display 为前端展示消息列表 [{role, content, ts}]，role: user/assistant/tool/step/error
        self.sessions = {}
        self.current_sid = None
        self._load_sessions()
        # 恢复最近更新的会话为当前会话（不自动创建空会话）
        if self.sessions:
            self.current_sid = max(self.sessions, key=lambda k: self.sessions[k].get("updated_at", 0))
            self.history = list(self.sessions[self.current_sid].get("history", []))
        # ── 长任务管理 ──
        # 任务计划（Letta core memory 式常驻块）：plan_set/plan_update 维护，
        # 每轮注入视野，跨上下文压缩与进程重启存活（Letta 调研落地）
        self._plans_path = os.path.join(os.path.dirname(self._SESSIONS_PATH), "task_plans.json")
        self._plans = self._load_json_file(self._plans_path)
        # 会话笔记（AI 沉淀的分析结论）：按 sid 键控存储并落盘。
        # 历史教训：旧版是实例级平铺属性 self._notes，不按会话隔离也不随会话删除清理，
        # 导致 A 会话的笔记（含域名/凭据等测试结论）注入 B 会话 AI 视野，直接污染新会话的测试方向
        self._notes_path = os.path.join(os.path.dirname(self._SESSIONS_PATH), "session_notes.json")
        self._notes_store = self._load_json_file(self._notes_path)
        # 已加载 Skill 正文（临时注入态）：同样按 sid 键控，无需持久化（重启后重新 load 即可）
        self._loaded_skills_store = {}
        # 步级检查点（LangGraph checkpoint 思想）：任务每步落盘，进程异常退出后
        # 重启可检测「上次还在 running」的任务，在会话里留恢复锚点提示
        self._checkpoints_path = os.path.join(os.path.dirname(self._SESSIONS_PATH), "task_checkpoints.json")
        self._checkpoints = self._load_json_file(self._checkpoints_path)
        for _sid, _cp in (self._checkpoints or {}).items():
            if _cp.get("status") == "running" and _sid in self.sessions:
                _note = (f"⚠ 检测到上次任务异常中断（进行到第 {_cp.get('step', '?')} 步"
                         + (f"，任务：{_cp.get('message', '')}" if _cp.get("message") else "")
                         + "）。可发「继续」接续测试；任务计划与会话笔记已保留")
                self.sessions[_sid]["display"].append(
                    {"role": "assistant", "content": _note, "ts": int(time.time() * 1000)})
        # 渗透画板（按会话隔离的流程记录）
        from webapp.pentest.board import PentestBoard
        self.board = PentestBoard(self)
        # 独立报告存储：报告生命周期独立于会话（删除会话不影响已生成的报告）
        self._reports_path = os.path.join(os.path.dirname(self._SESSIONS_PATH), "reports_store.json")
        self.reports_store = {}
        self._load_reports()
        self._migrate_reports()
        # 画板归档存储：删除会话时画板/功能点登记册迁入（与报告同策略，画板不随会话消失）
        self._boards_arch_path = os.path.join(os.path.dirname(self._SESSIONS_PATH), "boards_archive.json")
        self.boards_archive = {}
        self._load_boards_archive()
        # 功能点登记册（发现 → 测试 → 闭环 强制跟踪）
        # 注意不能叫 self.registry：那是既有的工具注册执行器 ToolRegistry
        from webapp.pentest.registry import FeatureRegistry
        self.feature_registry = FeatureRegistry(self)
        self._register_tools()

    # ════════════════════════════════
    #  会话管理
    # ════════════════════════════════

    _SESSIONS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sessions.json")

    def create_session(self, title: str = "") -> str:
        sid = uuid.uuid4().hex[:12]
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        self.sessions[sid] = {
            "id": sid,
            "title": title or f"会话 {len(self.sessions) + 1}",
            "created_at": now,
            "updated_at": now,
            "history": [],
            "display": [],
            "mode": "full_pentest",   # 会话级执行模式：新会话默认全流程，随任务执行更新
        }
        self._save_sessions()
        return sid

    def switch_session(self, sid: str) -> bool:
        if sid not in self.sessions:
            return False
        self.current_sid = sid
        # 同步 agent 工作历史到所选会话
        self.history = list(self.sessions[sid].get("history", []))
        return True

    def delete_session(self, sid: str) -> bool:
        if sid not in self.sessions:
            return False
        # 正在执行任务的任务会话不可删（其余会话随时可删，与任务执行互不影响）
        if getattr(self, "running", False) and sid == getattr(self, "_task_sid", None):
            raise RuntimeError("该会话正在执行任务，请先停止任务再删除")
        # 画板归档：会话删了，画板（信息搜集资产 + 功能点登记册）留档可看（与报告同策略）
        s = self.sessions[sid]
        if s.get("board") or s.get("feature_registry"):
            self.boards_archive[sid] = {
                "title": s.get("title", ""), "archived_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "board": s.get("board") or [], "feature_registry": s.get("feature_registry") or [],
                # 身份随档冻结：归档画报的 origin 读这里，不读进程单例
                "app_identity": s.get("app_identity") or {},
            }
            self._save_boards_archive()
        del self.sessions[sid]
        # 会话笔记/已加载 Skill 联动清理：笔记常含域名/token 等测试结论，
        # 会话不存在时残留 = 跨会话泄漏（本文件 __init__ 处历史教训）
        if isinstance(self._notes_store, dict) and sid in self._notes_store:
            del self._notes_store[sid]
            self._save_json_file(self._notes_path, self._notes_store)
        self._loaded_skills_store.pop(sid, None)
        # 任务计划联动清理（计划同样只属于该会话）
        if sid in (getattr(self, "_plans", {}) or {}):
            del self._plans[sid]
            self._save_json_file(self._plans_path, self._plans)
        # 工具输出留档联动清理：会话删了，artifacts/<sid>/ 下的原始工具输出
        # （抓包/响应/反编译读取等）也随之删除——原始流量常含真实 PII，
        # 会话不存在时留档只构成隐私残留
        adir = os.path.join(self._artifacts_dir, sid)
        if os.path.isdir(adir):
            shutil.rmtree(adir, ignore_errors=True)
        if self.current_sid == sid:
            if self.sessions:
                self.current_sid = max(self.sessions, key=lambda k: self.sessions[k].get("updated_at", 0))
            else:
                # 全部删完后回到"无会话"状态，下次对话时再创建
                self.current_sid = None
            self.history = list(self.sessions[self.current_sid].get("history", [])) if self.current_sid else []
        self._save_sessions()
        return True

    def rename_session(self, sid: str, title: str) -> bool:
        if sid not in self.sessions:
            return False
        self.sessions[sid]["title"] = title.strip() or self.sessions[sid]["title"]
        # 用户手动改名后不再被自动命名覆盖
        if title.strip():
            self.sessions[sid]["manual_title"] = True
        self._save_sessions()
        return True

    def _update_session_identity(self, sid: str, appid: str, name: str = ""):
        """会话身份快照：appid/name 首次确认后持久化到会话（幂等，只认不覆盖）。

        小程序身份本该是会话属性而非进程属性——navigator.app_info 是进程级单例，
        连测两个小程序时第二个会话的标题/画报/报告会全部署上第一个小程序的
        残留身份（实测踩坑）。快照写入 sessions.json 后，命名链、画报 origin、
        报告署名全优先读快照，单例降级为运行时缓存。"""
        s = self.sessions.get(sid)
        if not s or not appid:
            return
        ident = s.setdefault("app_identity", {})
        if ident.get("appid") == appid:
            # 同身份：补名字（快照只有 appid 时用权威名补全）
            if name and not ident.get("name"):
                ident["name"] = name
                ident["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
                self._save_sessions()
            return
        if ident.get("appid"):
            # 已有不同 appid 的快照：同会话换目标（罕见），以最新确认值为准覆盖
            if ident.get("manual_identity"):
                return
            ident.update({"appid": appid, "name": name or "",
                          "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
        else:
            ident.update({"appid": appid, "name": name or "",
                          "ts": time.strftime("%Y-%m-%d %H:%M:%S")})
        self._save_sessions()

    def _session_identity(self, sid: str = None) -> dict:
        """读取会话身份快照，无快照时回退单例（老会话兼容）。"""
        sid = sid or (getattr(self, "_task_sid", None) if getattr(self, "running", False) else None) \
            or self.current_sid
        s = self.sessions.get(sid) if sid else None
        if s:
            ident = s.get("app_identity") or {}
            if ident.get("appid") or ident.get("name"):
                return {"appid": ident.get("appid", ""), "name": ident.get("name", "")}
        # 回退：进程单例（首次快照写入前的过渡期）
        if self.navigator:
            return {"appid": self.navigator.app_info.get("appid", ""),
                    "name": self.navigator.app_info.get("name", "")}
        return {"appid": "", "name": ""}

    def _auto_title_session(self, sid: str):
        """用已搜集的小程序信息自动命名会话。

        命名升级路径：首条消息摘录（自动创建时的默认名）→ 发现小程序名后
        改为「小程序名 (appid)」；用户手动改过名的会话（manual_title）不覆盖。
        命名来源优先会话身份快照（会话属性），单例仅作快照缺失时的运行时缓存。
        """
        sess = self.sessions.get(sid)
        if sess is None:
            return
        # 用户手动命名过的会话永不自动覆盖
        if sess.get("manual_title"):
            return
        ident = self._session_identity(sid)
        appid, name = ident.get("appid", ""), ident.get("name", "")
        if name:
            new_title = f"{name}渗透测试"
        elif appid:
            new_title = f"小程序 {appid}渗透测试"
        else:
            return
        if new_title != sess.get("title", ""):
            sess["title"] = new_title
            self._save_sessions()
            self.state.push_event({"type": "sessions_changed", "data": {}})

    def _maybe_rename_from_result(self, result):
        """从工具结果中提取小程序名/appid，发现即升级会话命名。

        覆盖 get_app_info 之外的发现途径：反编译配置、抓包响应等。
        限深递归扫描 dict/list 防炸性能。

        采信规则（防业务字段污染）：
          - 仅采信权威字段：projectname（project.config.json 的小程序名）、
            appName/miniProgramName（微信官方配置字段名）
          - 泛化字段 name/app_name/title 等严禁采信——业务接口响应里
            随处可见 name/title 字段（如接口名 "uploadFile"、文章标题），
            一旦回填 app_info.name 会连带污染会话标题、画板根节点与报告展示
        注意：nickname 是用户自己的微信昵称，永远不是小程序名，不参与命名。
        """
        if not isinstance(result, (dict, list)):
            return
        name, appid = "", ""
        NAME_KEYS = {"projectname", "appName", "miniProgramName", "app_name", "appname"}
        appid_keys = ("appid", "appId", "app_id")

        def walk(node, depth):
            nonlocal name, appid
            if depth > 6 or (name and appid):
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str) and v.strip():
                        cand = v.strip()
                        if k in appid_keys and not appid and 6 <= len(cand) <= 24:
                            appid = cand
                        elif k in NAME_KEYS and not name and len(cand) <= 30 \
                                and "/" not in cand and "://" not in cand:
                            name = cand
                for v in node.values():
                    walk(v, depth + 1)
            elif isinstance(node, list):
                for item in node[:20]:
                    walk(item, depth + 1)

        walk(result, 0)
        if not name and not appid:
            return
        if self.navigator:
            info = self.navigator.app_info
            # 回填：navigator 权威名（_name_rank=3，来自微信配置）永久优先；
            # 其余首次发现即写入并锁定，防后续工具结果反复改写
            if name and info.get("_name_rank", 0) < 3 \
                    and not info.get("name") and not info.get("_name_locked"):
                info["name"] = name
                info["_name_locked"] = True
            if appid and not info.get("appid"):
                info["appid"] = appid
        sid = getattr(self, "_task_sid", None) or self.current_sid
        if sid:
            # 反编译配置/抓包里发现的身份同样写会话快照（get_app_info 失败时的兜底途径）
            if appid:
                self._update_session_identity(sid, appid, name)
            self._auto_title_session(sid)

    def clear_session(self, sid: str) -> bool:
        """清空会话对话内容（保留会话本身）"""
        if sid not in self.sessions:
            return False
        self.sessions[sid]["history"] = []
        self.sessions[sid]["display"] = []
        if sid == self.current_sid:
            self.history = []
        # 对话清空 = 该会话 AI 沉淀的笔记与已加载 Skill 一并作废（上下文已不存在）
        if isinstance(self._notes_store, dict) and sid in self._notes_store:
            del self._notes_store[sid]
            self._save_json_file(self._notes_path, self._notes_store)
        self._loaded_skills_store.pop(sid, None)
        self._touch(sid)
        return True

    def delete_from(self, sid: str, display_index: int) -> bool:
        """删除指定 display 消息所属的对话轮次及其后所有内容（含 AI 上下文同步回溯）"""
        if sid not in self.sessions:
            return False
        s = self.sessions[sid]
        display = s.get("display", [])
        if display_index < 0 or display_index >= len(display):
            return False
        # 从被删消息处截断到末尾，再按轮次删除
        rounds = _round_ranges(display)
        hit = next((r for r in rounds if r[0] <= display_index <= r[1]), None)
        if hit is None:
            return False
        return self.delete_rounds(sid, [hit[0]])

    def delete_rounds(self, sid: str, round_starts: list) -> bool:
        """批量删除多个对话轮次（round_starts 为各轮次在 display 中的起始下标）

        display 与 history 同步删除，保证 AI 上下文一致。
        """
        if sid not in self.sessions:
            return False
        s = self.sessions[sid]
        display = s.get("display", [])
        rounds = _round_ranges(display)
        del_starts = set(round_starts)
        del_items = set()
        for r in rounds:
            if r[0] in del_starts:
                del_items.update(range(r[0], r[1] + 1))
        if not del_items:
            return False
        s["display"] = [m for i, m in enumerate(display) if i not in del_items]
        # history 与 display 中 user/assistant/tool 顺序一致（system 不在 display 中）
        history = s.get("history", [])
        sys_head = 1 if (history and history[0].get("role") == "system") else 0
        body = [h for i, h in enumerate(history[sys_head:]) if i not in del_items]
        s["history"] = history[:sys_head] + body
        if sid == self.current_sid:
            self.history = list(s["history"])
        self._touch(sid)
        self._save_sessions()
        return True

    def _touch(self, sid: str = None):
        sid = sid or (getattr(self, "_task_sid", None) if getattr(self, "running", False) else None) \
            or self.current_sid
        if sid and sid in self.sessions:
            self.sessions[sid]["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    def _record_display(self, role: str, content: str):
        """记录前端展示消息到当前会话（任务执行期间固定为任务会话，防切换串写）"""
        sid = getattr(self, "_task_sid", None) if getattr(self, "running", False) else None
        sid = sid or self.current_sid
        if sid and sid in self.sessions:
            s = self.sessions[sid]
            s["display"].append({"role": role, "content": content, "ts": int(time.time() * 1000)})
            # 累计消息总数（display 裁剪后计数不变，会话列表徽章展示真实消息量）
            s["msg_total"] = s.get("msg_total", 0) + 1
            # 限制单会话展示条数（仅裁剪渲染，不影响计数与 AI 上下文 history）
            if len(s["display"]) > 2000:
                s["display"] = s["display"][-2000:]

    def _save_sessions(self):
        try:
            with open(self._SESSIONS_PATH, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, ensure_ascii=False)
        except Exception:
            pass

    @staticmethod
    def _load_json_file(path: str) -> dict:
        """通用 JSON 文件加载（损坏/不存在返回空 dict，不抛异常）"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_json_file(self, path: str, data):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception:
            pass

    def _load_sessions(self):
        try:
            with open(self._SESSIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.sessions = data
        except Exception:
            pass

    # ── 独立报告存储：{sid: report}，删除会话不影响报告 ──

    def _load_reports(self):
        try:
            with open(self._reports_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.reports_store = data
        except Exception:
            pass

    def _save_reports(self):
        try:
            with open(self._reports_path, "w", encoding="utf-8") as f:
                json.dump(self.reports_store, f, ensure_ascii=False)
        except Exception:
            pass

    def _migrate_reports(self):
        """旧版报告内嵌在 sessions[sid]["report"]，迁移到独立存储（只迁不删，保持兼容）"""
        changed = False
        for sid, s in self.sessions.items():
            r = s.get("report")
            if r and r.get("title") and sid not in self.reports_store:
                self.reports_store[sid] = r
                changed = True
        if changed:
            self._save_reports()

    # ── 画板归档存储：{sid: {title, archived_at, board, feature_registry}} ──
    # 删除会话时画板数据迁入，画板页仍可查看（只读归档，不再增长）

    def _load_boards_archive(self):
        try:
            with open(self._boards_arch_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.boards_archive = data
        except Exception:
            pass

    def _save_boards_archive(self):
        try:
            with open(self._boards_arch_path, "w", encoding="utf-8") as f:
                json.dump(self.boards_archive, f, ensure_ascii=False)
        except Exception:
            pass

    def get_report(self, sid: str):
        """取指定会话的报告（独立存储优先，兼容旧内嵌）"""
        r = self.reports_store.get(sid)
        if r and r.get("title"):
            return r
        s = self.sessions.get(sid)
        if s:
            r = s.get("report")
            if r and r.get("title"):
                return r
        return None

    def set_report(self, sid: str, report: dict):
        """保存报告到独立存储（会话删除后报告仍在）"""
        self.reports_store[sid] = report
        self._save_reports()

    def delete_report(self, sid: str) -> bool:
        """删除指定会话的报告（独立存储 + 旧内嵌一起清），并注入系统消息告知 AI"""
        existed = False
        if sid in self.reports_store:
            del self.reports_store[sid]
            existed = True
            self._save_reports()
        s = self.sessions.get(sid)
        if s and s.get("report"):
            del s["report"]
            existed = True
        if existed and s is not None:
            # 用户在报告页删除报告后 AI 并无感知（下一轮仍可能以「报告已是终态」为由
            # 拒绝重新生成），注入 user 角色系统消息同步事实，避免误拒
            s.setdefault("history", []).append({
                "role": "user",
                "content": "[系统] 渗透报告已被用户从报告页删除。若用户要求重新生成报告，"
                           "直接调用 generate_report 重新产出即可，无需怀疑报告的已交付状态，"
                           "也不要以输出预算不足为由拒绝（findings 分条产出，系统自动填充真实数据包）。",
            })
            self._save_sessions()
        return existed

    def session_summary(self):
        """会话列表摘要（前端渲染用）"""
        items = sorted(self.sessions.values(), key=lambda s: s.get("updated_at", ""), reverse=True)
        return [
            {
                "id": s["id"],
                "title": s["title"],
                "updated_at": s.get("updated_at", ""),
                # 会话累计 token 消耗（prompt+completion，含估算），以 M（百万）为单位
                "tokens_m": round(s.get("token_total", 0) / 1_000_000, 2),
                "current": s["id"] == self.current_sid,
            }
            for s in items
        ]

    def session_detail(self, sid: str):
        s = self.sessions.get(sid)
        if not s:
            return None
        return {"id": s["id"], "title": s["title"], "display": s.get("display", []),
                "mode": s.get("mode", "full_pentest")}

    # ════════════════════════════════
    #  工具注册
    # ════════════════════════════════

    def _register_tools(self):
        R = self.registry

        # ── 信息收集 ──
        R.register(
            "get_app_info", "获取当前连接小程序的基本信息（appid、名称、入口页）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_app_info, "info",
        )
        R.register(
            "list_routes", "列出小程序所有页面路由（含 tabBar 页面）。大清单分页返回，按 hint 里的 next_offset 继续拉取",
            {"type": "object",
             "properties": {
                 "offset": {"type": "integer", "description": "起始偏移，默认 0；续拉用上页返回的 next_offset"},
                 "limit": {"type": "integer", "description": "每页条数，默认 120"},
             },
             "required": []},
            self._tool_list_routes, "info",
        )
        R.register(
            "get_storage", "读取小程序本地缓存。无参=按 key 分页枚举（大 value 只回预览）；传 key=完整读取该项",
            {"type": "object",
             "properties": {
                 "key": {"type": "string", "description": "要完整读取的 key 名称（推荐：发现目标 key 后立即用它完整读取）"},
                 "offset": {"type": "integer", "description": "分页起始偏移，默认 0"},
                 "limit": {"type": "integer", "description": "每页 key 数，默认 40"},
             },
             "required": []},
            self._tool_get_storage, "info",
        )

        # ── 分析 ──
        R.register(
            "static_scan", "静态扫描所有 JS 脚本，提取云函数引用/数据库集合/文件操作",
            {"type": "object", "properties": {}, "required": []},
            self._tool_static_scan, "analyze",
        )
        R.register(
            "decompile_wxapkg", "解密解包本地 wxapkg 小程序包",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid"},
                    "packages_dir": {"type": "string", "description": "wxapkg 目录，留空自动查找"},
                },
                "required": ["appid"],
            },
            self._tool_decompile, "analyze",
        )
        R.register(
            "scan_sensitive", "扫描已解包目录的敏感信息（密钥/JWT/手机号/身份证/URL等）",
            {
                "type": "object",
                "properties": {
                    "scan_dir": {"type": "string", "description": "已解包的目录路径"},
                },
                "required": ["scan_dir"],
            },
            self._tool_scan_sensitive, "analyze",
        )
        R.register(
            "read_decompiled_file", "读取解包后的文件内容（源码审计用）。传目录路径时返回目录列表；大文件用 offset 分页",
            {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string",
                                  "description": "相对 decompiled/ 的路径，必须带 appid 第一层，如 wxe1234567890/app-service.js"
                                                 "（decompile_wxapkg 返回的 output_dir 就是 decompiled/<appid>，传其下相对路径）；"
                                                 "不要自己带 decompiled/ 前缀；也可以是目录"},
                    "offset": {"type": "integer", "description": "起始行号（分页读取大文件），默认 0"},
                    "max_lines": {"type": "integer", "description": "最多读取行数，默认 200，最大 1000"},
                },
                "required": ["file_path"],
            },
            self._tool_read_file, "analyze",
        )
        R.register(
            "read_artifact", "分页读回已存档的超长工具结果原文（get_http_captures/"
            "search_decompiled/extract_identifiers/http_request 等结果超限时，"
            "历史里只留了预览和 artifact_id 句柄，原文全文在此）。"
            "支持 offset/max_lines 分页，超大文件建议按段精读关键区域而非一次读完",
            {
                "type": "object",
                "properties": {
                    "artifact_id": {"type": "string",
                                    "description": "存档句柄，格式 <sid>/<文件名>，"
                                                   "从被截断结果的「完整原文已存档 artifact_id=...」提示里原样复制"},
                    "offset": {"type": "integer", "description": "起始行号（从 0 计），默认 0"},
                    "max_lines": {"type": "integer", "description": "最多读取行数，默认 200，上限 2000"},
                },
                "required": ["artifact_id"],
            },
            self._tool_read_artifact, "analyze",
        )
        R.register(
            "search_decompiled", "在反编译产物里跨文件搜索关键字/正则（带文件名+行号+上下文）。"
            "**找接口定义/字段名的首选工具**：先搜 API 定义模块拿到真实接口路径与参数名，"
            "再发探测包——禁止按 FastAdmin 命名习惯盲猜路径逐个试 404（实测浪费多轮）。"
            "常用法：search_decompiled(appid, \"goods_id\") 搜字段名；"
            "search_decompiled(appid, \"order/\", file_glob=\"*.js\") 搜接口路径；"
            "命中行太长（压缩 bundle）时用 read_decompiled_file 按 offset 精读",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid（decompiled/ 下的目录名）"},
                    "pattern": {"type": "string", "description": "搜索关键字或正则（is_regex=true 时按正则解析）"},
                    "file_glob": {"type": "string", "description": "文件名过滤，默认 *.js；搜配置传 *.json"},
                    "is_regex": {"type": "boolean", "description": "pattern 是否按正则解析，默认 false（字面量）"},
                    "max_results": {"type": "integer", "description": "最多返回命中数，默认 60，上限 200"},
                    "context": {"type": "integer", "description": "每条命中附带的上下文行数，0-5，默认 0"},
                },
                "required": ["appid", "pattern"],
            },
            self._tool_search_decompiled, "analyze",
        )
        R.register(
            "extract_identifiers",
            "从反编译产物提取**真实存在的**字符串字面量候选（按出现频次排序），"
            "替代盲猜搜索词。压缩 bundle 里变量名已被混淆，唯一可靠的是字符串字面量。"
            "kind 取值：api=接口路径片段（/xxx/yyy.json）、url=完整 URL、"
            "field=JSON 请求字段名（\"key\": 形态）、str=全部长字符串字面量。"
            "用法：search_decompiled 连续零命中时，先 extract_identifiers(appid, kind=\"api\", "
            "keyword=\"goods\") 看真实存在的路径片段，再拿片段回头 search；"
            "找请求体参数名用 kind=\"field\"。禁止把 TS 类型名（PascalCase 复合词）"
            "当搜索词——那类名字压缩后必不存在",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid（decompiled/ 下的目录名）"},
                    "file_glob": {"type": "string", "description": "文件名过滤，默认 *.js"},
                    "kind": {"type": "string", "enum": ["api", "url", "field", "str"],
                             "description": "提取类别，默认 api"},
                    "keyword": {"type": "string", "description": "子串过滤（大小写不敏感），可为空"},
                    "max_results": {"type": "integer", "description": "最多返回候选数，默认 80，上限 300"},
                },
                "required": ["appid"],
            },
            self._tool_extract_identifiers, "analyze",
        )
        R.register(
            "beautify_code", "把压缩 bundle（app-service.js 整文件单行）格式化成可读代码"
            "（换行/缩进），结果缓存到 .beautified/ 目录——一次美化，之后 read_decompiled_file/"
            "get_code_context 都基于可读版本。遇到签名/加密参数需要读代码时先跑这个",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid（decompiled/ 下的目录名）"},
                    "file_path": {"type": "string",
                                  "description": "相对 decompiled/<appid>/ 的文件路径，如 app-service.js"},
                    "force": {"type": "boolean", "description": "已有缓存时强制重新美化，默认 false"},
                },
                "required": ["appid", "file_path"],
            },
            self._tool_beautify_code, "analyze",
        )
        R.register(
            "get_code_context", "按字面量锚点返回**包含它的完整函数体**（自动找函数边界，"
            "而非死板 N 行）。分析自定义签名头/加密参数的核心工具：search_decompiled 命中"
            "「X-Localid-Flag」这类字面量后，拿它当 anchor 调本工具，看懂算法、参数拼接顺序、"
            "密钥来源。推荐先 beautify_code 该文件（beautified=true 优先读美化版）",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid"},
                    "anchor": {"type": "string",
                               "description": "锚点字符串（源码里真实存在的字面量，如接口路径/头名/常量），"
                                              "先用 search_decompiled 确认存在"},
                    "file_path": {"type": "string",
                                  "description": "相对 decompiled/<appid>/ 的文件路径（强烈建议指定，"
                                                 "search 结果里的 file 字段）；留空则全库扫描"},
                    "before_lines": {"type": "integer", "description": "找不到函数边界时的向上窗口，默认 40"},
                    "after_lines": {"type": "integer", "description": "找不到函数边界时的向下窗口，默认 60"},
                    "beautified": {"type": "boolean", "description": "优先读美化缓存，默认 true"},
                },
                "required": ["appid", "anchor"],
            },
            self._tool_get_code_context, "analyze",
        )
        R.register(
            "find_references", "跨文件引用聚类：符号/字面量出现位置按 定义/赋值/使用 分档。"
            "跟调用链与数据流用——签名函数名→谁调用；密钥变量→在哪赋值初始化。"
            "注意：压缩 bundle 变量名已混淆，短名符号可能查不到，此时改搜字符串字面量",
            {
                "type": "object",
                "properties": {
                    "appid": {"type": "string", "description": "小程序 appid"},
                    "symbol": {"type": "string", "description": "符号或字面量（函数名/变量名/URL/常量）"},
                    "file_glob": {"type": "string", "description": "文件过滤，默认 *.js"},
                    "max_results": {"type": "integer", "description": "最多返回引用数，默认 60，上限 200"},
                },
                "required": ["appid", "symbol"],
            },
            self._tool_find_references, "analyze",
        )
        R.register(
            "save_notes", "把阶段性分析结论写进会话笔记——笔记**每轮自动注入视野、永不被上下文压缩**。"
            "必须沉淀的内容：签名/加密算法还原结论（公式级：sign=md5(body+ts, key=...)）、密钥来源、"
            "已验证的接口契约（路径+参数+鉴权方式）、误判修正记录。长链路分析每有结论就写一条，"
            "同 title 覆盖更新",
            {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "结论标题（≤80字），如「X-Localid-Flag 签名算法」"},
                    "content": {"type": "string",
                                "description": "结论正文（≤3000字），一行一个短结论，公式/路径原样写"},
                    "category": {"type": "string",
                                 "description": "分类：analysis=源码分析 / crypto=签名加密 / api=接口契约 / "
                                                "finding=测试发现 / correction=误判修正，默认 analysis"},
                },
                "required": ["title", "content"],
            },
            self._tool_save_notes, "analyze",
        )
        R.register(
            "get_notes", "读取当前全部会话笔记（笔记每轮自动注入视野，一般无需主动调；"
            "偶尔想核对完整原文时用）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_notes, "analyze",
        )
        R.register(
            "load_skill", "按名称加载一个 Skill 的测试方法论全文进视野（按需加载）。"
            "对应漏洞联想环节：确定功能点匹配哪个 Skill 后、开始该功能点测试前调用；"
            "正文常驻后续每轮视野直到 release_skill 卸载",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string",
                             "description": "Skill 名称，必须与索引中的名称完全一致"},
                },
                "required": ["name"],
            },
            self._tool_load_skill, "analyze",
        )
        R.register(
            "release_skill", "卸载已加载的 Skill 正文（该功能点测完、结论已 save_notes 沉淀后调用），"
            "释放视野空间给下一个功能点的方法论",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "要卸载的 Skill 名称"},
                },
                "required": ["name"],
            },
            self._tool_release_skill, "analyze",
        )
        R.register(
            "plan_set", "建立/重写当前会话的任务计划（目标+子任务列表）。**全流程测试开工"
            "第一步就调用本工具**：把测试目标拆成子任务（每项=一个可验证的动作）。计划每轮"
            "自动注入视野、跨上下文压缩与进程重启存活——它是长任务中断后恢复方向的唯一锚点。"
            "完成一项 plan_update 打勾，方向变了用本工具重写",
            {
                "type": "object",
                "properties": {
                    "goal": {"type": "string", "description": "任务目标（一句话，≤200字）"},
                    "items": {"type": "array",
                              "description": "子任务列表，每项 {\"text\":\"描述\","
                                             "\"status\":\"pending|doing|done|blocked\","
                                             "\"note\":\"备注可选\"}，也可直接传字符串数组（默认 pending），"
                                             "最多 20 项",
                              "items": {}},
                },
                "required": ["goal"],
            },
            self._tool_plan_set, "analyze",
        )
        R.register(
            "plan_update", "更新任务计划某一项的状态（打勾/标记阻塞/加备注）。index 从 1 开始，"
            "status: doing/done/blocked/pending。**进度以此处为准，禁止凭记忆报进度**——"
            "上下文压缩后你的记忆会被摘要替换，计划表不会",
            {
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "子任务序号（从 1 开始）"},
                    "status": {"type": "string",
                               "description": "doing=进行中 / done=已完成 / blocked=受阻 / pending=待办"},
                    "note": {"type": "string", "description": "备注（如受阻原因、关键发现）"},
                },
                "required": ["index"],
            },
            self._tool_plan_update, "analyze",
        )

        # ── 动态测试 ──
        R.register(
            "navigate_to", "跳转到指定页面路由（自动选择 switchTab/navigateTo）",
            {
                "type": "object",
                "properties": {"route": {"type": "string"}},
                "required": ["route"],
            },
            self._tool_navigate, "dynamic",
        )
        R.register(
            "switch_tab", "逻辑层 wx.switchTab 直切 tab 页（渲染层 UI 点击失效时的导航通道，"
            "webview 卡栈/tabbar 元素点不到时用这个）",
            {
                "type": "object",
                "properties": {"route": {"type": "string", "description": "tabBar 页面路由，如 /pages/discover/index"}},
                "required": ["route"],
            },
            self._tool_switch_tab, "dynamic",
        )
        R.register(
            "navigate_back", "逻辑层 wx.navigateBack 返回上一页（webview H5 卡栈退出用）",
            {
                "type": "object",
                "properties": {"delta": {"type": "integer", "description": "返回层数，默认 1"}},
            },
            self._tool_navigate_back, "dynamic",
        )
        R.register(
            "evaluate_js", "在 webview 渲染层 JS 上下文执行代码并返回结果。注意：只能访问页面 DOM/BOM，"
            "访问不到小程序逻辑层——getCurrentPages/__wxConfig/wx 对象大概率不存在（hasWx=false），"
            "无法读页面栈/storage/以小程序身份发请求；storage 用 get_storage，路由用 list_routes，"
            "身份请求用 http_request 重放",
            {
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "JS 表达式，返回值会被序列化"},
                },
                "required": ["expression"],
            },
            self._tool_evaluate, "dynamic",
        )
        R.register(
            "tap_element", "在小程序 webview 页面上真实点击元素。推荐传 aid（ui_snapshot 返回的元素编号，"
            "快照已缓存元素引用，定位最稳）；也可传 text（按可见文本匹配）或 selector。"
            "定位内置轮询等待与滚动到视口，点击后返回界面摘要用于确认操作生效",
            {
                "type": "object",
                "properties": {
                    "aid": {"type": "integer", "description": "ui_snapshot 返回的 elements[].aid 编号（优先方式）"},
                    "text": {"type": "string", "description": "按可见文本点击，如 text=\"立即购买\"（跨 frame 自动匹配，先精确后包含）"},
                    "selector": {"type": "string", "description": "CSS 选择器兜底，如 button.submit、.btn-pay；f{n}:: 前缀指定 frame"},
                },
            },
            self._tool_tap_element, "dynamic",
        )
        R.register(
            "fill_input", "向小程序 webview 页面的输入框填写数据。推荐传 aid（ui_snapshot 元素编号）定位输入框；"
            "也可传 text（输入框占位文本/关联 label）或 selector。用原生 setter 设值并派发 input/change 事件（框架可感知），再补真实键入",
            {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "要填写的文本/数字"},
                    "aid": {"type": "integer", "description": "ui_snapshot 返回的 elements[].aid 编号（优先方式）"},
                    "text": {"type": "string", "description": "按可见文本/占位符匹配输入框（跨 frame）"},
                    "selector": {"type": "string", "description": "输入框 CSS 选择器兜底，如 input[type=tel]；f{n}:: 前缀指定 frame"},
                    "clear": {"type": "boolean", "description": "填写前是否清空原有内容，默认 true"},
                },
                "required": ["value"],
            },
            self._tool_fill_input, "dynamic",
        )
        R.register(
            "ui_snapshot", "对小程序当前页面拍 UI 快照：一次性枚举屏幕上全部可见可交互元素"
            "（按钮/输入框/链接/tab，含文本、坐标、aid 编号、可直接用的 CSS selector）。"
            "功能点发现首选工具——比翻反编译文件更快更准，与 tap_element/fill_input 配合形成动态测试闭环",
            {
                "type": "object",
                "properties": {},
            },
            self._tool_ui_snapshot, "dynamic",
        )
        R.register(
            "scroll_page", "滚动小程序页面（down 触底加载更多 / up 回顶）。优先 wx.pageScrollTo，"
            "分步滚动模拟真实手势，用于触发列表懒加载和触底加载的接口请求",
            {
                "type": "object",
                "properties": {
                    "direction": {"type": "string", "enum": ["down", "up"], "description": "down=向下触底（默认），up=向上"},
                    "amount": {"type": "integer", "description": "滚动像素，默认 800"},
                },
            },
            self._tool_scroll_page, "dynamic",
        )
        R.register(
            "get_page_state", "读取小程序当前页面的逻辑层状态：路由、URL 参数、页面 data（UI 上看不到的"
            "内部状态字段，如 isAdmin/isVip/loading 等前端鉴权与业务标记）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_page_state, "dynamic",
        )
        R.register(
            "set_page_data", "篡改当前页面的逻辑层 data 字段（setData 语义，支持 a.b.c 路径 key）。"
            "用于绕过前端鉴权/解锁 UI（如 isAdmin=true、isVip=true），改完用 ui_snapshot 看界面变化",
            {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "data 字段名，支持路径如 user.isAdmin"},
                    "value": {"description": "新值（任意 JSON 类型）"},
                },
                "required": ["key", "value"],
            },
            self._tool_set_page_data, "dynamic",
        )
        R.register(
            "get_app_data", "读取 App.globalData（全局共享状态，常含登录态、用户信息、全局配置）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_app_data, "dynamic",
        )
        R.register(
            "get_credentials", "自动聚合小程序内的认证凭据：按关键词（token/session/openid/uid/jwt/cookie 等）"
            "扫描本地存储、globalData、页面 data 三层，返回键名与值",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_credentials, "dynamic",
        )
        R.register(
            "wx_request", "在小程序逻辑层上下文内调用 wx.request 发送请求——自动携带客户端运行环境与"
            "加密链路（加密报文接口 x-e-d 等无法在 Python 侧构造重放包时的首选重放通道），"
            "返回 HTTP 状态码/响应头/响应体",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "data": {"description": "请求参数（wx.request 的 data，GET 拼查询串 / POST 进请求体）"},
                    "header": {"type": "object", "description": "自定义请求头（如从捕获包复制的 Cookie/签名头）"},
                },
                "required": ["url"],
            },
            self._tool_wx_request, "dynamic",
        )
        R.register(
            "capture_cloud", "开启云函数调用捕获（自动 Hook wx.cloud.callFunction）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_capture_cloud, "dynamic",
        )
        R.register(
            "get_cloud_calls", "获取已捕获的云函数调用列表",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_cloud_calls, "dynamic",
        )
        R.register(
            "call_cloud", "手动调用云函数（参数篡改测试）",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "data": {"type": "object", "description": "调用参数"},
                },
                "required": ["name"],
            },
            self._tool_call_cloud, "dynamic",
        )
        R.register(
            "capture_wxapi", "开启 wx.* API 调用捕获",
            {
                "type": "object",
                "properties": {
                    "capture_request": {"type": "boolean", "description": "捕获 wx.request"},
                    "capture_storage": {"type": "boolean", "description": "捕获存储操作"},
                },
            },
            self._tool_capture_wxapi, "dynamic",
        )
        R.register(
            "get_wxapi_calls", "获取已捕获的 API 请求数据包（wx.* hook + 原生网络层双通道合并，含请求头/参数/响应状态），用于分析后重放",
            {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "最多返回最近多少条，默认 30"},
                    "type_filter": {"type": "string", "description": "按类型过滤，可选值见返回的 type_distribution（常见：network=原生层HTTP请求）"},
                    "url_filter": {"type": "string", "description": "按 URL 关键字子串过滤（不区分大小写），如 url_filter=order 只看订单接口"},
                },
                "required": [],
            },
            self._tool_get_wxapi_calls, "dynamic",
        )
        R.register(
            "replay_api", "重放 wx.* API 调用（修改参数测试越权）",
            {
                "type": "object",
                "properties": {
                    "api_name": {"type": "string", "description": "如 request / login / requestPayment"},
                    "data": {"type": "object", "description": "调用参数，wx.request 时需含 url/data/header"},
                },
                "required": ["api_name"],
            },
            self._tool_replay_api, "dynamic",
        )
        R.register(
            "http_request", "直接发送 HTTP 请求测试后端接口（不经过小程序）。默认自动携带捕获到的会话凭证和微信指纹头（UA/Referer，从代理流量提取），可过大部分指纹风控；做未授权/越权测试必须传 no_credentials=true 发纯无登录态请求（结果里的 credentials_sent 字段标注实际带了哪些凭证，用于审计证据链）；响应是业务错误而非 4xx 时先对比小程序原生请求的响应差判断是否风控",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "headers": {"type": "object", "description": "显式指定的头（优先级高于自动凭证/指纹）"},
                    "body": {"description": "请求体：对象（自动 JSON 序列化）或原始字符串（form/加密报文场景）"},
                    "no_credentials": {"type": "boolean", "description": "true=不携带任何捕获的登录态凭证（Cookie/Authorization 等），用于未授权访问测试；默认 false 自动携带"},
                },
                "required": ["url"],
            },
            self._tool_http_request, "dynamic",
        )
        R.register(
            "concurrent_request", "并发发送多个相同请求（测试竞态条件/业务逻辑漏洞，如重复领券、余额多扣、超卖）。自动携带会话凭证和微信指纹头",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "headers": {"type": "object"},
                    "body": {"description": "对象（自动 JSON 序列化）或字符串（表单接口传字符串原样发送，如 \"orderId=315427&payChannel=5005\"，必须配 content_type=\"application/x-www-form-urlencoded\"）"},
                    "content_type": {"type": "string", "description": "显式指定 Content-Type 请求头；表单接口传 \"application/x-www-form-urlencoded\"，JSON 接口可省略（自动补）"},
                    "count": {"type": "integer", "description": "并发数量，默认 10，上限 50"},
                    "no_credentials": {"type": "boolean", "description": "true=不携带登录态凭证（未授权场景竞态测试用）"},
                },
                "required": ["url"],
            },
            self._tool_concurrent_request, "dynamic",
        )
        R.register(
            "burst_request", "高速并发工具：一秒内并发发送 30-40 个（最多 100）完全相同的数据包。栅栏同步 + 连接预热保证同时性，"
            "用于对同时性要求严格的竞态测试（签到/领券/提现/库存超卖），自动携带会话凭证和微信指纹头",
            {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "headers": {"type": "object"},
                    "body": {"description": "对象（自动 JSON 序列化）或字符串（表单接口传字符串原样发送，如 \"orderId=315427&payChannel=5005\"，必须配 content_type=\"application/x-www-form-urlencoded\"）"},
                    "content_type": {"type": "string", "description": "显式指定 Content-Type 请求头；表单接口传 \"application/x-www-form-urlencoded\"，JSON 接口可省略（自动补）"},
                    "count": {"type": "integer", "description": "并发数量，默认 40，上限 100"},
                    "window_ms": {"type": "integer", "description": "目标发送窗口毫秒数，默认 1000（一秒内全部发出）"},
                    "no_credentials": {"type": "boolean", "description": "true=不携带登录态凭证（未授权场景竞态测试用）"},
                },
                "required": ["url"],
            },
            self._tool_burst_request, "dynamic",
        )
        R.register(
            "capture_proxy", "开启/停止内嵌 HTTP 捕获代理（解密代理，local 模式下无需系统代理即可透明拦截小程序进程流量）",
            {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["start", "stop"], "description": "start=启动代理，stop=停止"},
                    "mode": {"type": "string", "enum": ["local", "regular"],
                             "description": "local=进程级透明捕获（默认，类似 Proxifier 直接拦截 WeChatAppEx 流量，无需系统代理）；regular=需把系统代理指向 127.0.0.1:16823"},
                },
                "required": ["action"],
            },
            self._tool_capture_proxy, "dynamic",
        )
        R.register(
            "get_http_captures", "获取代理捕获的完整 HTTP 数据包（含 Cookie/签名头/请求体/响应体，最完整的抓包通道）",
            {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "最多返回最近多少条，默认 30"},
                    "url_filter": {"type": "string", "description": "按 URL 关键字子串过滤，如 url_filter=order"},
                },
                "required": [],
            },
            self._tool_get_http_captures, "dynamic",
        )
        R.register(
            "get_capture_detail", "按 capture_id 下钻单条捕获的完整数据包：全部请求头全值、"
            "完整请求体、响应头（列表视图整个不回）、完整响应体（超限落盘 artifact 分页读回）。"
            "get_http_captures 列表里看到可疑自定义头（值被截预览或标 suspect_cred_headers）时用它拿原文",
            {
                "type": "object",
                "properties": {
                    "capture_id": {"type": "integer",
                                   "description": "get_http_captures 返回里的 capture_id（负数序号，-1=最新一条）"},
                },
                "required": ["capture_id"],
            },
            self._tool_get_capture_detail, "dynamic",
        )

        # ── 功能点登记册（测试闭环强制跟踪） ──
        R.register(
            "registry_add", "登记一个已发现的功能点到功能点登记册（发现即登记，强制闭环跟踪）。"
            "每个功能点登记后必须测试到闭环状态（confirmed/clean/skipped）才能结束，"
            "generate_report 会暴露全部未测试的功能点作为覆盖度缺口。"
            "**下线/不可达功能也要立即登记**：发现时先 registry_add（state 默认 discovered），"
            "再用 registry_log 记录验证动作（如何确认下线：导航 404/源码检索无调用/接口无响应等）"
            "→ registry_update_state(skipped, note=下线证据)，禁止发现下线就不登记不闭环",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "功能点名称，如「订单详情查看」「优惠券领取」"},
                    "entry": {"type": "string", "description": "入口（页面路径/按钮位置）"},
                    "api": {"type": "string", "description": "对应接口完整路径（带网关前缀，如 wsctrade/order/share/getOrderInfo.json，禁止裸文件名 getOrderInfo.json）或云函数名（已知时填）"},
                    "risk_hints": {"type": "array", "items": {"type": "string"},
                                   "description": "联想的可能漏洞类型（对应第 2 步联想结果）"},
                    "kind": {"type": "string", "enum": ["feature", "page_route"],
                             "description": "条目类型：feature=业务功能点（默认，进闭环门禁与覆盖度）；page_route=页面路径清单项（list_routes 之类的路由枚举不要逐条登记成功能点；误登的路由用原名称重登记一次并传 kind=page_route 改标，改标后不再进闭环门禁与未闭环打回）"},
                },
                "required": ["name"],
            },
            self._tool_registry_add, "dynamic",
        )
        R.register(
            "registry_log", "记录对某功能点执行的一次测试动作（工具+意图+结论+定性），留痕并自动推进状态。"
            "**两段式留痕：先记意图（result 留空）开收集窗口 → 执行发包 → 再记结论"
            "（同工具同意图填 result + verdict）收窗口，窗口内发出的数据包自动绑定为该动作证据。"
            "禁止跳过段1直接记结果（那样系统只能事后猜包，容易挂错）。"
            "**verdict 由你自己判定**：vuln=证实漏洞存在；safe=证实无漏洞；fail=动作失败无结论"
            "（WAF拦截/403/网络错误/未复现）。画报动作标签直接采用该定性——「测了X」「未复现」"
            "这类描述由你定性为 fail，系统不再按关键词猜。"
            "**重测覆盖**：同工具+逐字相同的 intent 会原位覆盖旧记录（补包/重测不堆重复动作）——"
            "修复自检错配时段1 intent 必须照抄原动作文字。"
            "每个功能点至少要有一条测试记录（tap/http_request/wx_request/burst_request 等）。"
            "**一个测试动作一条记录，禁止合并**：功能点有多个测试点（如 SQL 注入 + 价格篡改）时，"
            "每个测试点单独走一遍两段式（各自的 intent/result/证据独立），"
            "画板会为每个动作生成独立节点。"
            "**verdict=vuln 时必须用 key_packets 指认关键数据包**（证明漏洞的那 1~2 个包）："
            "从窗口内刚收到的包里挑出最能证明漏洞的（通常是结论里宣称的成功响应包/泄露数据包），"
            "按请求特征指认（路径段+关键参数值，如「evaluate/add + CZ202512121459548375」）——"
            "系统按指认挑选挂账，避免窗口里失败的重试包抢位；"
            "判定依据（结论里说的订单号/响应码/价格）必须与被指认包的实际响应一致",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "功能点名称（须已登记）"},
                    "tool": {"type": "string", "description": "使用的工具名，如 http_request/tap_element/burst_request"},
                    "intent": {"type": "string", "description": "本条测试动作的意图（只写这一个动作），如「篡改 order_id 测水平越权」"},
                    "result": {"type": "string", "description": "本条动作的结果一句话，如「200 返回他人订单数据，越权确认」。记意图（开窗口）时留空，记结论（收窗口）时必填"},
                    "verdict": {"type": "string", "enum": ["vuln", "safe", "fail"],
                                "description": "结论定性（记结论时必填，AI 自己判定）：vuln=该动作证实了漏洞存在；safe=该动作证实无漏洞（防御有效/响应正常）；fail=动作本身失败无结论（WAF拦截/网络错误/参数不存在/未复现）。记结论（result 非空）时省略会被拒收要求补传——画报动作没有状态标记的根源就是漏传 verdict"},
                    "key_packets": {"type": "array", "items": {"type": "string"},
                                    "description": "verdict=vuln 时必填：本动作证明漏洞的关键数据包指认，每条一个特征串（接口路径段+关键参数值，如 evaluate/add + CZ202512121459548375）。系统按特征从窗口内包中挑出对应包作为证据；不指认则默认取窗口全部包"},
                },
                "required": ["name", "tool", "intent"],
            },
            self._tool_registry_log, "dynamic",
        )
        R.register(
            "registry_update_state", "推进功能点测试状态：testing(测试中)/confirmed(确认漏洞)/clean(已测无漏洞)/"
            "skipped(跳过，必须附原因)。clean/confirmed 前必须已有 registry_log 留痕的测试动作，"
            "无漏洞也要先记录测了什么、结果如何；无法测试用 skipped 附原因。"
            "置终态时登记的每条 risk_hints 必须逐条申报处置（发现了就测），漏报直接拒收："
            "**推荐传 hint_resolutions=[{hint_index: 序号, verdict: \"tested\"或\"waived\", "
            "reason: 豁免理由}]**（hint_index 按 registry_add 登记 risk_hints 的数组序号从 0 起，"
            "只报序号不复述原文，tested 不用 reason）；也可在 note 里写文本标记兜底："
            "【已测】<联想开头>（测了什么）/【豁免】<联想开头>：<理由>。"
            "置 confirmed 时系统自动把该功能点 verdict=vuln 动作的证据包整批固化为快照，"
            "报告直接引用这批包——漏洞动作收账时必须带 verdict=vuln，否则其包进不了报告",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "功能点名称（须已登记）"},
                    "state": {"type": "string", "enum": ["testing", "confirmed", "clean", "skipped"],
                              "description": "confirmed=确认漏洞 clean=已测无漏洞 skipped=跳过(必须附原因)"},
                    "note": {"type": "string", "description": "结论或跳过原因（skipped 必填）；置终态时若不传 hint_resolutions，在 note 末尾逐条写【已测】/<联想开头>（测了什么）/【豁免】/<联想开头>：<理由>"},
                    "hint_resolutions": {"type": "array", "items": {
                        "type": "object",
                        "properties": {
                            "hint_index": {"type": "integer", "description": "risk_hints 数组序号，从 0 起"},
                            "verdict": {"type": "string", "enum": ["tested", "waived"],
                                        "description": "tested=已测过；waived=豁免不适用"},
                            "reason": {"type": "string", "description": "豁免理由（verdict=waived 必填，会随报告暴露给用户）；tested 时不用传"},
                        },
                        "required": ["hint_index", "verdict"],
                    }, "description": "置终态必传（推荐方式）：登记的 risk_hints 逐条处置申报，按序号引用，漏一条直接拒收并回传 unhandled_hints 清单"},
                },
                "required": ["name", "state"],
            },
            self._tool_registry_update_state, "dynamic",
        )
        R.register(
            "registry_list", "查看功能点登记册全量清单与覆盖度（闭环 x/y，未闭环功能点名列表）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_registry_list, "dynamic",
        )

        # ── 引擎自恢复（断连唯一可靠恢复通道）──
        R.register(
            "reconnect_engine",
            "重新附加调试引擎（Frida 重新注入 + CDP 通道重建），修复「小程序未连接/逻辑层冻结」后"
            "一切工具持续无响应的死局。使用时机：①「小程序未连接」报错连续出现 2-3 次且未自动恢复；"
            "②逻辑层冻结（frozen:true）处置后仍无响应；③location.reload 之类渲染层自救操作后连接彻底断开"
            "（hook 已随进程丢失，等自动重连和重启小程序进程都无效，只有重注入能救）。"
            "调用成功后先 get_page_state 确认恢复再继续测试；失败（如微信未开/小程序未打开）时提示用户手动干预",
            {"type": "object", "properties": {}, "required": []},
            self._tool_reconnect_engine, "dynamic",
        )
        R.register(
            "self_check_evidence", "动作↔数据包对齐自检：核对登记册每个动作描述提到的接口"
            "与其证据报文 URL 是否同源，输出错配/无证据清单。"
            "**写完画报（每完成一个功能点的测试）和写报告（generate_report 前）必须调用，"
            "有 must_fix 逐条修复后复检，全绿才能继续**",
            {"type": "object", "properties": {}, "required": []},
            self._tool_self_check_evidence, "dynamic",
        )
        R.register(
            "verify_evidence_semantics", "AI 语义检验（比 self_check 更深一层）：把动作描述"
            "（intent+result）与挂账数据包**原文**一起交给 AI 逐条判定——包内容能否支撑描述宣称"
            "（宣称成功但包是500、宣称的订单号在包里找不到、宣称泄露的值没出现在响应里 = 不吻合）。"
            "**generate_report 前必跑**，与 self_check_evidence 串联：URL 对齐 + 语义吻合都全绿才出报告；"
            "不吻合的动作按 must_fix 重走两段式重新发包（intent 逐字相同原位覆盖），复检全绿后写报告",
            {"type": "object", "properties": {}, "required": []},
            self._tool_verify_evidence_semantics, "dynamic",
        )

        # ── 报告 ──
        R.register(
            "generate_report", "生成渗透测试报告（每个漏洞按四段式：漏洞描述/漏洞复现/漏洞危害/修复建议）。"
            "报告自动附带功能点测试覆盖度统计，未闭环的功能点会在报告中显式列出。"
            "报告可能被用户删除后要求重新生成，此时直接调用本工具重发即可；"
            "输出预算截断不阻碍此调用（findings 分条产出，系统自动填充真实数据包）"
            "【验收前置·每次调用前自查，不满足不要调】① self_check_evidence 已通过（全绿）；"
            "② 所有已登记功能点均已闭环（tested/confirmed/clean/skipped），没有只登记未测试的；"
            "③ 每个运行时漏洞都有真实留痕数据包（证据包不挂 evidence 的漏洞会被验收打回）。"
            "【常见被拒原因（被拒=浪费一整轮输出预算）】报告验收会打回：存在只登记未测试的功能点"
            "（提示会列出缺口清单）→ 先测试补闭环，禁止仅为补数据包对已测过的动作原样重复探测"
            "（同接口重复发包只堆重复留痕，补不了包；缺包动作按 self_check_evidence 提示重走"
            "两段式留痕）；①self_check_evidence 未通过 → 按返回的 must_fix/no_evidence 修复后复查；"
            "②静态信息项（反编译敏感信息类）feature 填字面量「static」+evidence 文件证据，"
            "运行时漏洞才挂数据包（静态项不查包）",
            {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "findings": {
                        "type": "array",
                        "description": "发现列表",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string", "description": "漏洞名称"},
                                "feature": {
                                    "type": "string",
                                    "description": "运行时漏洞二选一必填（A/B 见下）：填关联的登记册功能点名（从功能点登记册/画板骨架复制准确名称，写错名=挂不上包）。A 漏洞通过操作某个已登记功能点复现 → 填该功能点名，报告复现数据包直取该功能点确认时固化的真实流量快照（与画板同源）。B 反编译文件类漏洞（硬编码密钥/源码泄露等静态发现）→ 填字面量「static」（不填会被校验以「缺 feature 且缺 related_api」拒收，实测踩坑）并同时填 evidence",
                                },
                                "related_api": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "该漏洞涉及的接口 URL 关键字数组（如 api.example.com/wscgoods/detail）。运行时漏洞若无法归入任何已登记功能点（暴露面探测/独立接口测试等）→ 必填此字段（系统按此从真实流量提取复现数据包）；挂了 feature 的运行时漏洞也应填写（供包对账白名单）。反编译敏感信息类漏洞（硬编码密钥/源码泄露等）不填",
                                },
                                "evidence": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "path": {"type": "string", "description": "所在文件相对路径，如 appservice/page/api.js"},
                                            "content": {"type": "string", "description": "敏感内容原文（该行/该段，敏感值部分可打码保留前后 4 字符）"},
                                            "line": {"type": "number", "description": "行号（知道时填）"},
                                        },
                                        "required": ["path", "content"],
                                    },
                                    "description": "静态证据（反编译敏感信息类漏洞必填，且该条 finding 的 feature 须填字面量「static」；网络类漏洞不填）：敏感信息所在的文件路径+内容原文，每处一条",
                                },
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"],
                                             "description": "critical=严重 high=高危 medium=中危 low=低危 info=信息"},
                                "description": {"type": "string", "description": "漏洞描述：漏洞成因与位置"},
                                "reproduction": {"type": "string", "description": "漏洞复现：完整复现步骤文字说明。每一步必须写明接口路径原文（如 PUT /app/shopp/shoppReceive/edit）与关键参数值（如 receiveId=108749），禁止用「编辑接口」「详情接口」这类泛称——系统靠路径与参数值把真实数据包挂到对应步骤，泛称会导致该步数据包挂空"},
                                "packets": {"type": "object",
                                            "description": "复现数据包：禁止填写！系统会用测试留痕的真实数据包自动填充（AI 复盘实测教训：手写报文 100% 被验收打回并引入编造接口）；没有留痕真实报文的漏洞数据包留空（宁可没有也不准用文字说明/自编报文充当数据包）",
                                            "properties": {
                                                "tampered": {"type": "string", "description": "请求包（实施攻击发出的请求）：仅当工具结果里有真实报文时原样复制"},
                                                "response": {"type": "string", "description": "响应包：仅当工具结果里有真实报文时原样复制"},
                                            }},
                                "impact": {"type": "string", "description": "漏洞危害：可造成的实际影响"},
                                "recommendation": {"type": "string", "description": "修复建议"},
                            },
                            "required": ["title", "severity", "description", "reproduction", "impact", "recommendation"],
                        },
                    },
                    "findings_delta": {
                        "type": "array",
                        "description": "【r2 增量修正，推荐用于被打回后的重传】按 id 的 findings 补丁："
                            "首次调用必须用 findings 全量；被拒后重传只需传本参数（下轮无需再发全量，"
                            "系统用会话暂存的上次 findings 合并本补丁后再验收）——省掉逐轮 5 万字符的全量重发。"
                            "补丁项格式：{\"id\": 序号(从0起), \"op\": \"set|del\", 以及要修改的字段}"
                            "——op=set 时只写要改的字段（title/severity/description/reproduction/"
                            "impact/recommendation/feature/related_api/evidence），未写的字段保留原值；"
                            "op=del 表示删除该条。新增一条：id 填现有最大序号+1 且 op=set 带全部必填字段。"
                            "注意：若被拒原因涉及「必填字段缺失」，该条补丁必须把缺失字段一并写全",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "number", "description": "findings 序号（从 0 起，与上轮传的顺序一致）"},
                                "op": {"type": "string", "enum": ["set", "del"], "description": "set=修改/新增该条（未写字段保留），del=删除该条"},
                                "title": {"type": "string", "description": "漏洞名称（op=set 时可选择性修改）"},
                                "feature": {"type": "string", "description": "关联登记册功能点名（op=set 时可选择性修改）"},
                                "related_api": {"type": "array", "items": {"type": "string"}, "description": "接口 URL 关键字数组（op=set 时可选择性修改）"},
                                "evidence": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "line": {"type": "number"}}, "required": ["path", "content"]}, "description": "静态证据（op=set 时整组替换）"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                                "description": {"type": "string"},
                                "reproduction": {"type": "string"},
                                "impact": {"type": "string"},
                                "recommendation": {"type": "string"},
                            },
                            "required": ["id", "op"],
                        },
                    },
                    "reuse_last_findings": {
                        "type": "boolean",
                        "description": "【被打回后重传且 findings 无任何变化时传 true】直接复用会话暂存的上次 findings "
                            "（本轮不再传 findings/findings_delta，只改 title）。系统不会因「findings 与上次相同」拒收——"
                            "打回原因若在 findings 之外（对账/素材门），此项可省一整轮 5 万字符",
                    },
                },
                "required": ["title", "findings"],
            },
            self._tool_generate_report, "report",
        )
        R.register(
            "report_finding", "实时分级上报漏洞发现（中高危才调，低危/噪音不要上报）。"
            "拿到可复现的漏洞证据（如越权拿到他人数据、0元购成功）时立即调用，"
            "用户端会高亮置顶提醒。**不替代闭环**：登记册仍要 registry_update_state 置 confirmed，"
            "报告 findings 必须包含本条",
            {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "漏洞名称（≤60字），如「订单详情接口水平越权（IDOR）」"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"],
                                 "description": "严重级别（critical/high 会高亮提醒用户）"},
                    "evidence_summary": {"type": "string",
                                         "description": "证据摘要（≤300字）：接口+篡改点+响应差异，一行结论式"},
                    "feature": {"type": "string", "description": "关联的功能点名（登记册中的名称），可选"},
                },
                "required": ["title", "severity", "evidence_summary"],
            },
            self._tool_report_finding, "report",
        )

        # ── 渗透画板：信息搜集资产补充登记（信息搜集类工具已自动记录，AI 只补遗漏）+ 读取
        R.register(
            "add_board", "在渗透画板「信息搜集」分支补充登记一条资产信息（同名自动去重）。"
                         "仅在自动记录遗漏了重要资产时使用，标题一句话、细节一行以内",
            {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["recon", "sensitive", "note"],
                             "description": "recon=资产信息 sensitive=敏感资产 note=备注"},
                    "title": {"type": "string", "description": "一句话标题，如「IP 风控影子接口」"},
                    "detail": {"type": "string", "description": "一行关键值细节"},
                    "source": {"type": "string", "description": "信息来源渠道，如「反编译的文件」「响应数据包」「小程序运行时」，不要写工具名"},
                },
                "required": ["type", "title"],
            },
            self._tool_add_board, "recon",
        )
        R.register(
            "get_board", "读取渗透画板当前内容（信息搜集资产 + 功能点测试进展思维导图数据）",
            {"type": "object", "properties": {}, "required": []},
            self._tool_get_board, "report",
        )

    # ════════════════════════════════
    #  工具实现
    # ════════════════════════════════

    async def _tool_get_app_info(self):
        await self.navigator.fetch_config()
        info = dict(self.navigator.app_info)
        # appid 兜底：getAccountInfoSync（逻辑层 API）常驻执行，不再被 appid 非空短路。
        # 旧逻辑 `if not info.get("appid")` 导致单例残留旧 appid 时权威源永远没机会
        # 读取——切到第二小程序后 __wxConfig.appid 为空回退旧值，权威兜底被跳过，
        # 两个会话的标题/画报/报告全部署同一个旧 appid（实测踩坑）
        _auth_appid = ""
        try:
            js = (
                "JSON.stringify((function(){try{"
                "var f=(window.nav&&window.nav.wxFrame)||window;"
                "var a=f.wx&&f.wx.getAccountInfoSync&&f.wx.getAccountInfoSync();"
                "return {appid:(a&&a.miniProgram&&a.miniProgram.appId)||'',"
                "version:(a&&a.miniProgram&&a.miniProgram.version)||''};"
                "}catch(e){return {}}})())"
            )
            r = await self.engine.evaluate_js(js, timeout=5.0)
            v = self._extract_value(r)
            if v:
                import json as _json
                extra = _json.loads(v)
                _auth_appid = extra.get("appid", "")
        except Exception:
            pass
        # 切换检测：权威源读到与单例不同的 appid = 目标小程序已切换 → 清空单例身份，
        # 以本次权威值+新 fetch 值重建（同身份时 getAccountInfoSync 结果只做兜底补空）
        if _auth_appid and info.get("appid") and _auth_appid != info.get("appid"):
            self.navigator.reset_identity()
            info = {"appid": _auth_appid, "version": ""}
            # 单例身份已重置，重拉一次配置拿新小程序的权威名
            # （首次 fetch 时旧身份还在，name 被合并规则保成了旧名，已随重置丢弃）
            try:
                await self.navigator.fetch_config()
                info["name"] = self.navigator.app_info.get("name", "")
                info["entry"] = self.navigator.app_info.get("entry", "")
            except Exception:
                pass
        elif _auth_appid and not info.get("appid"):
            info["appid"] = _auth_appid
            info.setdefault("version", "")
        if _auth_appid and info.get("appid") == _auth_appid:
            info.setdefault("version", "")
        if self.navigator:
            self.navigator.app_info.update(info)
        # 身份确认即快照：appid 是会话属性，首次确认后持久化，供标题/画报/报告
        # 跨进程重启稳定读取（单例是进程属性，切目标/重启后都会变）
        sid_now = getattr(self, "_task_sid", None) or self.current_sid
        if sid_now and info.get("appid"):
            self._update_session_identity(sid_now, info.get("appid"), info.get("name", ""))
        # 代理残留兜底检测：任务开场 run_task 已自动清库，正常情况下本任务
        # 的 captures 全是当前目标的包。此处捕获「同一任务中途换目标」的
        # 罕见场景（appid 与代理记录的上次 appid 不同 + 已有捕获 = 有残留），
        # 仍触发则提示用户重启代理（自动清只在任务开场跑，中途不清防误删
        # 本任务刚抓的包）
        proxy_warning = ""
        try:
            pc = getattr(self.state, "proxy_capture", None)
            cur_appid = info.get("appid", "")
            if pc is not None and cur_appid:
                last = getattr(pc, "last_appid", None)
                stale = len(getattr(pc, "captures", []) or [])
                if last and last != cur_appid and stale > 0:
                    proxy_warning = (f"检测到测试目标切换（上一目标 {last} → 当前 {cur_appid}），"
                                     f"捕获代理中已有 {stale} 条流量与当前目标不符"
                                     "（可能是本任务中途切换了目标小程序）。"
                                     "请提示用户：先停止代理再重新启动（重启会自动清空残留），"
                                     "再继续本目标的抓包与测试")
                pc.last_appid = cur_appid
        except Exception:
            pass
        # 信息搜集到手后自动命名会话
        try:
            self._auto_title_session(sid_now)
        except Exception:
            pass
        out = {
            "appid": info.get("appid", ""),
            "name": info.get("name", ""),
            "entry": info.get("entry", ""),
            "page_count": len(self.navigator.pages),
            "tab_bar_count": len(self.navigator.tab_bar_pages),
        }
        if proxy_warning:
            out["proxy_stale_warning"] = proxy_warning
        return out

    async def _tool_list_routes(self, offset=0, limit=120):
        await self.navigator.fetch_config()
        pages = self.navigator.pages
        # 空清单诊断：fetch_config 内部 evaluate 静默失败时（CDP 通道故障/桥接丢失），
        # 不让 AI 拿到空列表误判为「小程序无页面」，给出排查线索
        if not pages:
            return {"pages": [], "tabBar": self.navigator.tab_bar_pages,
                    "warning": "页面清单为空。可能原因：① 渲染层 CDP 通道故障（重启调试会话/微信开发者工具）；"
                               "② 逻辑层桥接未建立（等小程序页面加载完成后再试）；"
                               "③ 兜底：用 decompile_wxapkg 反编译后读 app-config.json 的 pages 字段静态还原页面清单"}
        # 大清单分页：403 页一次全量返回会被写时裁剪掐头去尾，AI 实际拿到的是残缺清单
        # （上一轮 403 页只看到开头几十个）。改分页游标模式：默认每页 120 条
        try:
            offset = max(0, int(offset))
            limit = min(300, max(20, int(limit)))
        except (TypeError, ValueError):
            offset, limit = 0, 120
        total = len(pages)
        # tabBar 页排最前（遍历起点），其余保持原序
        tb = list(self.navigator.tab_bar_pages or [])
        ordered = [p for p in tb if p in pages] + [p for p in pages if p not in tb]
        chunk = ordered[offset:offset + limit]
        out = {"pages": chunk, "tabBar": tb,
               "total": total, "offset": offset, "count": len(chunk)}
        if offset + limit < total:
            out["next_offset"] = offset + limit
            out["hint"] = (f"页面清单共 {total} 页，本页 {len(chunk)} 条（{offset}–{offset + len(chunk) - 1}）。"
                           f"继续拉取用 list_routes(offset={out['next_offset']})，"
                           f"遍历优先级：tabBar 页 → 业务主包页 → 分包页（async-* 占位包与 webview 壳页可跳过）")
        else:
            out["hint"] = f"页面清单已到末尾（共 {total} 页）。遍历优先级：tabBar 页 → 业务主包页 → 分包页（async-* 占位包与 webview 壳页可跳过）"
        return out

    async def _tool_get_storage(self, key=None, offset=0, limit=40):
        blk = self._guard_miniapp_conn("get_storage")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        js = ("(function(){"
              "try{"
              "var nav=window.nav;"
              "var wxObj=nav&&nav.wxFrame?nav.wxFrame.wx:window.wx;"
              "if(!wxObj||!wxObj.getStorageInfoSync)return JSON.stringify({err:'no wx'});"
              "var info=wxObj.getStorageInfoSync();"
              "var out={};"
              "for(var i=0;i<info.keys.length;i++){"
              "try{out[info.keys[i]]=wxObj.getStorageSync(info.keys[i])}catch(e){}"
              "}"
              "return JSON.stringify(out);"
              "}catch(e){return JSON.stringify({err:e.message})}"
              "})()")
        if key:
            # 指定 key 精确读取：大 value 完整返回（截 12000），不被其他 key 挤占
            key_js = json.dumps(str(key), ensure_ascii=False)
            js = ("(function(){"
                  "try{"
                  "var nav=window.nav;"
                  "var wxObj=nav&&nav.wxFrame?nav.wxFrame.wx:window.wx;"
                  "if(!wxObj||!wxObj.getStorageSync)return JSON.stringify({err:'no wx'});"
                  f"var v=wxObj.getStorageSync({key_js});"
                  "return JSON.stringify({k:" + key_js + ", v:v===undefined?null:v});"
                  "}catch(e){return JSON.stringify({err:e.message})}"
                  "})()")
        result = await self.engine.evaluate_js(js, timeout=8.0)
        value = self._extract_value(result)
        if not value:
            return {"error": "无法读取缓存"}
        try:
            data = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {"error": "解析失败", "raw": value[:2000]}
        if data.get("err"):
            return {"error": f"读取缓存失败: {data['err']}"}
        if key:
            return {"key": key, "value": data.get("v"),
                    "hint": "大 value 可分段读：evaluate_js 对 getStorageSync 结果自行切片"}
        # 全量读取 → 按 key 分页返回（40+ key 且 value 大时极易触发写时裁剪）
        items = data if isinstance(data, dict) else {}
        keys = sorted(items.keys())
        try:
            offset = max(0, int(offset))
            limit = min(200, max(10, int(limit)))
        except (TypeError, ValueError):
            offset, limit = 0, 40
        chunk_keys = keys[offset:offset + limit]
        out_items = {}
        for k in chunk_keys:
            v = items[k]
            s = json.dumps(v, ensure_ascii=False, default=str) if not isinstance(v, str) else v
            # 单 value 预览截 800，指定 key 精确读才是完整通道
            if len(s) > 800:
                out_items[k] = {"_preview": s[:800], "_len": len(s),
                                "_truncated": True}
            else:
                out_items[k] = v
        out = {"storage": out_items, "total_keys": len(keys),
               "offset": offset, "count": len(chunk_keys)}
        if offset + limit < len(keys):
            out["next_offset"] = offset + limit
            out["hint"] = (f"缓存共 {len(keys)} 个 key，本页 {len(chunk_keys)} 个（值超 800 字符只回预览）。"
                           f"下一页 get_storage(offset={out['next_offset']})；"
                           f"要完整读某个 key 用 get_storage(key=\"名称\")")
        else:
            out["hint"] = f"缓存清单已到末尾（共 {len(keys)} 个 key）。要完整读某个 key 用 get_storage(key=\"名称\")"
        return out

    async def _tool_static_scan(self):
        results = await self.cloud.static_scan()
        return {"count": len(results), "cloud_functions": results}

    async def _tool_decompile(self, appid, packages_dir=None):
        from src.wxapkg import find_wxapkg_files, find_wxapkg_files_multi, extract_wxapkg, deep_find_wxapkg
        # 反编译目标确定后也尝试自动命名（get_app_info 失败时兜底，用 appid 命名）
        try:
            self._auto_title_session(getattr(self, "_task_sid", None) or self.current_sid)
        except Exception:
            pass
        # 解析包目录：显式传参 > 配置持久化 > 自动扫描所有微信账号目录
        dirs = []
        if packages_dir:
            dirs = [packages_dir]
        else:
            try:
                from webapp.routes import _resolve_packages_dirs
                dirs = _resolve_packages_dirs()
            except Exception:
                from src.wxapkg import get_all_packages_dirs
                dirs = get_all_packages_dirs()
        pkgs = [p for p in find_wxapkg_files_multi(dirs) if p["appid"] == appid] if dirs else []
        if not pkgs:
            # 常规路径找不到 → 按目录名全树下钻（微信 4.x 目录结构多变）
            pkgs = deep_find_wxapkg(appid)
            if pkgs:
                dirs = dirs or ["<radium 深度搜索>"]
        if not pkgs:
            available = sorted({p["appid"] for p in find_wxapkg_files_multi(dirs)}) if dirs else []
            return {"error": f"未找到 appid={appid} 的 wxapkg",
                    "searched_dirs": dirs,
                    "available": available[:20]}
        import os
        # 插件包过滤：__PLUGINCODE__.wxapkg 的文件头 marker 为 0xe9（正常包 0xBE/0xED），
        # 常规解包流程必然失败，且会拖垮整个反编译（此前单包失败直接整体 return）
        plugin_pkgs = [p for p in pkgs if "PLUGINCODE" in (p.get("name") or "").upper()]
        pkgs = [p for p in pkgs if p not in plugin_pkgs] if plugin_pkgs else pkgs
        if not pkgs:
            return {"error": f"appid={appid} 只找到插件包（{[p['name'] for p in plugin_pkgs]}），"
                             f"插件包格式不同无法用常规流程解包；请先在微信中完整打开一次小程序让主包落盘"}
        out_dir = os.path.join("decompiled", appid)
        # 解包前清空旧产物：out_dir 按 appid 键控，extract_wxapkg 只覆盖同名文件不删旧文件，
        # 小程序更新后旧版本残留会被 read_decompiled_file/search_decompiled 读到，
        # 造成「新旧版本接口混杂」的假证据（跨会话残留排查中的实证问题）
        if os.path.isdir(out_dir):
            shutil.rmtree(out_dir, ignore_errors=True)
        all_files = []
        failures = []
        for pkg in pkgs:
            try:
                files = extract_wxapkg(pkg["path"], out_dir, appid)
                all_files.extend(files)
            except Exception as e:
                # 单包失败不再中止整体：主包失败仍可继续尝试分包
                failures.append(f"{pkg['name']}: {e}")
        if not all_files:
            return {"error": "解包失败（全部包均失败）",
                    "detail": failures[:5],
                    "hint": "若报 marker/格式错误，说明抓到的是插件包或损坏包；"
                            "先在微信中完整打开一次小程序让主包重新落盘再试"}
        if failures:
            result = {"ok": True, "output_dir": out_dir, "file_count": len(all_files),
                    "partial_failures": failures[:5],
                    "structure": self._decompile_structure(out_dir, all_files)}
        else:
            result = {"ok": True, "output_dir": out_dir, "file_count": len(all_files),
                    "structure": self._decompile_structure(out_dir, all_files)}
        # 静态锚点提取：机器自动从反编译产物提取页面/接口全量清单，
        # 作为发现阶段的确定性下限（AI 动态游走只做补充核对，不承担穷尽性）
        try:
            result["static_anchors"] = self._extract_static_anchors(out_dir)
        except Exception:
            pass
        return result

    @staticmethod
    def _extract_static_anchors(out_dir: str) -> dict:
        """从反编译产物机器提取「页面全清单 + 接口路径候选」。

        页面：app-config.json / app.json 的 pages（含分包 subPackages/subpackages）
        与 tabBar；接口：JS 源码里的 url/path 常量（wx.request 调用形态），
        只保留像接口的（含 / 分隔），过滤静态资源与超长噪音。
        """
        import os as _os
        pages, tab_pages = [], []
        # 1) 页面清单：优先 app-config.json（wxapkg 解包主配置），退回 app.json
        cfg = None
        for cand in ("app-config.json", "app.json"):
            p = _os.path.join(out_dir, cand)
            if _os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                        cfg = json.load(fp)
                    break
                except Exception:
                    cfg = None
        if isinstance(cfg, dict):
            def _collect_pages(node):
                if isinstance(node, list):
                    for x in node:
                        if isinstance(x, str) and x and not x.startswith("/"):
                            pages.append("/" + x)
                        elif isinstance(x, str):
                            pages.append(x)
            _collect_pages(cfg.get("pages"))
            for sp in (cfg.get("subPackages") or cfg.get("subpackages") or []):
                root = str(sp.get("root", "")).strip("/")
                for pg in sp.get("pages", []):
                    pages.append("/" + (root + "/" + str(pg)).strip("/"))
            tb = (cfg.get("tabBar") or {}).get("list") or []
            for t in tb:
                if isinstance(t, dict) and t.get("pagePath"):
                    # 反编译产物 pagePath 可能带 .html 后缀（如 pages/x/index.html），归一化
                    pp = str(t["pagePath"]).strip("/")
                    if pp.lower().endswith(".html"):
                        pp = pp[:-5]
                    tab_pages.append("/" + pp)
        # 2) 接口候选：扫全部 JS 提取 url/path 常量（限深限量防大包卡死）
        # 小程序内部路径前缀（页面/组件引用，不是后端接口）
        _INTERNAL_PREFIX = ("/pages/", "/components/", "/packages/", "/custom-tab-bar",
                            "/ext-", "/assets/", "/images/", "/img/", "/static/",
                            "/styles/", "/utils/", "/node_modules/", "/./")
        api_hits = {}
        js_count = 0
        for dirpath, dirnames, filenames in _os.walk(out_dir):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
            for fn in filenames:
                if not fn.lower().endswith((".js", ".json")):
                    continue
                js_count += 1
                if js_count > 3000:
                    break
                fp_ = _os.path.join(dirpath, fn)
                try:
                    if _os.path.getsize(fp_) > 8 * 1024 * 1024:
                        continue
                    with open(fp_, "r", encoding="utf-8", errors="ignore") as fp:
                        text = fp.read()
                except Exception:
                    continue
                # url: "/xxx/yyy"、url:`/xxx`、"/api/xxx" 等形态；相对路径常量不带域名也算
                for m in re.findall(r'''["'`](/[A-Za-z0-9_\-./]{3,120})["'`]''', text):
                    if m.count("/") < 2 or m.endswith((".js", ".json", ".png", ".jpg",
                                                       ".gif", ".css", ".html", ".wxss",
                                                       ".webp", ".svg", ".mp3", ".mp4")):
                        continue
                    if m.startswith(_INTERNAL_PREFIX) or m.endswith("/"):
                        continue
                    api_hits[m] = api_hits.get(m, 0) + 1
            if js_count > 3000:
                break
        # 出现 ≥2 次的优先（常量复用），全部按出现次数排序截断
        apis = sorted(api_hits, key=lambda k: -api_hits[k])
        return {"pages": sorted(set(pages)), "tab_bar": tab_pages,
                "apis": apis[:200], "api_files_scanned": js_count}

    @staticmethod
    def _decompile_structure(out_dir: str, all_files: list) -> dict:
        """生成目录结构摘要，让 AI 不用盲猜路径：
        主包文件在 out_dir 根，分包在 packages/{name}/ 下"""
        root_files, sub_pkgs = [], {}
        for f in all_files:
            rel = f.replace("\\", "/").removeprefix(out_dir.replace("\\", "/")).lstrip("/")
            if rel.startswith("packages/"):
                parts = rel.split("/", 2)
                sub_pkgs.setdefault(parts[1], 0)
                sub_pkgs[parts[1]] += 1
            else:
                root_files.append(rel)
        return {
            "root_files": sorted(root_files)[:60],
            "sub_packages": {k: sub_pkgs[k] for k in sorted(sub_pkgs)},
        }

    async def _tool_scan_sensitive(self, scan_dir):
        from src.extractor import Extractor
        ext = Extractor()
        # with_locations：结果附带「文件:行号」位置，供画板反编译文件溯源
        result = ext.scan_directory(scan_dir, with_locations=True)
        # 入库 + WebSocket 通知敏感信息页（appid 读会话快照，单例可能残留上一个目标）
        appid = self._session_identity().get("appid", "")
        try:
            self.state.add_sensitive(
                {**result.get("results", {}), **{f"custom:{k}": v for k, v in result.get("custom_results", {}).items()}},
                source=scan_dir, appid=appid,
                files_scanned=result.get("files_scanned", 0),
            )
        except Exception:
            pass
        return result

    async def _tool_read_file(self, file_path, offset=0, max_lines=200):
        """读取解包文件。规则：
        - 相对路径自动补 decompiled/ 前缀；传入的路径若已带前缀不重复补（修双前缀）
        - 传目录时返回该目录列表（含子目录内容，修盲猜）
        - 大文件支持 offset 分页读取（修 2MB 文件直接拒绝）
        """
        import os
        norm = file_path.replace("\\", "/").strip()
        if not os.path.isabs(norm):
            # 防双前缀：已带 decompiled/ 开头的不再补
            parts = norm.split("/")
            if parts and parts[0] == "decompiled":
                norm = "/".join(parts[1:])
            norm = os.path.join("decompiled", norm)
        if os.path.isdir(norm):
            entries = []
            try:
                for name in sorted(os.listdir(norm))[:200]:
                    full = os.path.join(norm, name)
                    if os.path.isdir(full):
                        entries.append(f"{name}/ ({len(os.listdir(full))} 项)")
                    else:
                        entries.append(f"{name} ({os.path.getsize(full)} bytes)")
            except PermissionError:
                return {"error": f"目录无权限: {norm}"}
            return {"type": "directory", "path": norm, "listing": entries}
        if not os.path.exists(norm):
            # 找不到时只列出目标所在目录（单层、带目录标记），避免跨层级混淆导致反复盲猜
            err = {"error": f"文件不存在: {norm}",
                   "hint": "结合 dir_listing 校准相对路径（不要带 decompiled/ 前缀）"}
            target_dir = os.path.dirname(norm)
            probe = target_dir
            for _ in range(2):
                if os.path.isdir(probe):
                    try:
                        listing = []
                        for name in sorted(os.listdir(probe))[:100]:
                            full = os.path.join(probe, name)
                            listing.append(f"{name}/" if os.path.isdir(full) else name)
                        err["dir_listing"] = {"dir": probe, "entries": listing}
                        break
                    except PermissionError:
                        pass
                probe = os.path.dirname(probe)
            return err
        size = os.path.getsize(norm)
        offset = max(0, int(offset or 0))
        max_lines = max(1, min(int(max_lines or 200), 1000))
        # 单行长文件（压缩 bundle）自动切字符页：read_decompiled_file 按行分页，
        # 一行 76KB 时 total_lines=1、12KB 显示上限把中间段永远截掉——offset 翻页
        # 返回全空是死路（实测 bulidOrderNew 提交函数因此始终读不到）。此处把超长
        # 行按 ~4000 字符切成多「行」，offset 在字符页坐标下继续翻页
        _CHAR_PAGE = 4000
        need_split = False
        with open(norm, "r", encoding="utf-8", errors="ignore") as f:
            lines = []
            total_lines = 0
            for i, line in enumerate(f):
                if len(line) > _CHAR_PAGE:
                    need_split = True
                    chunks = [line[k:k + _CHAR_PAGE]
                              for k in range(0, len(line), _CHAR_PAGE)]
                    for ci, ck in enumerate(chunks):
                        if offset <= total_lines < offset + max_lines:
                            lines.append(f"{ci + 1}| {ck.rstrip(chr(10))}")
                    total_lines += len(chunks)
                    if total_lines > offset + max_lines:
                        break
                else:
                    total_lines += 1
                    if offset <= i < offset + max_lines:
                        lines.append(line.rstrip("\n"))
        result = {
            "path": norm, "size": size, "total_lines": total_lines,
            "offset": offset, "content": "\n".join(lines),
        }
        if need_split:
            result["long_line_split"] = True
            result["note"] = ("文件含超长行（压缩 bundle），已按 4000 字符切页；"
                              "content 前缀 N| 是同一行的第 N 段。继续翻页用 next_offset——"
                              "search_decompiled 报告的行号是源文件行号，与本工具的 offset"
                              " 坐标系不同（本文件按字符页计），禁止拿 search 行号当 offset 翻页")
        if offset + max_lines < total_lines:
            result["next_offset"] = offset + max_lines
            if "note" in result:
                result["note"] += f"；用 offset={offset + max_lines} 继续"
            else:
                result["note"] = f"文件较大已分页，用 offset={offset + max_lines} 继续读取"
        return result

    async def _tool_read_artifact(self, artifact_id, offset=0, max_lines=200):
        """分页读回已存档的超长工具结果原文（卸载在 webapp/artifacts/<sid>/ 下）。

        防 path traversal：句柄只允许 <sid>/<文件名> 两段，文件名白名单字符；
        命中失败时列出该会话可用 artifact 帮助纠错（避免盲猜句柄空转）。
        """
        norm = str(artifact_id).replace("\\", "/").strip("/")
        parts = norm.split("/")
        if (len(parts) != 2 or any(p in ("", ".", "..") for p in parts)
                or not all(re.fullmatch(r"[\w.\-]+", p) for p in parts)):
            return {"error": f"artifact_id 格式非法: {artifact_id}",
                    "hint": "格式为 <sid>/<文件名>，从截断结果的存档提示里原样复制"}
        path = os.path.join(self._artifacts_dir, *parts)
        if not os.path.isfile(path):
            avail = []
            try:
                sdir = os.path.join(self._artifacts_dir, parts[0])
                if os.path.isdir(sdir):
                    avail = sorted(os.listdir(sdir))[-20:]
            except OSError:
                pass
            return {"error": f"artifact 不存在: {artifact_id}",
                    "hint": "该会话最近存档的 artifact：" if avail else "该会话暂无存档",
                    "available": avail}
        offset = max(0, int(offset or 0))
        max_lines = max(1, min(int(max_lines or 200), 2000))
        # 单行 JSON 存档（total_lines=1）同样死路：offset 翻页全空。
        # 与 read_decompiled_file 同款字符切页修复
        _CHAR_PAGE = 4000
        need_split = False
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = []
            total_lines = 0
            for i, line in enumerate(f):
                if len(line) > _CHAR_PAGE:
                    need_split = True
                    chunks = [line[k:k + _CHAR_PAGE]
                              for k in range(0, len(line), _CHAR_PAGE)]
                    for ci, ck in enumerate(chunks):
                        if offset <= total_lines < offset + max_lines:
                            lines.append(f"{ci + 1}| {ck.rstrip(chr(10))}")
                    total_lines += len(chunks)
                    if total_lines > offset + max_lines:
                        break
                else:
                    total_lines += 1
                    if offset <= i < offset + max_lines:
                        lines.append(line.rstrip("\n"))
        result = {
            "artifact_id": artifact_id, "size": os.path.getsize(path),
            "total_lines": total_lines, "offset": offset,
            "content": "\n".join(lines),
        }
        if need_split:
            result["long_line_split"] = True
            result["note"] = "存档含超长行，已按 4000 字符切页；前缀 N| 是同一行的第 N 段"
        if offset + max_lines < total_lines:
            result["next_offset"] = offset + max_lines
            result["note"] = (result.get("note", "") + f"；未读完，用 offset={offset + max_lines} 继续").lstrip("；")
        return result

    async def _tool_search_decompiled(self, appid, pattern, file_glob="*.js",
                                      is_regex=False, max_results=60, context=0):
        """在反编译产物中按关键字/正则搜索（跨文件，带行号与上下文）。

        背景（实测踩坑）：879KB webpack bundle 靠 read_decompiled_file 按 200 行/页
        翻页定位 API 定义层要翻几十页，AI 被迫按 FastAdmin 命名习惯盲猜接口路径
        大量 404。本工具一次搜索直达真实定义（真实命名常与猜测完全不同，
        如 order/list vs order/orderList）。
        """
        import os, re as _re
        root = os.path.join("decompiled", appid.replace("\\", "/").strip("/"))
        if not os.path.isdir(root):
            alt = appid.replace("\\", "/").strip("/")
            root = alt if os.path.isdir(alt) else root
        if not os.path.isdir(root):
            avail = []
            base = "decompiled"
            if os.path.isdir(base):
                avail = sorted(os.listdir(base))[:20]
            return {"error": f"反编译目录不存在: {root}",
                    "hint": "先对目标 appid 执行 decompile_wxapkg；已有解包产物时 available 列出了当前可搜的 appid",
                    "available": avail}
        try:
            rx = _re.compile(pattern if is_regex else _re.escape(pattern),
                             _re.IGNORECASE if not is_regex else 0)
        except _re.error as e:
            return {"error": f"正则无效: {e}"}
        max_results = max(1, min(int(max_results or 60), 200))
        context = max(0, min(int(context or 0), 5))
        # 零命中熔断：连续零命中累计计数，防止 AI 无限换词空转
        # （实测：猜 TS 类型名/字段名连搜 120 次全零命中烧光上下文）
        self._search_miss_seq = getattr(self, "_search_miss_seq", 0)
        glob_rx = _re.compile(
            _re.escape(file_glob).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$")
        hits, scanned = [], 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
            for name in filenames:
                if not glob_rx.match(name):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(full)
                    if size > 30 * 1024 * 1024:
                        continue
                    scanned += 1
                    rel = os.path.relpath(full, root).replace("\\", "/")
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except (OSError, PermissionError):
                    continue
                for i, line in enumerate(lines):
                    if rx.search(line):
                        ctx = []
                        if context:
                            lo = max(0, i - context)
                            hi = min(len(lines), i + context + 1)
                            ctx = [f"{j + 1}: {lines[j].rstrip()[:400]}"
                                   for j in range(lo, hi)]
                        hits.append({"file": rel, "line": i + 1,
                                     "text": line.strip()[:400],
                                     **({"context": ctx} if ctx else {})})
                        if len(hits) >= max_results:
                            break
                if len(hits) >= max_results:
                    break
            if len(hits) >= max_results:
                break
        out = {"ok": True, "root": root, "files_scanned": scanned,
               "count": len(hits), "matches": hits}
        if len(hits) >= max_results:
            out["note"] = f"命中已达上限 {max_results}，收窄 pattern 或 file_glob 再搜"
        if not hits:
            self._search_miss_seq += 1
            # TS 类型名特征：GoodsXxx / xxxInfoResponse 等 PascalCase 复合词，
            # 这类名字只存在于 .d.ts/注释里，压缩后 bundle 里几乎必不存在——
            # 单独点名，别让 AI 继续按类型名规律造词
            words = _re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", pattern)
            looks_type = bool(words) and all(
                w[0].isupper() and _re.search(r"[a-z]", w) for w in words)
            if looks_type:
                out["type_name_warning"] = (
                    f"pattern「{pattern}」是 PascalCase 复合词，疑似 TS 类型名/枚举名——"
                    "这类名字只出现在 .d.ts 或源码注释，压缩 bundle 中几乎必不存在"
                    "（变量名会被混淆，字符串字面量才会保留）。别再按类型名规律造词搜索")
            if self._search_miss_seq == 2:
                # 实测：纪律写「2 次即停」但 AI 在 2-5 次区间仍会继续换词猜
                # （猜参数名 4 轮全错才放弃）。第 2 次零命中即强干预
                out["stop_now"] = True
                out["hint"] = ("已连续 2 次 search_decompiled 零命中——按纪律立即停止换词，"
                               "你猜的词在压缩产物里大概率不存在（变量名已混淆，只有字符串字面量"
                               "保留）。强制改道：extract_identifiers(appid, kind=\"api\"/\"field\", "
                               "keyword=核心词) 拿真实存在的字面量候选 → 拿候选回头精搜或直接 "
                               "get_http_captures 从真实流量取参数。继续换词盲搜只会重复零命中")
            elif self._search_miss_seq >= 6:
                # 熔断：连续 6 次零命中说明「换关键字」路线已死，给降级策略
                out["circuit_breaker"] = True
                out["hint"] = (f"已连续 {self._search_miss_seq} 次 search_decompiled 零命中，"
                               "「换关键字」路线已熔断，禁止继续逐词盲搜。降级策略（按优先级）："
                               "① 用 extract_identifiers 工具从该 bundle 提取真实存在的字符串/URL 候选"
                               "（压缩产物里只有字符串字面量是可靠的）；"
                               "② 改从真实流量取参数：触发一次页面加载后 get_http_captures 看实际请求体；"
                               "③ 代码理解通道：对命中所疑文件 beautify_code 后直接精读（read_decompiled_file "
                               "读美化版），或以已知字面量为锚 get_code_context 展开函数体；"
                               "④ read_decompiled_file 精读接口 URL 首次出现的那一行（搜索接口路径而非字段名）。"
                               "禁止再对同一 bundle 连续猜词")
            else:
                out["hint"] = ("无命中：① 换更可能作为字符串字面量存在的词（接口 URL 片段/字段名，"
                               "而非 TS 类型名——变量名压缩后已混淆）；"
                               "② 放宽 file_glob（*.js 覆盖不到 app-config.json 等配置）；"
                               "③ 连续零命中 6 次将熔断并给出降级策略")
            return out
        self._search_miss_seq = 0
        return out

    async def _tool_extract_identifiers(self, appid, file_glob="*.js",
                                        kind="api", keyword=None, max_results=80):
        """从反编译产物提取真实存在的字符串字面量候选（替代盲猜搜索词）。

        压缩 bundle 里变量名已被混淆，唯一可靠的是字符串字面量。本工具按类别提取：
        api=接口路径片段（/xxx/yyy.json 形态）、url=完整 URL、
        field=疑似请求字段名（"key": 形态的 JSON 键）、str=全部长字符串字面量。
        可用 keyword 过滤（子串匹配，大小写不敏感）。
        """
        import os, re as _re
        from collections import Counter
        root = os.path.join("decompiled", appid.replace("\\", "/").strip("/"))
        if not os.path.isdir(root):
            alt = appid.replace("\\", "/").strip("/")
            root = alt if os.path.isdir(alt) else root
        if not os.path.isdir(root):
            return {"error": f"反编译目录不存在: {root}",
                    "hint": "先对目标 appid 执行 decompile_wxapkg"}
        kind = kind if kind in ("api", "url", "field", "str") else "api"
        max_results = max(1, min(int(max_results or 80), 300))
        kw = (keyword or "").lower()
        # api：路径片段（带/不带前导斜杠都收——压缩 bundle 里 url:"order/save"
        # 形态不带斜杠，只收 "/xxx" 会整文件提取为空）；url：完整 URL；
        # field：JSON 键名（带引号 + 无引号键两种形态）；str：长字符串字面量
        if kind == "api":
            rx = _re.compile(r'"(/[A-Za-z0-9_./-]{4,80})"|"([A-Za-z][A-Za-z0-9_./-]{4,80}/[A-Za-z0-9_./-]{1,60})"')
        elif kind == "url":
            rx = _re.compile(r'"(https?://[A-Za-z0-9_./?=&%-]{8,200})"')
        elif kind == "field":
            rx = _re.compile(r'"([a-z][A-Za-z0-9_]{2,40})"\s*:|[{,]\s*([a-z][A-Za-z0-9_]{2,40})\s*:')
        else:
            rx = _re.compile(r'"([A-Za-z0-9_./:?=&-]{6,120})"')
        glob_rx = _re.compile(
            _re.escape(file_glob).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$")
        counter = Counter()
        where = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
            for name in filenames:
                if not glob_rx.match(name):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(full) > 30 * 1024 * 1024:
                        continue
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except (OSError, PermissionError):
                    continue
                rel = os.path.relpath(full, root).replace("\\", "/")
                for m in rx.finditer(text):
                    v = m.group(1) or m.group(2)  # api/field 双组正则取非空组
                    if not v:
                        continue
                    if kw and kw not in v.lower():
                        continue
                    counter[v] += 1
                    where.setdefault(v, rel)
        # api/field 类：出现次数降序 = 真实高频标识符；url 类保持字典序稳定性即可
        items = counter.most_common(max_results)
        out = {"ok": True, "kind": kind, "root": root,
               "keyword": keyword or "", "unique": len(counter),
               "candidates": [{"value": v, "count": n, "file": where[v]}
                              for v, n in items]}
        if not items:
            out["hint"] = (f"该 bundle 中未提取到 {kind} 类字面量"
                           + (f"（keyword={keyword} 过滤后为空，去掉 keyword 重试）" if kw else "")
                           + "。换 kind（api/url/field/str）或放宽 file_glob")
        return out

    # ── 代码理解通道：字面量检索打不动（签名算法/加密参数/混淆逻辑）时的升级路径 ──
    # search/extract 只能确认「字符串存在」，回答不了「这段代码在干什么」；
    # 本组工具提供 美化 → 函数上下文 → 引用聚类 的代码阅读能力，成果写笔记防蒸发。

    def _resolve_decompiled_path(self, appid: str = "", rel_path: str = "") -> str:
        """解析反编译产物路径（与 read_decompiled_file 同容错规则）。
        兼容三种写法：appid+相对路径 / 只传相对路径（appid 段自含）/ 带 decompiled/ 前缀。
        返回绝对路径；解析不出返回空串"""
        import os
        norm = (rel_path or "").replace("\\", "/").strip("/")

        def _ok(p):
            return p and os.path.isfile(p) or (p and os.path.isdir(p))

        # 写法①带 decompiled/ 前缀 → 剥掉
        parts = norm.split("/")
        if parts and parts[0] == "decompiled":
            norm = "/".join(parts[1:])
        # 写法②appid+相对路径（官方用法）
        if appid:
            p = os.path.join("decompiled", appid.replace("\\", "/").strip("/"),
                             norm.replace("\\", "/"))
            if _ok(p):
                return p
        # 写法③rel_path 自含 appid 首段（wxe123/app-service.js）——
        # beautify_code 实测两种写法都报错就是因为只认②不认③
        p = os.path.join("decompiled", norm.replace("\\", "/"))
        if _ok(p):
            return p
        # 写法④美化缓存直读（.beautified/ 下同名文件）
        if ".beautified" in norm.split("/"):
            p = norm.replace("\\", "/")
            if os.path.isfile(p):
                return p
        return ""

    def _beautified_path(self, abs_path: str) -> str:
        """美化缓存文件路径：decompiled/<appid>/.beautified/<相对路径>.beautified.js"""
        import os
        norm = os.path.normpath(abs_path).replace("/", os.sep)
        low = norm.lower()
        marker = f"{os.sep}decompiled{os.sep}"
        idx = low.find(marker)
        if idx >= 0:
            rel = norm[idx + len(marker):]
        elif low.startswith("decompiled" + os.sep):
            # 相对路径开头形态（_resolve_decompiled_path 返回 decompiled\<appid>\...，
            # 无前导分隔符）——旧版只认绝对路径里的嵌入形态，beautify_code 实测
            # 100% 失败：任何合法路径都报「文件不在 decompiled/ 目录下」（wxa33 实锤）
            rel = norm[len("decompiled") + 1:]
        else:
            return ""
        return os.path.join("decompiled", ".beautified", rel + ".beautified.js")

    async def _tool_beautify_code(self, appid, file_path, force=False):
        """美化压缩 bundle 供后续精读（jsbeautifier：换行/缩进/分号）。

        解决：app-service.js 整文件单行数万字符，read_decompiled_file 分页读进来的
        是不可读的压缩串。美化结果落盘缓存（.beautified/<path>.beautified.js），
        一次投入全程受益；后续 get_code_context / read_decompiled_file 优先读美化版。
        """
        import os
        abs_path = self._resolve_decompiled_path(appid, file_path)
        if not abs_path or not os.path.isfile(abs_path):
            # 找不到时列出候选（decompiled/ 下同目录层级），修「路径写法猜错空转」
            err = {"error": f"文件不存在: appid={appid or '(空)'} file_path={file_path}",
                   "hint": ("传法任选：file_path='wxe123/app-service.js'（自含 appid）或 "
                            "appid='wxe123' + file_path='app-service.js'；"
                            "不要带 decompiled/ 前缀")}
            probe = os.path.join("decompiled", appid) if appid else "decompiled"
            for d in (probe, "decompiled"):
                if os.path.isdir(d):
                    try:
                        err["dir_listing"] = {"dir": d,
                                              "entries": sorted(os.listdir(d))[:60]}
                    except OSError:
                        pass
                    break
            return err
        if os.path.getsize(abs_path) > 20 * 1024 * 1024:
            return {"error": "文件超过 20MB，过大不宜整体美化",
                    "hint": "先用 search_decompiled 定位目标区域，对更小粒度的文件美化"}
        out_path = self._beautified_path(abs_path)
        if not out_path:
            return {"error": "文件不在 decompiled/ 目录下，无法建立美化缓存"}
        if os.path.isfile(out_path) and not force:
            return {"ok": True, "cached": True, "beautified_file": out_path.replace("\\", "/"),
                    "lines": sum(1 for _ in open(out_path, encoding="utf-8", errors="ignore")),
                    "note": "已有美化缓存，直接 read_decompiled_file 或 get_code_context 该文件"}
        try:
            import jsbeautifier
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            pretty = jsbeautifier.beautify(src, opts)
        except ImportError:
            return {"error": "缺少 jsbeautifier，先 pip install jsbeautifier（或重启后端让依赖生效）"}
        except Exception as e:
            return {"error": f"美化失败（文件可能不是合法 JS）: {str(e)[:200]}"}
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(pretty)
        n_lines = pretty.count("\n") + 1
        return {"ok": True, "cached": False, "beautified_file": out_path.replace("\\", "/"),
                "original_chars": len(src), "beautified_lines": n_lines,
                "note": "美化完成。后续 read_decompiled_file 直接传美化版路径分页精读；"
                        "get_code_context 用原始文件里的字面量锚点取函数体"}

    async def _tool_get_code_context(self, appid, anchor, file_path="",
                                     before_lines=40, after_lines=60, beautified=True):
        """按字面量锚点返回包裹它的函数体/代码块（而非死板 N 行）。

        用法：search_decompiled 命中 "X-Localid-Flag" 在某行 → 以它为 anchor 调本工具，
        返回包含它的完整函数——签名算法、参数拼接、密钥来源一目了然。
        beautified=true 优先在美化缓存里找锚点（推荐先 beautify_code）；
        找不到锚点时自动降级为锚点±行数窗口。
        """
        import os, re as _re
        before_lines = max(5, min(int(before_lines or 40), 200))
        after_lines = max(5, min(int(after_lines or 60), 400))
        candidates = []
        if beautified:
            bp = self._beautified_path(self._resolve_decompiled_path(appid, file_path)) if file_path else ""
            if bp and os.path.isfile(bp):
                candidates.append(bp)
        if file_path:
            fp = self._resolve_decompiled_path(appid, file_path)
            if fp and os.path.isfile(fp):
                candidates.append(fp)
        else:
            root = self._resolve_decompiled_path(appid, "")
            if root and os.path.isdir(root):
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [d for d in dirnames if d != ".beautified"]
                    for name in filenames:
                        if name.endswith((".js", ".json", ".wxml")):
                            candidates.append(os.path.join(dirpath, name))
                    if len(candidates) > 3000:
                        break
        if not candidates:
            return {"error": f"未找到可读文件（appid={appid}, file_path={file_path or '未指定'}）",
                    "hint": "未指定 file_path 时全库扫描较慢且可能截断，"
                            "建议先 search_decompiled 拿到命中文件再指定"}
        anchor_rx = _re.compile(_re.escape(anchor), _re.IGNORECASE)
        func_head = _re.compile(
            r"(?:^|[;\n\r])\s*(?:(?:async\s+)?function\s+\w+|(?:var|let|const)\s+\w+\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)|\w+\s*[:=]\s*(?:async\s*)?function)")
        block_open = None
        for path in candidates:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, PermissionError):
                continue
            hit, hits_all = None, []
            for i, line in enumerate(lines):
                if anchor_rx.search(line):
                    if hit is None:
                        hit = i
                    hits_all.append(i)
            if hit is None:
                continue
            # 单行超长文件（压缩 bundle）专用路径：整文件 1 行时函数头/括号配平
            # 启发式全部失效（实测固定返回文件开头的 WXML 渲染块），改字符窗口——
            # 锚点命中位置前后各取一段，宁可粗也不返回无关代码块
            if len(lines[hit]) > 20000:
                text = lines[hit]
                pos = anchor_rx.search(text).start()
                win = max(before_lines, after_lines) * 60  # 行数参数折算字符量
                s = max(0, pos - win)
                e = min(len(text), pos + len(anchor) + win)
                # 窗口边缘截断在语句中间会误导阅读：向内收缩到最近的 ;/} 边界
                while s > 0 and text[s - 1] not in ";}\n":
                    s -= 1
                while e < len(text) and text[e] not in ";}\n":
                    e += 1
                body = text[s:e]
                return {
                    "ok": True, "file": os.path.relpath(path, "decompiled").replace("\\", "/"),
                    "lines": [1, 1], "anchor_hit_at": 1,
                    "char_window": [s, e], "total_chars": len(text),
                    "is_beautified": path.endswith(".beautified.js"),
                    "chars": len(body),
                    "code": body,
                    "note": "单行压缩 bundle：按锚点字符窗口提取（行级函数边界在此文件形态下不可用）。"
                            "窗口边缘按 ;/} 收缩。需要完整函数体时先 beautify_code 该文件再重试",
                }
            # 函数边界启发式：从锚点向上找函数头（找不到退化为 ±窗口），向下按大括号配平找函数尾
            start = max(0, hit - before_lines)
            for j in range(hit, max(-1, hit - 400), -1):
                if func_head.search(lines[j]):
                    start = j
                    break
            end = min(len(lines), hit + after_lines)
            depth, seen_open = 0, False
            for j in range(start, len(lines)):
                for ch in lines[j]:
                    if ch in "{[(":
                        depth += 1
                        seen_open = True
                    elif ch in "}])":
                        depth -= 1
                if seen_open and depth <= 0:
                    end = j + 1
                    break
            else:
                end = min(len(lines), hit + after_lines)
            # 美化文件里锚点命中时同时给出原始文件行号，方便回溯 search 结果
            src_line = ""
            if path.endswith(".beautified.js") and file_path:
                fp = self._resolve_decompiled_path(appid, file_path)
                if fp and os.path.isfile(fp):
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            for i, line in enumerate(f):
                                if anchor_rx.search(line):
                                    src_line = f"原始文件 {file_path}:{i + 1}"
                                    break
                    except OSError:
                        pass
            body = "".join(lines[start:end])
            rel = os.path.relpath(path, "decompiled").replace("\\", "/")
            # 多处命中提示：短通用词锚点常在无关文件/无关行先命中（wxa33 实测
            # search 报 7823 行、本工具返回 7673 行 wxParse 内容，错位无提示），
            # 列出全部命中行号让错位一眼可见，AI 可换更长锚点或指定 file_path
            multi_note = ""
            if len(hits_all) > 1:
                multi_note = (f"；注意：锚点在本文件共命中 {len(hits_all)} 行"
                              f"（行号 {[h + 1 for h in hits_all[:10]]}），本返回取首处——"
                              "与 search_decompiled 行号对不上时换更长锚点或指定 file_path")
            return {
                "ok": True, "file": rel,
                "lines": [start + 1, end],
                "anchor_hit_at": hit + 1,
                "source_ref": src_line,
                "is_beautified": path.endswith(".beautified.js"),
                "chars": len(body),
                "code": body,
                "note": "以上是包含锚点的函数/代码块。分析签名/加密算法时：找出哈希函数名、"
                        "参数拼接顺序、密钥来源（变量名/常量），再用 find_references 跟密钥赋值处；"
                        "结论务必 save_notes 沉淀，防止上下文压缩后丢失" + multi_note,
            }
        # 所有候选都没命中
        return {"error": f"锚点「{anchor}」未命中任何文件",
                "hint": "锚点须是源码里真实存在的字面量（先用 search_decompiled 确认），"
                        "且若 beautified=true 需已对该文件 beautify_code（未美化时传 beautified=false 直接搜原始文件）"}

    async def _tool_find_references(self, appid, symbol, file_glob="*.js", max_results=60):
        """跨文件引用聚类：把符号/字面量的出现按 定义/赋值/使用 分档展示。

        用于跟调用链与数据流：签名函数名 → 谁调用它；密钥变量 → 在哪赋值/初始化。
        """
        import os, re as _re
        root = self._resolve_decompiled_path(appid, "")
        if not root or not os.path.isdir(root):
            return {"error": f"反编译目录不存在: {root or 'decompiled/' + appid}",
                    "hint": "先对目标 appid 执行 decompile_wxapkg"}
        max_results = max(10, min(int(max_results or 60), 200))
        sym_rx = _re.compile(_re.escape(symbol))
        def_rx = _re.compile(r"(?:function\s+" + _re.escape(symbol) + r"\b|(?:var|let|const)\s+"
                             + _re.escape(symbol) + r"\s*=|\w+\s*[:=]\s*" + _re.escape(symbol) + r"\s*=\s*(?:function|\w))")
        assign_rx = _re.compile(r"(?:var|let|const)\s+" + _re.escape(symbol) + r"\b|\.\s*"
                                + _re.escape(symbol) + r"\s*=[^=]")
        refs = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".beautified")]
            for name in filenames:
                if not (name.endswith(".js") if file_glob == "*.js" else True):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(full) > 30 * 1024 * 1024:
                        continue
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f):
                            if sym_rx.search(line):
                                rel = os.path.relpath(full, root).replace("\\", "/")
                                if def_rx.search(line):
                                    kind = "definition"
                                elif assign_rx.search(line):
                                    kind = "assignment"
                                else:
                                    kind = "usage"
                                refs.append({"file": rel, "line": i + 1, "kind": kind,
                                             "text": line.strip()[:300]})
                                if len(refs) >= max_results * 3:
                                    break
                except (OSError, PermissionError):
                    continue
                if len(refs) >= max_results * 3:
                    break
            if len(refs) >= max_results * 3:
                break
        # 聚类排序：definition 优先，其次 assignment，最后 usage；同档按文件+行号
        order = {"definition": 0, "assignment": 1, "usage": 2}
        refs.sort(key=lambda r: (order[r["kind"]], r["file"], r["line"]))
        refs = refs[:max_results]
        by_kind = {k: sum(1 for r in refs if r["kind"] == k) for k in order}
        out = {"ok": True, "symbol": symbol, "total_shown": len(refs), "by_kind": by_kind,
               "references": refs}
        if not refs:
            out["hint"] = (f"符号「{symbol}」零命中：压缩 bundle 里变量名已被混淆成短名，"
                           "变量/函数名引用大概率查不到——改搜字符串字面量（URL/字段名/常量）；"
                           "若要跟数据流，可在字面量命中处 get_code_context 看上下文里的局部变量名")
        else:
            out["note"] = ("definition=定义处 / assignment=赋值处 / usage=使用处。"
                           "跟密钥/配置来源：优先看 assignment 行的右值；"
                           "理解调用链：usage 里的文件分布说明被谁引用。分析结论 save_notes 沉淀")
        return out

    def _task_notes(self) -> list:
        """当前任务会话的笔记列表（按 sid 隔离——跨会话泄漏教训见 __init__ 注释）"""
        sid = getattr(self, "_task_sid", None) or self.current_sid
        if not sid:
            return []
        store = self._notes_store if isinstance(self._notes_store, dict) else {}
        notes = store.get(sid)
        if not isinstance(notes, list):
            notes = []
            store[sid] = notes
        return notes

    async def _tool_save_notes(self, title, content, category="analysis"):
        """把阶段性分析结论写进会话笔记（永不被上下文压缩，每轮注入视野）。

        典型沉淀：签名算法还原结论（sign=md5(body+ts, key=storage.session_key)）、
        密钥来源、已验证的接口契约、误判修正记录。content 用一行一个结论的短句。
        """
        title, content = str(title).strip()[:80], str(content).strip()[:3000]
        if not title or not content:
            return {"error": "title 和 content 必填；content 一行一个结论短句"}
        notes = self._task_notes()
        # 同标题覆盖更新（迭代修正同一结论时不会堆重复条目）
        for n in notes:
            if n["title"] == title:
                n["content"] = content
                n["category"] = category
                n["updated_at"] = time.strftime("%H:%M:%S")
                self._save_json_file(self._notes_path, self._notes_store)
                return {"ok": True, "updated": True, "total_notes": len(notes),
                        "note": "同名笔记已更新（迭代修正覆盖旧版）"}
        notes.append({"title": title, "content": content, "category": category,
                      "ts": time.strftime("%H:%M:%S")})
        self._save_json_file(self._notes_path, self._notes_store)
        return {"ok": True, "total_notes": len(notes),
                "note": "已写入会话笔记，后续每轮自动注入你的视野，不会被上下文压缩丢掉"}

    async def _tool_get_notes(self):
        """读取当前全部会话笔记（一般不用主动调——笔记每轮自动注入）"""
        notes = self._task_notes()
        return {"ok": True, "total": len(notes), "notes": notes}

    def _notes_block(self) -> str:
        """渲染笔记注入块（进 send view 的 system 后补段；只注入当前任务会话自己的笔记）"""
        notes = self._task_notes()
        if not notes:
            return ""
        lines = [f"- [{n['category']}] {n['title']}（{n['ts']}）：{n['content']}"
                 for n in notes]
        return ("## 会话笔记（AI 沉淀的分析结论，跨轮次有效，禁止凭记忆推翻——"
                "要修正请用 save_notes 同名覆盖）\n" + "\n".join(lines))

    # ── C1 Skill 按需加载：正文走计划/笔记同通道注入（system 后补段，跨压缩存活）──

    def _skill_block(self) -> str:
        """渲染已加载 Skill 正文注入块（load_skill 调用后生效，release_skill 卸载）"""
        sid = getattr(self, "_task_sid", None) or self.current_sid
        loaded = (self._loaded_skills_store.get(sid) or {}) if sid else {}
        if not loaded:
            return ""
        blocks = []
        for name in loaded:
            prompt = str((self._skills_by_name_get(name) or {}).get("prompt", "") or "").strip()
            if prompt:
                blocks.append(f"### Skill: {name}\n{prompt}")
        if not blocks:
            return ""
        return ("## 已加载 Skill 方法论（load_skill 注入，测试时严格按此执行；"
                "用完 release_skill 卸载）\n\n" + "\n\n".join(blocks))

    def _skills_by_name(self) -> dict:
        """启用中的 Skill 按名称索引（每次现查，前端启停即时生效）"""
        try:
            return {s.get("name", ""): s for s in (self.state.enabled_skills() or [])}
        except Exception:
            return {}

    def _skills_by_name_get(self, name):
        return self._skills_by_name().get(name)

    async def _tool_load_skill(self, name):
        """按名称加载 Skill 正文进视野（按需加载，替代 system 全量常驻）"""
        name = str(name or "").strip()
        s = self._skills_by_name_get(name)
        if not s:
            avail = "、".join(list(self._skills_by_name().keys())[:20]) or "无"
            return {"error": f"Skill「{name}」不存在或未启用", "available": avail}
        sid = getattr(self, "_task_sid", None) or self.current_sid
        if not sid:
            return {"error": "无活动会话，无法加载 Skill"}
        loaded = self._loaded_skills_store.setdefault(sid, {})
        loaded[name] = True
        plen = len(str(s.get("prompt", "") or ""))
        return {"ok": True, "name": name, "prompt_chars": plen,
                "note": f"Skill「{name}」正文已注入视野（{plen} 字），本功能点测试期间严格遵循其方法论；"
                        "测试完 save_notes 沉淀结论后建议 release_skill 卸载"}

    async def _tool_release_skill(self, name):
        """卸载已加载的 Skill 正文（释放注意力空间；结论应先 save_notes 沉淀）"""
        name = str(name or "").strip()
        sid = getattr(self, "_task_sid", None) or self.current_sid
        loaded = (self._loaded_skills_store.get(sid) or {}) if sid else {}
        if name and name in loaded:
            del loaded[name]
            return {"ok": True, "name": name, "note": "已卸载；关键结论应已 save_notes 沉淀"}
        return {"ok": True, "name": name, "note": "该 Skill 本就未加载"}

    # ── 长任务管理：任务计划（Letta core memory 式常驻块）──

    def _plan_for(self, sid: str) -> dict:
        """取会话任务计划，无则返回空结构"""
        plan = (getattr(self, "_plans", {}) or {}).get(sid)
        if not isinstance(plan, dict):
            return {"goal": "", "items": [], "updated_at": ""}
        return plan

    def _save_plan(self, sid: str, plan: dict):
        self._plans = getattr(self, "_plans", {}) or {}
        self._plans[sid] = plan
        self._save_json_file(self._plans_path, self._plans)

    def _plan_block(self, sid: str) -> str:
        """渲染任务计划注入块（与笔记同通道，压缩打不掉）"""
        plan = self._plan_for(sid)
        if not plan.get("goal") and not plan.get("items"):
            return ""
        lines = [f"## 任务计划（常驻视野，跨压缩存活——完成一项立即 plan_update 打勾，"
                 f"方向变了用 plan_set 重写；禁止凭记忆宣称某项已完成，以此处为准）"]
        if plan.get("goal"):
            lines.append(f"目标：{plan['goal']}")
        mark = {"done": "✅", "doing": "▶", "pending": "○", "blocked": "⛔"}
        for it in plan.get("items", []):
            lines.append(f"{mark.get(it.get('status', 'pending'), '○')} "
                         f"{it.get('text', '')}" + (f"　← {it.get('note')}" if it.get("note") else ""))
        return "\n".join(lines)

    async def _tool_plan_set(self, goal, items=None):
        """建立/重写当前会话的任务计划（全流程测试开工时先建，方向调整时重写）。

        items 是子任务列表（计划导向，区别于 save_notes 的结论导向）：
        每项 {"text": "子任务描述", "status": "pending|doing|done|blocked", "note": "备注可选"}。
        计划每轮注入视野、跨上下文压缩与进程重启存活——这是压缩后恢复方向的锚点。
        """
        goal = str(goal).strip()[:200]
        if not goal:
            return {"error": "goal 必填"}
        items_out = []
        for it in (items or [])[:20]:
            if isinstance(it, str):
                it = {"text": it}
            if not isinstance(it, dict) or not str(it.get("text", "")).strip():
                continue
            items_out.append({"text": str(it["text"]).strip()[:150],
                              "status": it.get("status") if it.get("status") in
                                        ("pending", "doing", "done", "blocked") else "pending",
                              "note": str(it.get("note", ""))[:150]})
        sid = getattr(self, "_task_sid", None) or self.current_sid
        if not sid:
            return {"error": "无活动会话"}
        self._save_plan(sid, {"goal": goal, "items": items_out,
                              "updated_at": time.strftime("%m-%d %H:%M")})
        return {"ok": True, "goal": goal, "items": items_out,
                "note": "计划已建立并常驻视野。完成一项立即 plan_update 打勾；"
                        "每完成一项建议顺手 save_notes 沉淀结论"}

    async def _tool_plan_update(self, index, status=None, note=None):
        """更新任务计划某一项的状态（进度打勾/标记阻塞/加备注）。

        index 为 plan_set 建立的子任务序号（从 1 开始）。status: doing/done/blocked/pending。
        这是压缩后唯一可靠的进度事实来源——禁止凭记忆报进度。
        """
        sid = getattr(self, "_task_sid", None) or self.current_sid
        plan = self._plan_for(sid) if sid else {"items": []}
        if not plan.get("items"):
            return {"error": "当前会话还没有任务计划，先 plan_set 建立",
                    "hint": "全流程测试开工第一步就应建计划：目标 + 子任务列表"}
        idx = int(index or 0) - 1
        if idx < 0 or idx >= len(plan["items"]):
            return {"error": f"index 超范围（1~{len(plan['items'])}）",
                    "current_plan": plan}
        it = plan["items"][idx]
        if status in ("doing", "done", "blocked", "pending"):
            it["status"] = status
        if note is not None:
            it["note"] = str(note).strip()[:150]
        self._save_plan(sid, plan)
        # 全部完成时提示收尾
        remaining = sum(1 for i in plan["items"] if i["status"] not in ("done",))
        return {"ok": True, "item": it, "remaining": remaining,
                "plan_digest": "；".join(f"{i+1}.{x['status']}:{x['text']}"
                                         for i, x in enumerate(plan["items"])),
                "note": ("全部子任务完成——确认无遗漏后可生成测试报告收尾" if remaining == 0
                         else f"还有 {remaining} 项未完成，继续按计划推进")}

    # ── 长任务管理：StuckDetector（OpenHands 循环卡死探测）──
    # 渗透任务的典型死循环：对同一接口反复发同样的包、反复 tap 同一失败元素。
    # 规则：近 N 次工具调用（工具名+参数指纹）重复 ≥3 次即提醒换策略，不打断任务

    _STUCK_WINDOW = 8      # 观察窗口：最近 8 次工具调用
    _STUCK_REPEAT = 3      # 同指纹出现 ≥3 次判定卡死

    def _check_stuck(self, tool_name: str, arguments: dict) -> str:
        """滑动窗口指纹重复检测。返回提醒文本（未卡死返回空串）。

        指纹=工具名+规范化参数 JSON（剔除时间戳类随机字段），窗口内同指纹
        出现次数达阈值即触发。提醒注入发送视图，不修改 history。
        """
        import hashlib
        self._stuck_window = getattr(self, "_stuck_window", [])
        try:
            norm = {k: v for k, v in (arguments or {}).items()
                    if not any(t in k.lower() for t in ("ts", "time", "nonce", "rand"))}
            fp = hashlib.md5(json.dumps(
                [tool_name, norm], ensure_ascii=False, sort_keys=True,
                default=str).encode()).hexdigest()
        except Exception:
            return ""
        self._stuck_window.append(fp)
        self._stuck_window = self._stuck_window[-self._STUCK_WINDOW:]
        # 同指纹在窗口内出现 ≥_STUCK_REPEAT 次
        if self._stuck_window.count(fp) >= self._STUCK_REPEAT:
            self._stuck_window.clear()   # 清窗防连续轰炸：处理一轮后再观察
            self._stuck_hits = getattr(self, "_stuck_hits", 0) + 1
            return (f"⏰ 卡死警报（第 {self._stuck_hits} 次）：最近 {self._STUCK_WINDOW} 次工具调用中"
                    f"「{tool_name}」用完全相同的参数已重复 ≥{self._STUCK_REPEAT} 次，"
                    "结果大概率不变。必须换策略：① 换参数/换入口；② 用 get_capture_detail/"
                    "get_code_context 等分析工具找新线索；③ 该方向此路不通时 plan_update 标记 "
                    "blocked 换下一项。不要继续原样重试")
        return ""

    # ── L1 同目标失败熔断：StuckDetector 只认「同工具+同参数」，盲猜接口前缀的
    # 404 换前缀再猜参数每次都不同，永不触发。这里是并列的第二只眼：同一目标
    # （URL 主干/接口名）连续失败达阈值即强制提醒，堵实测最大的上下文浪费漏点

    _TFAIL_WINDOW = 8       # 观察窗口：最近 8 次工具调用
    _TFAIL_LIMIT = 5        # 同目标连续失败 ≥5 次触发熔断提醒

    def _target_key(self, tool_name: str, arguments: dict, result_str: str) -> str:
        """从工具调用中提取「目标键」：URL 主干 > 接口路径段 > 工具名+首个关键参数"""
        url = self._req_url(result_str[:4000]) or ""
        for a in (arguments or {}).values():
            s = str(a or "")
            if s.startswith(("http://", "https://", "/")):
                if not url:
                    url = s
                break
        # 目标键合法性门槛（实测 bug：请求行残缺时 _req_url 会捞出「false,」
        # 这类碎片当 URL，熔断提醒变成「目标『false,』已连续失败」）——
        # 非 URL/路径形态、含逗号花括号空白的一律不作目标
        if url:
            if "://" not in url and not url.startswith("/"):
                url = ""
            elif re.search(r"[\s,，{}<>\"']", url.split("?")[0]):
                url = ""
        if url:
            m = re.match(r"https?://[^/]+(/[^?]*?)?/?$", url.split("?")[0])
            path = (m.group(1) if m and m.group(1) else "") or "/"
            host = re.sub(r"^https?://", "", url.split("?")[0]).split("/")[0]
            return f"{host}{path.rstrip('/')}"
        # 无 URL：接口路径段或文件路径类参数当目标
        for a in (arguments or {}).values():
            s = str(a or "")
            if re.search(r"[\s,，{}]", s):
                continue  # 含逗号/花括号/空白的碎片不是目标（同上实测 bug）
            if 3 <= len(s) <= 120 and re.match(r"^[\w./\-]+$", s) and "/" in s or s.startswith("/"):
                return f"{tool_name}:{s}"
        return ""

    def _check_target_failure(self, tool_name: str, arguments: dict, result_str: str) -> str:
        """同目标连续失败滑动窗口检测。返回提醒文本（未触发返回空串）。

        与 _check_stuck 并列：指纹按「目标键」而非工具+参数——同目标不同参数
        的连续失败（盲猜接口前缀 404 换前缀再猜）正是此前的检测盲区。
        """
        try:
            tk = self._target_key(tool_name, arguments, result_str)
            if not tk:
                return ""
            # 失败判定（实测 bug：`"failed": false` 即成功的回执被裸 failed 词
            # 误判成失败）——带值的 JSON 键必须看值：false/0/"0"/"" 都不是失败
            fail = bool(re.search(
                r'"(?:status|http_status)"\s*:\s*(?:40[0-9]|5\d\d)|'
                r'"(?:error|failed)"\s*:\s*(?!"false"|false|0)[\w\-"]|'
                r'(?<![:\w"])(?:error|failed)\s*[:=]\s*(?!false\b)(?!"false\b")\S|'
                r'"ok"\s*:\s*false|失败|不存在|未找到|无数据|denied|refused|timeout',
                result_str[:3000], re.I))
            self._tfail_window = getattr(self, "_tfail_window", [])
            self._tfail_window.append({"tk": tk, "fail": fail})
            self._tfail_window = self._tfail_window[-self._TFAIL_WINDOW:]
            # 只看该目标最近的连续失败段
            streak = 0
            for rec in reversed(self._tfail_window):
                if rec["tk"] != tk:
                    break
                if not rec["fail"]:
                    break
                streak += 1
            if streak >= self._TFAIL_LIMIT:
                self._tfail_window.clear()
                self._tfail_hits = getattr(self, "_tfail_hits", 0) + 1
                return (f"🚫 同目标失败熔断（第 {self._tfail_hits} 次）：目标「{tk}」已连续失败 "
                        f"{streak} 次。停止继续盲试该目标——① 改用 search_decompiled(appid, "
                        "关键字)/find_references 从源码定位真实接口定义，源码里也搜不到再用 "
                        "UI 触发一次抓包确认路径；② 确认该功能此路不通时 registry_update_state "
                        "标 skipped 或 plan_update 标 blocked，不要再烧上下文")
            return ""
        except Exception:
            return ""

    async def _tool_navigate(self, route):
        import asyncio as _aio
        blk = self._guard_miniapp_conn("navigate_to")
        if blk:
            return blk
        if not route.startswith("/"):
            route = "/" + route
        target = route.split("?", 1)[0].rstrip("/") or "/"
        # 导航前记录栈深：navigateTo 成功栈深应 +1（空壳页假成功时栈深不变，
        # 实测 verified:true 但栈顶根本没换）。栈读失败记 -1，无法参与校验
        async def _stack_len():
            try:
                js = ("(() => { const f = " + self._WX_FRAME_EXPR + ";"
                      " if (!f) return -1;"
                      " const ps = f.getCurrentPages ? f.getCurrentPages() : [];"
                      " return ps.length; })()")
                r = await self.engine.evaluate_js(js, timeout=5.0)
                v = self._extract_value(r)
                n = int(v) if str(v).strip().lstrip("-").isdigit() else -1
                return n
            except Exception:
                return -1
        depth_before = await _stack_len()
        # tab 页目标走 wx.switchTab（nav_inject.js goTo 分流），switchTab 本就不入栈、
        # 栈深不变是合法行为——栈深校验只对 navigateTo 有效，tab 页跳过
        _tb_norm = [str(p).lstrip("/").split("?", 1)[0].rstrip("/") for p in (self.navigator.tab_bar_pages or [])]
        is_tab_target = target.lstrip("/") in _tb_norm
        await self.navigator.navigate_to(route)
        # ── 假成功验证：navigateTo:ok 可能只是壳回执（逻辑层冻结/webview 卡栈时
        # 页面实际不变）。导航后读栈顶核对，栈顶没变 → 自动 reLaunch 兜底一次 ──
        self._nav_seq = getattr(self, "_nav_seq", 0) + 1

        async def _stack_top():
            try:
                js = ("(() => { const f = " + self._WX_FRAME_EXPR + ";"
                      " if (!f) return '';"
                      " const ps = f.getCurrentPages ? f.getCurrentPages() : [];"
                      " if (!ps.length) return '';"
                      " const c = ps[ps.length - 1];"
                      " return (c.route || c.__route__ || ''); })()")
                r = await self.engine.evaluate_js(js, timeout=5.0)
                raw = self._extract_value(r)
                return (raw or "").strip().lstrip("/").split("?", 1)[0].rstrip("/")
            except Exception:
                return None  # 读取失败 ≠ 没变（可能只是慢），不判假成功

        await _aio.sleep(0.8)  # 等页面切换落定
        top = await _stack_top()
        depth_after = await _stack_len()
        verified = False
        fallback = ""

        # ── 逻辑层直调兜底（比 reLaunch 温和，保留当前页面栈）──
        # nav_inject.goTo 只送一次调用，webview 卡栈/逻辑层忙时可能被吞（ok 回执但没执行）。
        # 这里直接经逻辑层 wx API 再补一次调用，轮询栈顶等待真实变化
        async def _fallback_navigate():
            fb = ""
            try:
                if is_tab_target:
                    await self.wxapi.replay("switchTab", {"url": route})
                    fb = "switchTab(逻辑层)"
                else:
                    await self.wxapi.replay("navigateTo", {"url": route})
                    fb = "navigateTo(逻辑层)"
            except Exception as e:
                return None, f"逻辑层直调失败: {str(e)[:120]}"
            # 轮询栈顶，最多等 3 秒直到真变化
            for _ in range(6):
                await _aio.sleep(0.5)
                t2 = await _stack_top()
                if t2 is not None and t2 != "" and t2 == target.lstrip("/"):
                    return True, fb
                # 栈顶变到别的页了（可能 redirectTo 中转），也停止重试
                if t2 is not None and t2 != "" and t2 != target.lstrip("/") and t2 != (top or ""):
                    return False, fb + f"（栈顶变为 {t2}）"
            return False, fb + "（直调后栈顶未变）"

        # ── reLaunch 终极兜底（能踢出卡死的页面栈）──
        async def _relaunch_fallback(reason):
            try:
                await self.navigator.relaunch_to(route)
                self._nav_seq += 1
                await _aio.sleep(0.8)
                t3 = await _stack_top()
                return bool(t3 is not None and t3 == target.lstrip("/")), f"reLaunch（{reason}）"
            except Exception as e:
                return False, f"reLaunch 失败: {str(e)[:120]}"

        if top is not None and top != "" and top == target.lstrip("/"):
            # 栈顶已到目标页。再校验栈深变化：navigateTo 期望 +1；
            # 栈深不变且栈读可用 = 空壳回执（页面实例没真正入栈）
            # tab 页经 switchTab 到达时栈深不变是正常的，不参与栈深校验
            if (not is_tab_target and depth_before >= 0 and depth_after >= 0
                    and depth_after == depth_before):
                verified = False
                fallback = "栈深未变化，页面实例未入栈（空壳回执）"
            else:
                verified = True
        elif top is not None and top != "" and top != target.lstrip("/"):
            # 栈顶与目标不一致 → 假成功。两级兜底：先逻辑层直调（温和），
            # 仍失败再 reLaunch 强制重建页面栈
            v1, fb1 = await _fallback_navigate()
            if v1:
                verified = True
                fallback = fb1
            else:
                verified, fallback = await _relaunch_fallback(f"栈顶 {top} != 目标；" + fb1)
        else:
            # 栈顶读不到（None/空）：无法证明到达，不再乐观 verified=True
            # （空壳页假成功正是从这条乐观路径漏过）→ 逻辑层直调兜底再验
            v1, fb1 = await _fallback_navigate()
            if v1:
                verified = True
                fallback = fb1
            else:
                verified, fallback = await _relaunch_fallback("栈顶读取失败；" + fb1)
        # 页面遍历跟踪：仅在验证真实到达后计 visited；无法验证/假成功不标记
        # （此前的乐观标记曾让空壳页混进页面覆盖度）
        if verified:
            try:
                self.feature_registry.mark_page_visited(route)
            except Exception:
                pass
        out = {"ok": verified, "navigated_to": route, "verified": verified,
               "stack_top": top or None,
               "hint": ("到页后 ui_snapshot 拍全元素再逐入口点击；"
                        if verified else
                        "⚠️ 导航验证未通过：栈顶不是目标页（假成功）。页面可能被 webview/逻辑层冻结卡死："
                        "改用 replay_api 直调 wx.navigateTo/navigateBack；连续 2 次失败用 get_page_state "
                        "查逻辑层活性（连续两次返回完全一致即冻结），冻结时重启小程序进程再继续")}
        if fallback:
            out["fallback"] = fallback
        return out

    async def _tool_switch_tab(self, route):
        """逻辑层 wx.switchTab 直切 tab 页（渲染层 UI 点击失效时的导航通道）。

        与 navigate_to 的区别：绕过渲染层 nav_inject 桥，直接经逻辑层 wx API
        调用（wxapi.replay），适用于 webview 卡栈/tabbar 元素点不到的场景。
        """
        import asyncio as _aio
        blk = self._guard_miniapp_conn("switch_tab")
        if blk:
            return blk
        if not route.startswith("/"):
            route = "/" + route
        target = route.split("?", 1)[0].rstrip("/")
        # 校验目标确实是 tab 页：switchTab 只接受 tabBar 页面
        tb = [str(p).lstrip("/").split("?", 1)[0].rstrip("/") for p in (self.navigator.tab_bar_pages or [])]
        if tb and target.lstrip("/") not in tb:
            return {"ok": False, "error": f"{target} 不在 tabBar 页列表里，switchTab 会失败",
                    "tab_bar_pages": tb,
                    "hint": "非 tab 页用 navigate_to（走 navigateTo）；当前 tab 列表如上"}
        async def _stack_top():
            try:
                js = ("(() => { const f = " + self._WX_FRAME_EXPR + ";"
                      " if (!f) return '';"
                      " const ps = f.getCurrentPages ? f.getCurrentPages() : [];"
                      " if (!ps.length) return '';"
                      " const c = ps[ps.length - 1];"
                      " return (c.route || c.__route__ || ''); })()")
                r = await self.engine.evaluate_js(js, timeout=5.0)
                raw = self._extract_value(r)
                return (raw or "").strip().lstrip("/").split("?", 1)[0].rstrip("/")
            except Exception:
                return None
        r = await self.wxapi.replay("switchTab", {"url": route})
        # 轮询栈顶核对（最多 3 秒），switchTab 成功栈顶必变
        top0 = await _stack_top()
        verified = False
        for _ in range(6):
            await _aio.sleep(0.5)
            top = await _stack_top()
            if top is not None and top != "" and top == target.lstrip("/"):
                verified = True
                break
            if top is not None and top != "" and top != target.lstrip("/") and top != top0:
                break  # 栈顶变到别的页了
        self._nav_seq = getattr(self, "_nav_seq", 0) + 1
        out = {"ok": verified, "switched_to": route, "verified": verified,
               "stack_top": top or top0 or None,
               "api_receipt": r,
               "hint": ("到页后 ui_snapshot 拍全元素再逐入口点击" if verified else
                        "⚠️ switchTab 直调后栈顶未变：逻辑层可能冻结（用 get_page_state 连读两次核对），"
                        "或目标页有 onShow 拦截。仍失败时用 reconnect_engine 重附加引擎")}
        if verified:
            try:
                self.feature_registry.mark_page_visited(route)
            except Exception:
                pass
        return out

    async def _tool_navigate_back(self, delta=1):
        """逻辑层 wx.navigateBack 返回上一页（webview H5 卡栈时退出用）"""
        import asyncio as _aio
        blk = self._guard_miniapp_conn("navigate_back")
        if blk:
            return blk
        delta = max(1, int(delta or 1))
        async def _stack_top():
            try:
                js = ("(() => { const f = " + self._WX_FRAME_EXPR + ";"
                      " if (!f) return '';"
                      " const ps = f.getCurrentPages ? f.getCurrentPages() : [];"
                      " if (!ps.length) return '';"
                      " const c = ps[ps.length - 1];"
                      " return (c.route || c.__route__ || ''); })()")
                r = await self.engine.evaluate_js(js, timeout=5.0)
                raw = self._extract_value(r)
                return (raw or "").strip().lstrip("/").split("?", 1)[0].rstrip("/")
            except Exception:
                return None
        before = await _stack_top()
        await self.wxapi.replay("navigateBack", {"delta": delta})
        await _aio.sleep(0.8)
        after = await _stack_top()
        self._nav_seq = getattr(self, "_nav_seq", 0) + 1
        changed = bool(before is not None and after is not None
                       and before != "" and after != "" and before != after)
        out = {"ok": changed, "stack_top_before": before or None,
               "stack_top": after or None, "delta": delta}
        if not changed:
            out["hint"] = ("返回后栈顶未变：可能已在栈底（页面栈只有 1 层时 navigateBack 无效），"
                           "或逻辑层冻结。栈深用 get_page_state 查；栈底页想切走用 navigate_to/switch_tab")
        return out

    async def _tool_evaluate(self, expression):
        blk = self._guard_miniapp_conn("evaluate_js")
        if blk:
            return blk
        result = await self.engine.evaluate_js(expression, timeout=10.0)
        if not result:
            return {"error": "no response"}
        r = result.get("result", {})
        inner = r.get("result", {})
        if "value" in inner:
            return {"value": inner.get("value")}
        if "description" in inner:
            return {"value": inner["description"]}
        return {"raw": result}

    # ── UI 自动化：真实点击 + 数据填写（frame 感知 + 合成触摸黄金参数） ──

    @staticmethod
    def _split_frame_selector(selector):
        """解析 f{n}::sel 前缀（ui_snapshot 为 frame 内元素输出该格式）→ (sel, frame_index)"""
        m = re.match(r"^f(\d+)::(.+)$", selector or "")
        if m:
            return m.group(2), int(m.group(1))
        return selector, -1

    _QUERY_ELEMENT_JS = """
(async (args) => {
    // 一体化元素定位（按优先级依次尝试，轮询等待最多 3 秒）：
    //   1. aid:N    → window.__fySnap.handles 缓存的元素引用（快照时缓存，最稳）
    //   2. text=xx  → 跨 frame 按可见文本匹配（先精确后包含）
    //   3. selector → CSS 选择器（f{n}:: 前缀指定 frame，失效时全量搜索兜底）
    // 定位成功后自动 scrollIntoView + 可见性校验（列表深处元素先滚进视口）
    var WAIT_MAX = 3000, POLL = 200;

    function collectDocs(){
        var docs = [];
        // 顶层 document 优先纳入：tabBar/自定义导航（如 ShopNavWeapp）渲染在顶层
        // 文档，不在任何 iframe 里——只枚举 frames 会永久看不到这些元素
        if (document.body) docs.push(document);
        (function walk(win){
            for (var i = 0; i < win.frames.length; i++){
                var d = null;
                try { d = win.frames[i].document; } catch(e){ continue; }
                if (!d || !d.body) continue;
                docs.push(d);
                walk(win.frames[i]);
            }
        })(window);
        return docs;
    }

    function infoOf(el, doc){
        var r = el.getBoundingClientRect();
        var base = {tag: el.tagName.toLowerCase(), cls: (el.className || '').toString().slice(0, 100),
                    disabled: !!el.disabled,
                    rect: {l: Math.round(r.left), t: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height)}};
        if (r.width <= 0 || r.height <= 0)
            return Object.assign({ok: false, error: '元素不可见（宽高为 0）'}, base);
        base.ok = true;
        base.x = Math.round(r.left + r.width / 2);
        base.y = Math.round(r.top + r.height / 2);
        // 换算顶层页面坐标（frame 偏移累加），供 CDP 坐标兜底派发用
        var px = base.x, py = base.y;
        try {
            var w = doc.defaultView;
            while (w && w !== window && w.frameElement){
                var fr = w.frameElement.getBoundingClientRect();
                px += Math.round(fr.left); py += Math.round(fr.top);
                w = w.parent;
            }
        } catch(e){}
        base.px = px; base.py = py;
        return base;
    }

    function frameIndexOf(doc, docs){
        for (var i = 0; i < docs.length; i++) if (docs[i] === doc) return i;
        return -1;
    }

    function visible(el){
        var r = el.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return false;
        var st = getComputedStyle(el);
        return st.display !== 'none' && st.visibility !== 'hidden';
    }

    function findByText(docs, text, exact){
        var t = text.toLowerCase();
        for (var i = 0; i < docs.length; i++){
            var nodes = docs[i].querySelectorAll('button, a, input, textarea, wx-button, wx-view, wx-text, [role=button], [class*=btn], [class*=item], [class*=cell], [class*=tap]');
            for (var j = 0; j < nodes.length; j++){
                var el = nodes[j];
                var txt = (el.innerText || el.value || '').trim().toLowerCase();
                if (!txt) continue;
                var hit = exact ? (txt === t) : (txt.indexOf(t) >= 0);
                if (hit && visible(el)) return {el: el, doc: docs[i]};
            }
        }
        return null;
    }

    function tryOnce(){
        var docs = collectDocs();
        // 1) aid 句柄缓存
        if (args.aid !== undefined && args.aid !== null){
            var h = null;
            try { h = (window.__fySnap && window.__fySnap.handles || {})[String(args.aid)]; } catch(e){}
            if (h && h.el){
                try {
                    if (h.el.isConnected && h.el.ownerDocument && h.el.ownerDocument.body)
                        return {el: h.el, found: infoOf(h.el, h.el.ownerDocument), doc: h.el.ownerDocument, docs: docs, via: 'aid'};
                } catch(e){}
                // 缓存元素已断连 → 用缓存句柄里的元素文本重找（文本比 selector 稳）
                var htxt = '';
                try { htxt = (h.el.innerText || h.el.value || '').trim(); } catch(e){}
                if (htxt && htxt.length <= 40){
                    var hhit = findByText(docs, htxt, true) || findByText(docs, htxt, false);
                    if (hhit) return {el: hhit.el, found: infoOf(hhit.el, hhit.doc), doc: hhit.doc, docs: docs, via: 'aid'};
                }
            }
        }
        // 2) 按文本定位（args.text 来自快照缓存的元素文本 / AI 直接指定）
        if (args.text){
            var hit = findByText(docs, args.text, true) || findByText(docs, args.text, false);
            if (hit) return {el: hit.el, found: infoOf(hit.el, hit.doc), doc: hit.doc, docs: docs, via: 'text'};
        }
        // 3) selector：指定 frame 优先，失效全量兜底
        var lastInvisible = null;
        function probe(doc, fIdx){
            var el;
            try { el = doc.querySelector(args.sel); } catch(e){ return; }
            if (!el) return;
            var inf = infoOf(el, doc);
            if (inf.ok){ return {el: el, found: inf, doc: doc, docs: docs, via: 'selector'}; }
            lastInvisible = inf;
        }
        if (args.f >= 0 && args.f < docs.length){
            var r = probe(docs[args.f], args.f);
            if (r) return r;
        }
        var order = [document].concat(docs);
        for (var i = 0; i < order.length; i++){
            var r2 = null;
            try { r2 = probe(order[i], i === 0 ? -1 : i - 1); } catch(e){}
            if (r2) return r2;
        }
        if (lastInvisible) return {found: lastInvisible, doc: null, docs: docs, via: 'selector'};
        return null;
    }

    // 轮询等待：懒加载/弹窗动画中元素在 POLL 周期内出现即命中
    var deadline = Date.now() + WAIT_MAX;
    var result = null, lastErr = null;
    while (true){
        try { result = tryOnce(); } catch(e){ lastErr = e.message; }
        if (result && result.found && result.found.ok) break;
        if (Date.now() >= deadline) break;
        await new Promise(function(res){ setTimeout(res, POLL); });
    }
    if (!result){
        var snapAlive = false;
        try { snapAlive = !!(window.__fySnap && window.__fySnap.ts); } catch(e){}
        var aidNote = '';
        if (args.aid !== undefined && args.aid !== null && !snapAlive){
            aidNote = '（快照句柄缓存已失效——页面刷新/切换会冲掉 window.__fySnap；重新 ui_snapshot 拿新 aid 再操作）';
        } else if (args.aid !== undefined && args.aid !== null){
            aidNote = '（aid 在缓存里但元素已断连/不可见：页面可能已切换，重新 ui_snapshot 核对当前界面）';
        }
        return JSON.stringify({ok: false, error: '元素不存在于顶层及所有 frame（已等待 ' + WAIT_MAX + 'ms）' + (lastErr ? '：' + lastErr : '') + aidNote,
                               snapshot_stale: !snapAlive});
    }
    var inf = result.found;
    if (!inf.ok) return JSON.stringify(inf);
    // 滚进视口（列表深处元素不滚就点，坐标会打在别的元素上）+ 重算坐标
    var el = result.el;
    if (el && el.scrollIntoView){
        try {
            var wasOutside = (inf.rect.t < 0 || inf.rect.l < 0);
            if (wasOutside) el.scrollIntoView({block: 'center', behavior: 'instant'});
            var inf2 = infoOf(el, result.doc);
            if (inf2.ok) inf = inf2;
        } catch(e){}
    }
    // 暂存命中元素引用：tap/fill 的执行 JS 直接取 window.__fyLast.el，
    // 避免 aid/text 命中后还需反推 selector（一次 evaluate 内完成，无二次漂移窗口）
    if (el){
        try { window.__fyLast = { el: el, doc: result.doc, ts: Date.now(), via: result.via }; } catch(e){}
    }
    return JSON.stringify(Object.assign(inf, {frame_index: frameIndexOf(result.doc, result.docs), via: result.via}));
})(%s)
"""

    _CANDIDATES_JS = r"""
(function(){
  try {
    var esc = window.CSS && CSS.escape ? CSS.escape : function(s){return s.replace(/([^\w-])/g,'\\$1');};
    // 两段式候选：CAND1 交互元素优先；CAND2 兜 wx-view/wx-text（小程序页面主体是自定义元素，
    // 旧版只认 button/a/input 导致候选永远只剩胶囊按钮/授权壳，误导 selector 修正）
    var CAND1 = 'button, a, input, textarea, wx-button, [role=button], [onclick], '
              + '[class*=btn], [class*=button], [class*=tap], [class*=submit], [class*=confirm], '
              + '[class*=search], [class*=nav], [class*=tab], [class*=menu], [class*=item], [class*=cell]';
    var CAND2 = 'wx-view, wx-text';
    var out = [];
    function mkSel(el){
      if (el.id) return '#' + esc(el.id);
      var tag = el.tagName.toLowerCase();
      var cls = (el.className || '').toString().trim().split(/\s+/).filter(Boolean).slice(0, 2)
        .map(function(c){ return '.' + esc(c); }).join('');
      var suffix = '';
      if (el.parentElement){
        var sib = Array.prototype.filter.call(el.parentElement.children,
          function(c){ return c.tagName === el.tagName; });
        if (sib.length > 1) suffix = ':nth-of-type(' + (sib.indexOf(el) + 1) + ')';
      }
      return tag + cls + suffix;
    }
    var docs = [];
    // 顶层 document 优先：tabBar/自定义导航在顶层文档（不在 iframe 里）
    if (document.body) docs.push(document);
    (function walk(win){
      for (var i = 0; i < win.frames.length; i++){
        var d = null;
        try { d = win.frames[i].document; } catch(e){ continue; }
        if (!d || !d.body) continue;
        docs.push(d);
        walk(win.frames[i]);
      }
    })(window);
    function scanDoc(doc, fIdx, cand, needText){
      var nodes;
      try { nodes = doc.querySelectorAll(cand); } catch(e){ return; }
      for (var i = 0; i < nodes.length && out.length < 16; i++){
        var el = nodes[i];
        // 过滤微信系统弹窗外壳（授权/确认弹窗按钮壳，瞬现瞬灭且无业务文本，
        // 混进候选会误导 selector 修正方向）
        var clsAll = (el.className || '').toString();
        if (/fluent-modal|btn_allow|btn_reject|weui-dialog|wx-modal/i.test(clsAll)) continue;
        var r = el.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) continue;
        var txt = (el.innerText || el.value || '').trim().slice(0, 30);
        if (needText && !txt) continue;         // wx-view 补位时只要有文本的
        // 空文本的 btn 类元素多为弹窗外壳/装饰节点（真实可点元素几乎都有文本）
        if (!txt && !/input|textarea/i.test(el.tagName)) continue;
        var sel = mkSel(el);
        if (fIdx >= 0) sel = 'f' + fIdx + '::' + sel;   // 直接可喂给 tap_element
        out.push({sel: sel, frame: fIdx, tag: el.tagName.toLowerCase(), text: txt});
      }
    }
    function scanAll(cand, needText){
      scanDoc(document, -1, cand, needText);
      for (var f = 0; f < docs.length && out.length < 16; f++) scanDoc(docs[f], f, cand, needText);
    }
    scanAll(CAND1, false);
    if (out.length < 16) scanAll(CAND2, true);
    return JSON.stringify(out);
  } catch(e){ return '[]'; }
})()
"""

    async def _locate_element(self, selector=None, aid=None, text=None):
        """在 webview 渲染层一体化定位元素，优先级：aid 句柄缓存 → 文本匹配 → CSS selector。

        - aid: ui_snapshot 返回的元素编号（快照时已缓存元素引用到 window.__fySnap，最稳）
        - text: 按可见文本匹配（跨 frame，先精确后包含）
        - selector: CSS 选择器（支持 f{n}:: 前缀指定 frame，失效时全量兜底）
        定位成功后元素引用暂存到 window.__fyLast，tap/fill 的执行 JS 直接取用；
        失败时返回候选元素提示。
        """
        sel, f_idx = self._split_frame_selector(selector or "")
        args = {"sel": sel or "", "f": f_idx, "aid": aid, "text": text or ""}
        js = self._QUERY_ELEMENT_JS % json.dumps(json.dumps(args))
        result = await self.engine.evaluate_js(js, timeout=10.0)
        r = (result or {}).get("result", {}).get("result", {})
        raw = r.get("value") if isinstance(r.get("value"), str) else None
        if not raw:
            return {"ok": False, "error": f"evaluate 无返回：{json.dumps(result, ensure_ascii=False, default=str)[:300]}"}
        try:
            info = json.loads(raw)
        except Exception:
            return {"ok": False, "error": f"返回解析失败: {raw[:200]}"}
        if info.get("ok"):
            return info
        # 定位失败时列出顶层+各 frame 的可交互元素，帮助修正参数
        try:
            r2 = await self.engine.evaluate_js(self._CANDIDATES_JS, timeout=8.0)
            v2 = (r2 or {}).get("result", {}).get("result", {}).get("value")
            info["candidates"] = json.loads(v2) if isinstance(v2, str) else v2
        except Exception:
            pass
        return info

    _TAP_SYNTH_JS = """
(async (args) => {
    // 定位元素所在文档：DFS 深度枚举嵌套 frame；指定 frame 查不到时全量搜索兜底
    // （frame 序号随页面切换漂移，快照时的 f{n} 点击时可能已错位）
    function collectDocs(){
        var docs = [];
        // 顶层 document 优先：tabBar/自定义导航在顶层文档（不在 iframe 里）
        if (document.body) docs.push(document);
        (function walk(win){
            for (var i = 0; i < win.frames.length; i++){
                var d = null;
                try { d = win.frames[i].document; } catch(e){ continue; }
                if (!d || !d.body) continue;
                docs.push(d);
                walk(win.frames[i]);
            }
        })(window);
        return docs;
    }
    function findDoc(){
        var DOCS = collectDocs();
        if (args.f >= 0 && args.f < DOCS.length){
            try { if (DOCS[args.f].querySelector(args.sel)) return DOCS[args.f]; } catch(e){}
        }
        if (document.querySelector(args.sel)) return document;
        for (var i = 0; i < DOCS.length; i++){
            try { if (DOCS[i].querySelector(args.sel)) return DOCS[i]; } catch(e){}
        }
        return null;
    }
    // 优先复用定位阶段暂存的元素引用（window.__fyLast.el，aid/text 定位同源），
    // 失效（断连/不可见）时降级 selector 查找
    var doc = null, el = null, reused = false;
    var last = null;
    try { last = window.__fyLast; } catch(e){}
    if (last && last.el){
        try {
            var r0 = last.el.getBoundingClientRect();
            if (last.el.isConnected && last.doc && last.doc.body && r0.width > 0 && r0.height > 0){
                doc = last.doc; el = last.el; reused = true;
            }
        } catch(e){}
    }
    if (!el){
        doc = findDoc();
        if (!doc) return JSON.stringify({ok: false, error: '元素所在文档未找到（已深度扫描嵌套 frame）'});
        el = doc.querySelector(args.sel);
        if (!el) return JSON.stringify({ok: false, error: '元素不存在'});
    }
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return JSON.stringify({ok: false, error: '元素不可见（宽高为 0）'});
    const cx = Math.round(r.left + r.width / 2), cy = Math.round(r.top + r.height / 2);
    const win = doc.defaultView || window;
    // 换算顶层页面坐标（供 CDP 兜底用）
    let px = cx, py = cy;
    try {
        let w = win;
        while (w && w !== window && w.frameElement){
            const fr = w.frameElement.getBoundingClientRect();
            px += Math.round(fr.left); py += Math.round(fr.top);
            w = w.parent;
        }
    } catch(e){}
    function mkTouch(){
        try {
            const T = win.Touch || window.Touch;
            if (T) return new T({identifier: 1, target: el, clientX: cx, clientY: cy,
                                 pageX: cx, pageY: cy, radiusX: 2, radiusY: 2, rotationAngle: 0, force: 1});
        } catch(e){}
        return {identifier: 1, target: el, clientX: cx, clientY: cy, pageX: cx, pageY: cy};
    }
    function mkEvt(type, touches, targetTouches, changedTouches){
        const base = {bubbles: true, cancelable: true, composed: true, view: win,
                      clientX: cx, clientY: cy, screenX: cx, screenY: cy, pageX: cx, pageY: cy};
        try {
            return new win.TouchEvent(type, Object.assign(base, {touches, targetTouches, changedTouches}));
        } catch(e){
            const ev = new win.Event(type, {bubbles: true, cancelable: true});
            Object.assign(ev, base, {touches, targetTouches, changedTouches});
            return ev;
        }
    }
    // 黄金参数：touchstart 的 touches/changedTouches 均含坐标
    el.dispatchEvent(mkEvt('touchstart', [mkTouch()], [mkTouch()], [mkTouch()]));
    // 间隔约 60ms（awaitPromise 由引擎支持）
    await new Promise(res => setTimeout(res, 60));
    // touchend：touches/targetTouches 必须为空数组（手指抬起），changedTouches 保留坐标
    el.dispatchEvent(mkEvt('touchend', [], [], [mkTouch()]));
    return JSON.stringify({ok: true, synthetic: true, reused: reused, frame: args.f, x: cx, y: cy, page_x: px, page_y: py,
                           tag: el.tagName.toLowerCase()});
})(%s)
"""

    async def _tap_in_frame(self, selector, frame_index=-1):
        """frame 内合成触摸（黄金参数），比 CDP 坐标派发对小程序组件更可靠"""
        sel, f_idx = self._split_frame_selector(selector)
        if f_idx < 0:
            f_idx = frame_index if frame_index is not None else -1
        js = self._TAP_SYNTH_JS % json.dumps(json.dumps({"sel": sel, "f": f_idx}))
        result = await self.engine.evaluate_js(js, timeout=10.0)
        raw = (result or {}).get("result", {}).get("result", {}).get("value")
        try:
            return json.loads(raw) if isinstance(raw, str) else {"ok": False, "error": "合成触摸无返回"}
        except Exception:
            return {"ok": False, "error": f"合成触摸返回解析失败: {str(raw)[:200]}"}

    async def _tap_xy(self, x, y):
        """CDP Input 域派发真实触摸事件（touchStart→touchEnd），顶层兜底路径"""
        common = {"x": x, "y": y, "pointerType": "touch", "pointerId": 1}
        await self.engine.send_cdp_command("Input.dispatchTouchEvent",
                                           {"type": "touchStart", "touchPoints": [{"x": x, "y": y, "id": 1}]})
        await asyncio.sleep(0.08)
        await self.engine.send_cdp_command("Input.dispatchTouchEvent",
                                           {"type": "touchEnd", "touchPoints": []})
        # 补派鼠标事件序列，兼容部分用 mousedown/click 监听的 H5 组件
        for t in ("mousePressed", "mouseReleased"):
            await self.engine.send_cdp_command("Input.dispatchMouseEvent", {
                "type": t, **common,
                "button": "left", "clickCount": 1,
            })
        return True

    _PAGE_AFTER_JS = """
(function(){
    // 点击/填写后的界面摘要：确认操作是否生效（导航跳转/弹窗出现/内容变化）
    try {
        var frames = 0;
        (function walk(win){
            for (var i = 0; i < win.frames.length; i++){
                var d = null;
                try { d = win.frames[i].document; } catch(e){ return; }
                if (!d || !d.body) continue;
                frames++;
                walk(win.frames[i]);
            }
        })(window);
        // 收集可见文本前 6 条（按面积过滤小碎片）
        var texts = [];
        var nodes = document.body ? document.body.querySelectorAll('wx-view, wx-text, p, div, span, h1, h2, h3') : [];
        for (var i = 0; i < nodes.length && texts.length < 6; i++){
            var el = nodes[i];
            var r = el.getBoundingClientRect();
            if (r.width < 60 || r.height < 14) continue;
            var t = (el.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 40);
            if (!t || t.length < 2) continue;
            var dup = false;
            for (var j = 0; j < texts.length; j++){ if (texts[j].indexOf(t) >= 0){ dup = true; break; } }
            if (!dup) texts.push(t);
        }
        return JSON.stringify({ok: true, url: location.href.slice(0, 150),
                               title: (document.title || '').slice(0, 60), frames: frames, texts: texts});
    } catch(e){ return JSON.stringify({ok: false, error: e.message}); }
})()
"""

    async def _page_after_snapshot(self):
        """操作后采一次界面摘要（600ms 等待界面响应），失败静默返回 None"""
        try:
            await asyncio.sleep(0.6)
            r = await self.engine.evaluate_js(self._PAGE_AFTER_JS, timeout=5.0)
            raw = self._extract_value(r)
            return json.loads(raw) if isinstance(raw, str) else None
        except Exception:
            return None

    async def _tool_tap_element(self, selector=None, aid=None, text=None):
        blk = self._guard_miniapp_conn("tap_element")
        if blk:
            return blk
        if not selector and aid is None and not text:
            return {"error": "缺少定位参数：aid（ui_snapshot 的元素编号，优先）/ text（可见文本）/ selector 三选一"}
        loc = await self._locate_element(selector=selector, aid=aid, text=text)
        if not loc.get("ok"):
            out = {"ok": False, "error": loc.get("error", "定位失败"),
                   "candidates": loc.get("candidates")}
            # 外壳层提示：候选里 frame:-1 的元素在顶层文档（tabBar/自定义导航渲染层），
            # 若合成触摸对逻辑层绑定事件无效，改走逻辑层导航工具（switch_tab/navigate_back）
            cands = loc.get("candidates") or []
            if any(c.get("frame") == -1 for c in cands if isinstance(c, dict)):
                out["hint"] = ("候选含 frame:-1 的顶层元素（tabBar/外壳层）。这类元素若绑定逻辑层事件，"
                               "DOM 合成触摸可能无效——切 tab 用 switch_tab，返回用 navigate_back，"
                               "普通页面跳转用 navigate_to")
            return out
        # 首选：frame 内合成触摸（黄金参数，复用定位暂存的元素引用）；失败降级 CDP 坐标派发
        sel, f_idx = self._split_frame_selector(selector or "")
        synth = await self._tap_in_frame(sel, loc.get("frame_index", f_idx))
        if synth.get("ok"):
            tap_info = {"mode": "synthetic_touch", "frame": synth.get("frame"),
                        "via": loc.get("via"), "reused_ref": bool(synth.get("reused")),
                        "tapped_at": {"x": synth["x"], "y": synth["y"]}}
        else:
            # CDP Input 域坐标是顶层页面坐标：frame 内元素的局部 x/y 直接派发会点错位置，
            # 必须用定位阶段换算好的顶层坐标（frame 偏移已累加）
            tx, ty = loc.get("px", loc["x"]), loc.get("py", loc["y"])
            await self._tap_xy(tx, ty)
            tap_info = {"mode": "cdp_input", "via": loc.get("via"),
                        "fallback_reason": synth.get("error", ""),
                        "tapped_at": {"x": tx, "y": ty}}
        after = await self._page_after_snapshot()
        res = {"ok": True, "action": "tap", "selector": selector, **tap_info,
               "element": {"tag": loc["tag"], "class": loc["cls"]}}
        self._ui_op_seq = getattr(self, "_ui_op_seq", 0) + 1
        if after and after.get("ok"):
            res["after"] = {"url": after.get("url"), "title": after.get("title"),
                            "frames": after.get("frames"), "texts": after.get("texts", [])}
            res["hint"] = "对比 before/after 的 url/texts 判断点击是否生效；跳转了新页面或出现新文本即生效；" \
                          "点击无效果且目标是 tab 页/返回操作时，改用逻辑层通道 switch_tab/navigate_back"
        return res

    async def _tool_fill_input(self, selector=None, value="", clear=True, aid=None, text=None):
        blk = self._guard_miniapp_conn("fill_input")
        if blk:
            return blk
        if not value and value != "":
            return {"error": "缺少 value"}
        if not selector and aid is None and not text:
            return {"error": "缺少定位参数：aid（ui_snapshot 的元素编号，优先）/ text（可见文本）/ selector 三选一"}
        sel, f_idx = self._split_frame_selector(selector or "")
        loc = await self._locate_element(selector=selector, aid=aid, text=text)
        if not loc.get("ok"):
            return {"ok": False, "error": loc.get("error", "定位失败"),
                    "candidates": loc.get("candidates")}
        # 用原生 setter 设值并触发 input/change 事件，确保框架（Vue/React/小程序）感知
        # frame 感知：先解析 f{n}:: 前缀 / 自动搜索所在 frame，再在该文档内设值
        js = """
(async (args) => {
    // DFS 深度枚举嵌套 frame 定位文档；指定 frame 失效时全量搜索兜底
    function collectDocs(){
        var docs = [];
        // 顶层 document 优先：tabBar/自定义导航在顶层文档（不在 iframe 里）
        if (document.body) docs.push(document);
        (function walk(win){
            for (var i = 0; i < win.frames.length; i++){
                var d = null;
                try { d = win.frames[i].document; } catch(e){ continue; }
                if (!d || !d.body) continue;
                docs.push(d);
                walk(win.frames[i]);
            }
        })(window);
        return docs;
    }
    function findDoc(){
        var DOCS = collectDocs();
        if (args.f >= 0 && args.f < DOCS.length){
            try { if (DOCS[args.f].querySelector(args.sel)) return DOCS[args.f]; } catch(e){}
        }
        if (document.querySelector(args.sel)) return document;
        for (var i = 0; i < DOCS.length; i++){
            try { if (DOCS[i].querySelector(args.sel)) return DOCS[i]; } catch(e){}
        }
        return null;
    }
    // 优先复用定位阶段暂存的元素引用（window.__fyLast.el），失效降级 selector 查找
    var doc = null, el = null;
    var last = null;
    try { last = window.__fyLast; } catch(e){}
    if (last && last.el){
        try {
            var r0 = last.el.getBoundingClientRect();
            if (last.el.isConnected && last.doc && last.doc.body && r0.width > 0 && r0.height > 0){
                doc = last.doc; el = last.el;
            }
        } catch(e){}
    }
    if (!el){
        doc = findDoc();
        if (!doc) return JSON.stringify({ok: false, error: '元素不存在于顶层及各 frame（含嵌套）'});
        el = doc.querySelector(args.sel);
        if (!el) return JSON.stringify({ok: false, error: '元素不存在'});
    }
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
                : (el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype);
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (args.clear || el.value) { if (desc && desc.set) desc.set.call(el, ''); else el.value = ''; el.dispatchEvent(new Event('input', {bubbles: true})); }
    if (desc && desc.set) desc.set.call(el, args.val); else el.value = args.val;
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    el.dispatchEvent(new FocusEvent('focus', {bubbles: true}));
    return JSON.stringify({ok: true, filled: el.value.length, frame: args.f});
})(%s)
""" % json.dumps(json.dumps({"sel": sel, "val": str(value), "clear": bool(clear),
                             "f": f_idx}))
        result = await self.engine.evaluate_js(js, timeout=10.0)
        raw = (result or {}).get("result", {}).get("result", {}).get("value")
        try:
            info = json.loads(raw) if isinstance(raw, str) else {"ok": False, "error": f"evaluate 无返回: {json.dumps(result, ensure_ascii=False, default=str)[:200]}"}
        except Exception:
            info = {"ok": False, "error": f"返回解析失败: {str(raw)[:200]}"}
        if not info.get("ok"):
            return info
        # 聚焦后补一次真实键入，最大程度触发原生 input 逻辑（软键盘场景）
        try:
            await self.engine.send_cdp_command("Input.insertText", {"text": str(value)})
        except Exception:
            pass
        after = await self._page_after_snapshot()
        res = {"ok": True, "action": "fill", "selector": selector, "via": loc.get("via"),
               "value_len": info.get("filled", len(str(value))),
               "element": {"tag": loc["tag"], "class": loc["cls"]}}
        self._ui_op_seq = getattr(self, "_ui_op_seq", 0) + 1
        if after and after.get("ok"):
            res["after"] = {"url": after.get("url"), "title": after.get("title"),
                            "frames": after.get("frames"), "texts": after.get("texts", [])}
        return res

    # ── UI 快照：功能点发现（动态优先，替代翻反编译文件） ──

    _UI_SNAPSHOT_JS = r"""
(function(){
  try {
    var esc = window.CSS && CSS.escape ? CSS.escape : function(s){return s.replace(/([^\w-])/g,'\\$1');};
    var CAND = 'button, a, input, textarea, select, wx-button, [role=button], [onclick], '
             + '[class*=btn], [class*=button], [class*=tap], [class*=submit], [class*=confirm], '
             + '[class*=search], [class*=nav], [class*=tab], [class*=menu], [class*=link]';
    var out = [];
    var seen = {};
    function mkSel(el){
      if (el.id) return '#' + esc(el.id);
      var tag = el.tagName.toLowerCase();
      var cls = (el.className || '').toString().trim().split(/\s+/).filter(Boolean).slice(0, 2)
        .map(function(c){ return '.' + esc(c); }).join('');
      var suffix = '';
      if (el.parentElement){
        var sib = Array.prototype.filter.call(el.parentElement.children,
          function(c){ return c.tagName === el.tagName; });
        if (sib.length > 1) suffix = ':nth-of-type(' + (sib.indexOf(el) + 1) + ')';
      }
      return tag + cls + suffix;
    }
    function scan(doc, fIdx){
      // fIdx: -1=顶层；frame 内元素的 sel 输出 f{n}:: 前缀，tap_element/fill_input 可直接使用
      var nodes = Array.prototype.slice.call(doc.querySelectorAll(CAND));
      for (var i = 0; i < nodes.length && out.length < 80; i++){
        var el = nodes[i];
        var r = el.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) continue;              // 不可见
        var st = doc.defaultView.getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden') continue;
        var sel = mkSel(el);
        if (fIdx >= 0) sel = 'f' + fIdx + '::' + sel;
        if (seen[sel]) continue;                                 // 去重（同 selector 取第一个）
        seen[sel] = 1;
        var item = { sel: sel, tag: el.tagName.toLowerCase(), frame: fIdx,
                     text: (el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || '').trim().slice(0, 40),
                     rect: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)] };
        item._el = el;   // 元素引用：进入句柄缓存用，序列化前会摘掉
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA'){
          item.input = true; item.type = el.type || ''; item.value = (el.value || '').slice(0, 40);
        }
        if (el.disabled) item.disabled = true;
        out.push(item);
      }
    }
    // DFS 枚举 frame 文档（含嵌套 frame），f0 = 第一个子 frame（先序遍历），f1 = 其子 frame……
    // 活跃页过滤：微信多 tab 页在渲染层共存，隐藏页 frame 仍在 DOM 里——全量扫描会把
    // 非当前页元素混进快照（实测 me 页混入 discover 页元素）。frame 级判隐：
    // visibilityState=hidden / 宿主元素 display:none / 0 尺寸 / 完全在视口外，
    // 命中即跳过整棵子树；全部被过滤时（如整窗最小化）退回不过滤重扫，保证快照不空
    function frameVisible(fd, win){
      try {
        if (fd.visibilityState === 'hidden') return false;
        var fe = null;
        try { fe = win.frameElement; } catch(e){ return true; }
        if (!fe) return true;                        // 无宿主元素（顶层）不妄判
        var st = win.parent.getComputedStyle(fe);
        if (st.display === 'none' || st.visibility === 'hidden') return false;
        var r = fe.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) return false;
        var iw = win.parent.innerWidth || 0, ih = win.parent.innerHeight || 0;
        if (r.right <= 0 || r.bottom <= 0 ||
            (iw > 0 && r.left >= iw) || (ih > 0 && r.top >= ih)) return false;
        return true;
      } catch(e){ return true; }                     // 判不了就保留（宁滥勿缺）
    }
    var docs = [];
    var frameUrls = {};                    // frame 序号 → URL（僵尸 frame 识别用）
    function walk(win, filt){
      for (var f = 0; f < win.frames.length; f++){
        var fd = null;
        try { fd = win.frames[f].document; } catch(e){ continue; }
        if (!fd || !fd.body) continue;   // frame 不可访问（跨域/未就绪）时跳过
        if (filt && !frameVisible(fd, win.frames[f])) continue;
        var furl = '';
        try { furl = (fd.URL || fd.documentURI || '').slice(0, 150); } catch(e){}
        docs.push({doc: fd, f: docs.length, url: furl});
        frameUrls[docs.length - 1] = furl;
        walk(win.frames[f], filt);
      }
    }
    walk(window, true);
    if (!docs.length) walk(window, false);
    for (var i = 0; i < docs.length && out.length < 80; i++) scan(docs[i].doc, docs[i].f);
    // 元素句柄缓存：快照同时把「元素引用 + 定位信息」存到 window.__fySnap，
    // 后续 tap_element/fill_input 直接用 aid:N 查缓存定位（selector 漂移不再导致试错）。
    // 存活到下一次快照覆盖或页面刷新；跨 frame 元素引用直接持有，点击时无需重新定位 frame
    var handleCache = {};
    for (var i = 0; i < docs.length; i++){ docs[i].doc.__fyHandles = {}; }
    var out2 = [];
    for (var i = 0; i < out.length; i++){
      var it = out[i];
      var el = it._el;   // scan 时挂在临时对象上的引用（见下）
      var aid = i;
      if (el){
        it._el = undefined;
        try {
          var home = null;
          for (var j = 0; j < docs.length; j++){
            try { if (docs[j].doc.contains(el)) { home = docs[j]; break; } } catch(e){}
          }
          if (home){ home.doc.__fyHandles[aid] = { el: el, sel: it.sel, f: home.f }; }
        } catch(e){}
      }
      it.aid = aid;
      out2.push(it);
    }
    window.__fySnap = { ts: Date.now(), url: location.href, handles: (function(){
      var merged = {};
      for (var i = 0; i < docs.length; i++){
        try {
          var h = docs[i].doc.__fyHandles || {};
          for (var k in h) merged[k] = h[k];
          docs[i].doc.__fyHandles = undefined;   // 合并后清掉，统一挂 window
        } catch(e){}
      }
      return merged;
    })() };
    return JSON.stringify({ ok: true, url: location.href.slice(0, 150),
                            title: (document.title || '').slice(0, 60),
                            frames: docs.length,
                            frame_urls: frameUrls,
                            count: out2.length, elements: out2 });
  } catch(e){ return JSON.stringify({ ok: false, error: e.message }); }
})()
"""

    async def _tool_ui_snapshot(self):
        blk = self._guard_miniapp_conn("ui_snapshot")
        if blk:
            return blk
        result = await self.engine.evaluate_js(self._UI_SNAPSHOT_JS, timeout=10.0)
        raw = self._extract_value(result)
        if not raw:
            return {"error": "快照无返回（页面可能未就绪）",
                    "raw": json.dumps(result, ensure_ascii=False, default=str)[:300]}
        try:
            snap = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"error": "快照解析失败", "raw": str(raw)[:500]}
        if not snap.get("ok"):
            return {"error": snap.get("error", "快照失败")}
        # ── 渲染层冻结早识别：本次快照与上次完全一致（元素数+全部文本+坐标）
        # 且期间发生过点击/填写操作 → 渲染层大概率没刷新（UI 假死/逻辑层断连），
        # 提前告知别再硬撑 aid 试错，转协议层或重启小程序进程
        els = snap.get("elements", [])
        fp = json.dumps([[e.get("sel"), e.get("text"), e.get("rect")] for e in els],
                        ensure_ascii=False)
        prev_fp = getattr(self, "_ui_snap_fp", None)
        op_seq = getattr(self, "_ui_op_seq", 0)
        stale_warn = ""
        if prev_fp is not None and prev_fp == fp and op_seq > getattr(self, "_ui_fp_at_op_seq", -1):
            stale_warn = ("本次快照与上次完全一致，且期间发生过 tap/fill 操作——渲染层疑似冻结"
                          "（页面实际没刷新）。继续 tap_element/fill_input 大概率报「元素不存在」，"
                          "建议：① get_page_state 查逻辑层是否断连/冻结；② 重启小程序进程重连；"
                          "③ 暂时改用协议层工具（http_request/get_http_captures）推进")
        self._ui_snap_fp = fp
        self._ui_fp_at_op_seq = op_seq
        out = {"page": {"url": snap.get("url"), "title": snap.get("title")},
               "frames": snap.get("frames", 0),
               "count": snap.get("count", 0),
               "elements": els}
        # frame URL 标注：方便识别混帧（如 me 页快照里混着 discover 页 webview 残留）。
        # 同一业务页面的 H5 frame 有多份 URL 相似副本 = 僵尸残留，其元素 aid 不可点
        frame_urls = snap.get("frame_urls") or {}
        if frame_urls:
            out["frame_urls"] = frame_urls
            if len(frame_urls) > 1:
                urls = [str(u) for u in frame_urls.values()]
                dup = len(urls) != len(set(urls))
                out["hint"] = ("多 frame 共存：frame_urls 列出每个 frame 的 URL，元素 sel 的 f{n}:: 前缀对应此序号。"
                               + ("检测到 URL 重复的 frame——webview 页切换残留（僵尸 frame），"
                                  "其元素不要点（页面已销毁只是 DOM 未 detach），导航后重拍快照即可消失；"
                                  if dup else
                                  "混入非当前页元素时对照 URL 识别跳过该 frame 的元素；")
                               + "逻辑层当前页用 get_page_state 核对")
        if stale_warn:
            out["warning"] = stale_warn
        out.setdefault("hint", "操作优先用 elements[].aid：tap_element({aid: N}) 点击 / fill_input({aid: N, value: ...}) 填写（快照已缓存元素引用，最稳）；"
                       "aid 失效时可用 text（可见文本）或 sel（f{n}:: 前缀表示嵌套 frame 内）兜底；"
                       "点击后用 get_http_captures 查看触发的请求")
        return out

    # ── 逻辑层操控（借鉴 miniapp-cdp-mcp/wmpf-mcp：渲染层 UI + 逻辑层数据双通道） ──
    # 逻辑层入口 = window.nav.wxFrame（nav_inject.js 已自动定位含 wx/__wxConfig 的 frame）

    _WX_FRAME_EXPR = "(window.nav&&window.nav.wxFrame)||null"

    # window.nav 桥接探活：返回 1 = 桥接完好；0/null/异常 = 需重注入
    _NAV_PROBE = "(function(){try{return (window.nav&&window.nav.wxFrame&&window.nav.wxFrame.wx)?1:0}catch(e){return 0}})()"

    async def _ensure_nav_bridge(self) -> bool:
        """确保 window.nav 逻辑层桥接可用，失效则自动重注入 nav_inject.js。

        背景：nav_inject.js 注入的 window.nav 挂在渲染层 window 上，
        页面切换/小程序热重载/重进后常被整个冲掉；逻辑层工具此前直接
        引用 _WX_FRAME_EXPR，桥接丢失只能报错，需人工 navigate_to 触发
        navigator._ensure 才能恢复。此方法先探活、失效即重注入一次。
        """
        try:
            r = await self.engine.evaluate_js(self._NAV_PROBE, timeout=5.0)
            if self._extract_value(r) == 1:
                return True
        except Exception:
            pass
        # 探活失败 → 重注入（nav_inject.js 自带有效性检测与重建逻辑）
        try:
            await self.navigator._ensure(force=True)
        except Exception:
            return False
        try:
            r = await self.engine.evaluate_js(self._NAV_PROBE, timeout=5.0)
            return self._extract_value(r) == 1
        except Exception:
            return False

    @staticmethod
    def _json_expr(v):
        """值转 JS 字面量；undefined/不可序列化时退化为 null"""
        try:
            return json.dumps(v, ensure_ascii=False)
        except (TypeError, ValueError):
            return "null"

    def _guard_miniapp_conn(self, tool_label="本工具"):
        """断连守门 + 熔断：通道健康（有客户端连接 且 Frida hook 在位）时归零计数放行；
        否则计数，连续 DISCONNECT_TRIP 次即触发熔断——不再放行任何小程序类工具，直接指路
        reconnect_engine。治「断连后 AI 对着死通道空试几十次」。
        注意必须同时检查 frida 状态：reload 杀 hook 后 websocket 可能残留僵尸连接
        （实测本次 48 连超时），只看 miniapp_clients 非空会漏判。
        返回 None=放行，dict=拦截结果。"""
        if self.engine.miniapp_clients and self.engine.status.get("frida"):
            if getattr(self, "_disc_seq", 0):
                self._disc_seq = 0
            return None
        self._disc_seq = getattr(self, "_disc_seq", 0) + 1
        base = {"error": "小程序未连接（逻辑层 CDP 通道断开）",
                "failed_count": self._disc_seq,
                "hint": ("期间不要重试小程序类工具（UI/逻辑层/包重放都走这条死通道）。"
                         "断连期间可继续用协议层工具（http_request/get_http_captures/search_decompiled）推进")}
        if self._disc_seq >= self.DISCONNECT_TRIP:
            # 熔断：连续 N 次失败说明不是瞬时抖动，等自动重连大概率无效
            # （典型场景：Frida hook 已随进程丢失，无人再转发 debug message）
            return {**base,
                    "circuit_breaker": True,
                    "hint": (f"已连续 {self._disc_seq} 次「小程序未连接」，判定通道死锁（hook 丢失，"
                             "等自动重连/重启小程序进程均无效），已熔断停止放行小程序类工具。"
                             "唯一恢复方式：调用 reconnect_engine 重新附加引擎（Frida 重注入），"
                             "恢复后先 get_page_state 确认再继续测试；"
                             f"{tool_label}这次未执行")}
        return {**base,
                "hint": base["hint"] + f"。{tool_label}这次未执行；连续 "
                        f"{self.DISCONNECT_TRIP} 次未连接将熔断，届时需调用 reconnect_engine 恢复"}

    async def _tool_scroll_page(self, direction="down", amount=800):
        blk = self._guard_miniapp_conn("scroll_page")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        amount = max(100, min(int(amount or 800), 20000))
        js = f"""
(async () => {{
    const f = {self._WX_FRAME_EXPR};
    if (!f || !f.wx) return JSON.stringify({{ok: false, error: '逻辑层 wx 不可用'}});
    const pages = f.getCurrentPages ? f.getCurrentPages() : [];
    const cur = pages.length ? pages[pages.length - 1] : null;
    const sy = (cur && cur.scrollTop) || 0;
    // 分步滚动模拟真实手势（一步到底部分组件不触发 onReachBottom）
    const steps = [];
    if ('{direction}' === 'down') {{
        for (let y = sy; y < sy + {amount}; y += 300) steps.push(y);
        steps.push(sy + {amount});
    }} else {{
        for (let y = sy; y > Math.max(0, sy - {amount}); y -= 300) steps.push(Math.max(0, y));
    }}
    for (const y of steps) {{
        try {{ f.wx.pageScrollTo({{scrollTop: y, duration: 0}}); }} catch (e) {{}}
        await new Promise(r => setTimeout(r, 60));
    }}
    return JSON.stringify({{ok: true, direction: '{direction}', from: sy,
                            to: steps.length ? steps[steps.length - 1] : sy}});
}})()
"""
        result = await self.engine.evaluate_js(js, timeout=15.0)
        raw = self._extract_value(result)
        try:
            return json.loads(raw) if isinstance(raw, str) else {"ok": False, "error": "滚动无返回"}
        except Exception:
            return {"ok": False, "error": f"滚动返回解析失败: {str(raw)[:200]}"}

    async def _tool_get_page_state(self):
        blk = self._guard_miniapp_conn("get_page_state")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        js = f"""
(() => {{
    const f = {self._WX_FRAME_EXPR};
    if (!f) return JSON.stringify({{ok: false, error: '逻辑层 frame 未定位（先等页面加载）'}});
    const pages = f.getCurrentPages ? f.getCurrentPages() : [];
    if (!pages.length) return JSON.stringify({{ok: false, error: '页面栈为空'}});
    const cur = pages[pages.length - 1];
    let data = {{}}, dataKeys = [];
    try {{
        data = cur.data || {{}};
        dataKeys = Object.keys(data);
    }} catch (e) {{}}
    // data 太大时只回字段名+类型+预览，避免撑爆上下文
    const preview = {{}};
    for (const k of dataKeys.slice(0, 60)) {{
        const v = data[k];
        const t = v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
        let s = '';
        try {{ s = JSON.stringify(v); }} catch (e) {{ s = '"unserializable"'; }}
        preview[k] = {{type: t, preview: s.length > 120 ? s.slice(0, 117) + '...' : s}};
    }}
    // 页面栈全景：webview/H5 页会让渲染层与逻辑层观感不一致，
    // 回告整条栈让 AI 能识别「栈里其实有多个页，当前停在 webview 外壳页」
    const stack = pages.map(p => p.route || p.__route__ || '');
    // 活性指纹：栈顶实例引用 + options 原始序列化。逻辑层冻结时无论怎么导航，
    // 栈顶实例与 options 都不变（navigateTo:ok 只是壳回执）——这是判冻结的核心依据
    let optRaw = '';
    try {{ optRaw = JSON.stringify(cur.options || {{}}); }} catch (e) {{ optRaw = 'err'; }}
    return JSON.stringify({{ok: true, route: cur.route || cur.__route__ || '',
                            page_stack: stack, stack_depth: stack.length,
                            options: cur.options || {{}}, options_raw: optRaw,
                            data_key_count: dataKeys.length,
                            data: preview, truncated: dataKeys.length > 60}});
}})()
"""
        result = await self.engine.evaluate_js(js, timeout=8.0)
        raw = self._extract_value(result)
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {"error": f"页面状态读取失败: {str(raw)[:200]}"}
        if not info.get("ok"):
            if info:
                # 桥有响应的结构化错误（frame 未定位/页面栈空），非空回执
                self._gps_empty_seq = 0
                return info
            # ── 空回执诊断：桥通道存活但逻辑层无响应 ──
            # 实测踩坑：webview 页逻辑层桥对该页不可用时
            # evaluate_js 无返回，这里曾直接 return {}——AI 面对裸空字典无从判断，
            # 只能反复重试直到 StuckDetector 轰炸、上下文被烧穿。现改为递进诊断：
            # 第 1 次允许重试，连续 ≥2 次判定环境限制，引导改道协议层不再空转
            self._gps_empty_seq = getattr(self, "_gps_empty_seq", 0) + 1
            n = self._gps_empty_seq
            if n >= 2:
                return {"ok": False, "empty_response": True, "consecutive_empty": n,
                        "environment_limit": True,
                        "route": None, "page_stack": [], "stack_depth": 0,
                        "data_key_count": 0, "data": {},
                        "error": f"逻辑层桥连续 {n} 次无响应，判定该页面逻辑层桥不可用"
                                 "（webview 页/跨域 H5 卡死逻辑层的固有限制，reconnect 也救不了）",
                        "hint": ("停止重试 get_page_state/set_page_data 等逻辑层工具（结果不会变）。改道："
                                 "① 页面内容用 ui_snapshot（渲染层）+ evaluate_js 深挖 frame；"
                                 "② 业务数据与鉴权测试用协议层 get_http_captures/http_request；"
                                 "③ 依赖逻辑层状态的功能点按预案置 skipped（注明 webview 页逻辑层桥不可用），"
                                 "结论改用接口对照实验旁证闭环；"
                                 "④ 此状态下 navigate_to/replay_api 返回 ok 也只是壳回执，"
                                 "页面覆盖度以真实流量为准。测完用 replay_api navigateBack 尝试退出，"
                                 "退出失败就换下一个页面，不要被卡死在这")}
            return {"ok": False, "empty_response": True, "consecutive_empty": n,
                    "route": None, "page_stack": [], "stack_depth": 0,
                    "data_key_count": 0, "data": {},
                    "error": "逻辑层桥本次无响应（返回空）",
                    "hint": "可重试 1 次等页面加载落定；若再返回空即判定该页逻辑层桥不可用，"
                            "按提示改道协议层，不要反复重试"}
        self._gps_empty_seq = 0
        stack = info.get("page_stack") or []
        cur_route = info.get("route") or ""
        # ── 逻辑层冻结检测 ──
        # 指纹 = 栈顶路由 + 栈全景 + options 原文。连续 2 次读取完全一致（且期间发生过
        # 导航）即判定逻辑层冻结：navigateTo 返回 ok 也只是壳响应，UI 不会真变。
        # 此时 visited 标记全部不可信，必须重启小程序进程/重新附加，不能硬撑
        fingerprint = json.dumps([cur_route, stack, info.get("options_raw", "")],
                                 ensure_ascii=False)
        prev = getattr(self, "_page_state_fp", None)
        nav_seq = getattr(self, "_nav_seq", 0)
        frozen = False
        if prev is not None and prev == fingerprint and nav_seq > getattr(self, "_fp_at_nav_seq", -1):
            frozen = True
        self._page_state_fp = fingerprint
        self._fp_at_nav_seq = nav_seq
        if frozen:
            # 冻结不自愈只会积累假成功：直接自动 reconnect_engine 重附加引擎
            # （连续 2 次指纹一致已实锤逻辑层卡死，等 AI 手动处置只会多浪费轮次）
            rec = await self._tool_reconnect_engine()
            return {"ok": False, "frozen": True,
                    "error": "逻辑层疑似冻结：本次与上次读取的页面栈/路由/options 完全一致，"
                             "且期间发生过导航操作。navigateTo 返回 ok 只是壳回执，页面实际没变",
                    "route": cur_route, "page_stack": stack,
                    "auto_reconnect": rec,
                    "hint": ("已自动执行 reconnect_engine：" + str(rec.get("note", ""))[:150] +
                             "。恢复后先重读 get_page_state 确认 options 在变化（活性恢复）再继续；"
                             "冻结期间的导航 visited 标记不可信，恢复后用 get_http_captures 按流量重新核实。"
                             "若 reconnect 后依然 frozen，说明小程序进程本身卡死，请用户手动关闭重开小程序"),
                    "recovery": "reconnect_engine(auto)"}
        # 页面遍历跟踪：逻辑层栈顶路由命中即计 visited（navigate_to 之外的
        # 页面切换——tap 跳转/back/redirect——也覆盖到）
        try:
            if cur_route:
                self.feature_registry.mark_page_visited("/" + cur_route)
        except Exception:
            pass
        hints = ["data 是逻辑层内部状态（UI 上不一定显示）；发现 isAdmin/isVip/price 等敏感字段后可用 set_page_data 篡改测试前端鉴权"]
        if cur_route and ("webview" in cur_route or "web-view" in cur_route):
            hints.append(f"当前是 webview 外壳页（{cur_route}）：H5 内容在独立跨域 frame 里，逻辑层 data 看不到 H5 内部状态；"
                         f"渲染层快照显示多 frame 共存而这里只有一页属正常现象。导航卡死时用 replay_api 直调 wx.navigateBack"
                         f"（{{api_name:'navigateBack'}}）退出 webview 页再继续")
        elif len(stack) > 1:
            hints.append(f"页面栈共 {len(stack)} 层: {', '.join(stack)}；确认 route 是否是你预期的栈顶页（页面切换后逻辑层状态可能滞后），"
                         f"不确定时重拍 ui_snapshot 与渲染层互相印证")
        return {"route": cur_route, "page_stack": stack, "stack_depth": len(stack),
                "options": info.get("options"),
                "data_key_count": info.get("data_key_count"), "data": info.get("data"),
                "truncated": info.get("truncated"),
                "hint": " ".join(hints)}

    async def _tool_set_page_data(self, key, value):
        blk = self._guard_miniapp_conn("set_page_data")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        key_js = json.dumps(str(key), ensure_ascii=False)
        val_js = self._json_expr(value)
        js = f"""
(() => {{
    const f = {self._WX_FRAME_EXPR};
    if (!f) return JSON.stringify({{ok: false, error: '逻辑层 frame 未定位'}});
    const pages = f.getCurrentPages ? f.getCurrentPages() : [];
    if (!pages.length) return JSON.stringify({{ok: false, error: '页面栈为空'}});
    const cur = pages[pages.length - 1];
    if (!cur.setData) return JSON.stringify({{ok: false, error: '页面无 setData 方法'}});
    const patch = {{}};
    // setData 原生支持 'a.b.c' 路径 key
    patch[{key_js}] = {val_js};
    try {{ cur.setData(patch); }}
    catch (e) {{ return JSON.stringify({{ok: false, error: 'setData 失败: ' + e.message}}); }}
    // 回读确认
    const parts = {key_js}.split('.');
    let probe = cur.data;
    for (const p of parts) {{ probe = probe == null ? undefined : probe[p]; }}
    return JSON.stringify({{ok: true, key: {key_js},
                            now: (typeof probe === 'object' ? JSON.stringify(probe) : String(probe))}});
}})()
"""
        result = await self.engine.evaluate_js(js, timeout=8.0)
        raw = self._extract_value(result)
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {"error": f"setData 执行失败: {str(raw)[:200]}"}
        if info.get("ok"):
            info["note"] = "改的是前端渲染状态，不改变后端权限；用 ui_snapshot 看界面是否解锁，再对真实接口做越权验证"
        return info

    async def _tool_get_app_data(self):
        blk = self._guard_miniapp_conn("get_app_data")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        js = f"""
(() => {{
    const f = {self._WX_FRAME_EXPR};
    if (!f) return JSON.stringify({{ok: false, error: '逻辑层 frame 未定位'}});
    let app = null;
    try {{ app = f.getApp ? f.getApp({{allowDefault: true}}) : null; }} catch (e) {{}}
    if (!app) return JSON.stringify({{ok: false, error: 'getApp 不可用'}});
    const g = app.globalData || {{}};
    const preview = {{}};
    let n = 0;
    for (const k of Object.keys(g)) {{
        if (n++ >= 60) break;
        let s = '';
        try {{ s = JSON.stringify(g[k]); }} catch (e) {{ s = '"unserializable"'; }}
        preview[k] = s.length > 150 ? s.slice(0, 147) + '...' : s;
    }}
    return JSON.stringify({{ok: true, keys: Object.keys(g), data: preview, truncated: Object.keys(g).length > 60}});
}})()
"""
        result = await self.engine.evaluate_js(js, timeout=8.0)
        raw = self._extract_value(result)
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {"error": f"globalData 读取失败: {str(raw)[:200]}"}
        return info

    async def _tool_reconnect_engine(self):
        """重新附加调试引擎：engine 完整 stop+start（等价 /engine/restart）。

        断连场景（Frida detached / miniapp_clients 空）下这是唯一可靠恢复通道——
        hook 已随 webview 上下文丢失，等 websocket 自动重连和重启小程序进程都无效，
        只有重新注入才行。PID 变化无妨：_find_wmpf_pids 注入时现查存活进程。
        """
        # 已连接就无需折腾，避免把好端端的会话拆了
        # 条件与 _guard_miniapp_conn 对齐：frida 状态必须同时在位——
        # reload 杀 hook 后 websocket 可能残留僵尸连接（连接在、hook 死、全超时）
        if self.engine.miniapp_clients and self.engine.status.get("frida"):
            return {"ok": True, "already": True,
                    "note": "调试通道本来就在线，无需恢复；若工具仍报错请把原始错误反馈排查",
                    "status": dict(self.engine.status)}
        try:
            await self.engine.stop()
        except Exception as e:
            return {"ok": False, "error": f"引擎停止失败: {e}",
                    "hint": "停止阶段失败通常不影响重试，可直接再调一次 reconnect_engine"}
        await asyncio.sleep(1.0)  # 与 /engine/restart 一致，留端口释放与句柄回收时间
        try:
            await self.engine.start()
        except Exception as e:
            return {"ok": False, "error": f"引擎重启失败: {e}",
                    "hint": "重注入失败常见原因：①微信未运行/未打开目标小程序（WeChatAppEx 进程不存在）；"
                            "② Frida 版本不匹配（addresses 文件拉取失败）。两条都排除后让用户看后端日志"}
        # 重新注入成功 ≠ 逻辑层马上可用：websocket 要等小程序端重连回来
        # （用户打开/刷新小程序页面才触发），轮询最多 15 秒
        for _ in range(15):
            if self.engine.miniapp_clients:
                break
            await asyncio.sleep(1.0)
        connected = bool(self.engine.miniapp_clients)
        out = {"ok": True, "frida": bool(self.engine.status.get("frida")),
               "miniapp": connected,
               "status": dict(self.engine.status)}
        if connected:
            out["note"] = "引擎已恢复且逻辑层通道在线；先 get_page_state 确认页面状态再继续测试"
        else:
            out["note"] = ("Frida 已重新注入，但逻辑层通道 15 秒内未回连。"
                           "请用户在微信中打开/刷新目标小程序页面触发重连，"
                           "连上后再继续测试（期间不要空试 UI 工具）")
        return out

    # 凭据关键词（参考开源小程序调试工具 get_user_credentials 实现）
    _CRED_KEYWORDS = ["token", "session", "openid", "open_id", "unionid", "uid", "userid",
                      "user_id", "jwt", "auth", "cookie", "ticket", "apikey", "api_key",
                      "secret", "access", "refresh", "login", "phone", "mobile"]

    async def _tool_get_credentials(self):
        blk = self._guard_miniapp_conn("get_credentials")
        if blk:
            return blk
        await self._ensure_nav_bridge()
        kws_js = json.dumps(self._CRED_KEYWORDS, ensure_ascii=False)
        js = f"""
(() => {{
    const KWS = {kws_js};
    const hit = (k) => KWS.some(w => (k || '').toLowerCase().includes(w));
    const clip = (v) => {{ let s = ''; try {{ s = typeof v === 'string' ? v : JSON.stringify(v); }} catch (e) {{}} return s.length > 200 ? s.slice(0, 197) + '...' : s; }};
    const out = {{storage: {{}}, globalData: {{}}, pageData: {{}}, total: 0}};
    try {{
        const f = {self._WX_FRAME_EXPR} || window;
        const wxObj = (f && f.wx) || window.wx;
        if (wxObj && wxObj.getStorageInfoSync) {{
            const info = wxObj.getStorageInfoSync();
            for (const k of (info.keys || [])) {{
                if (hit(k)) {{ try {{ out.storage[k] = clip(wxObj.getStorageSync(k)); out.total++; }} catch (e) {{}} }}
            }}
        }}
        if (f) {{
            let app = null;
            try {{ app = f.getApp ? f.getApp({{allowDefault: true}}) : null; }} catch (e) {{}}
            if (app && app.globalData) {{
                for (const k of Object.keys(app.globalData)) {{
                    if (hit(k)) {{ out.globalData[k] = clip(app.globalData[k]); out.total++; }}
                }}
            }}
            const pages = f.getCurrentPages ? f.getCurrentPages() : [];
            const cur = pages.length ? pages[pages.length - 1] : null;
            if (cur && cur.data) {{
                for (const k of Object.keys(cur.data)) {{
                    if (hit(k)) {{ out.pageData[k] = clip(cur.data[k]); out.total++; }}
                }}
            }}
        }}
    }} catch (e) {{ return JSON.stringify({{ok: false, error: e.message}}); }}
    return JSON.stringify({{ok: true, ...out}});
}})()
"""
        result = await self.engine.evaluate_js(js, timeout=10.0)
        raw = self._extract_value(result)
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {"error": f"凭据聚合失败: {str(raw)[:200]}"}
        if info.get("ok"):
            info["hint"] = "这些凭据可配合 http_request/wx_request 重放使用；openid/sessionKey 类泄露本身即敏感信息泄露"
        return info

    async def _tool_wx_request(self, url, method="GET", data=None, header=None):
        blk = self._guard_miniapp_conn("wx_request")
        if blk:
            return {**blk, "hint": blk["hint"] + "。wx_request 不可用时改用 http_request（Python 侧直发，自动带会话凭证与微信指纹头）"}
        await self._ensure_nav_bridge()
        url_js = json.dumps(str(url), ensure_ascii=False)
        method_js = json.dumps(str(method or "GET").upper())
        data_js = self._json_expr(data)
        header_js = self._json_expr(header)
        js = f"""
(() => new Promise((resolve) => {{
    const f = {self._WX_FRAME_EXPR};
    const wxObj = (f && f.wx) || window.wx;
    if (!wxObj || !wxObj.request) {{ resolve(JSON.stringify({{ok: false, error: '逻辑层 wx.request 不可用'}})); return; }}
    const t0 = Date.now();
    wxObj.request({{
        url: {url_js}, method: {method_js},
        data: {data_js}, header: {header_js},
        timeout: 15000,
        success: (res) => resolve(JSON.stringify({{
            ok: true, status: res.statusCode, header: res.header,
            body: (typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).slice(0, 4000),
            elapsed_ms: Date.now() - t0, via: 'appservice'
        }})),
        fail: (err) => resolve(JSON.stringify({{ok: false, error: (err && err.errMsg) || 'request fail', elapsed_ms: Date.now() - t0}}))
    }});
}}))()
"""
        result = await self.engine.evaluate_js(js, timeout=20.0)
        raw = self._extract_value(result)
        try:
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {"error": f"wx_request 返回解析失败: {str(raw)[:200]}"}
        if info.get("ok"):
            # 会话流量日志：逻辑层请求同样全量留痕（原先不存流量，报告数据包缺这块来源）
            wx_body = data if isinstance(data, str) else (
                json.dumps(data, ensure_ascii=False) if data is not None else None)
            wx_headers = header if isinstance(header, dict) else {}
            resp_lines = [f"HTTP/1.1 {info.get('status', '')}"]
            resp_lines += [f"{k}: {v}" for k, v in (info.get("header") or {}).items()]
            resp_lines.append("")
            resp_lines.append(str(info.get("body", ""))[:8000])
            self._record_traffic(
                self._format_http_request(method, url, wx_headers, wx_body),
                "\n".join(resp_lines), url, method)
            info["hint"] = "逻辑层发起的请求自动携带客户端环境；对比 get_http_captures 里原始包的头/体差异，确认加密参数是否自动生成"
        return info

    async def _tool_capture_cloud(self):
        result = await self.cloud.start()
        return result

    async def _tool_get_cloud_calls(self):
        calls = await self.cloud.poll()
        self.state.cloud_calls.extend(calls)
        return {"count": len(self.state.cloud_calls), "calls": self.state.cloud_calls[-50:]}

    async def _tool_call_cloud(self, name, data=None):
        result = await self.cloud.call_function(name, data or {})
        return result

    async def _tool_capture_wxapi(self, capture_request=True, capture_storage=False):
        result = await self.wxapi.start(
            capture_request=capture_request,
            capture_storage=capture_storage,
            capture_bridge=False,
        )
        if isinstance(result, dict):
            # 提示双通道：逻辑层 JS hook 之外，代理通道（capture_proxy）负责网络层完整抓包
            result["hint"] = "逻辑层 hook 已开启；要抓完整网络层流量（含响应体）请另开 capture_proxy(action='start')"
        return result

    async def _tool_get_wxapi_calls(self, limit=30, type_filter=None, url_filter=None):
        # 先拉 JS hook 增量，并入全局记录
        new_calls = await self.wxapi.poll()
        self.state.wxapi_calls.extend(new_calls)
        # 合并三路捕获：JS hook + CDP 网络层 + 内嵌解密代理（按 method+url+postData 去重）
        pc = getattr(self.state, "proxy_capture", None)
        proxy_caps = pc.captures if pc else []
        seen_keys = set()
        merged = []
        for c in self.state.wxapi_calls:
            key = (c.get("method"), c.get("url"), (c.get("postData") or "")[:100])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            merged.append(c)
        sources = list(getattr(self.engine, "network_calls", [])) + list(proxy_caps)
        for nc in sources:
            key = (nc.get("method"), nc.get("url"), (nc.get("postData") or "")[:100])
            if key not in seen_keys:
                merged.append(nc)
                seen_keys.add(key)
        self.state.wxapi_calls = merged
        # 源头降噪：剔除内联资源（data:/blob:），这些不是可测的 API 请求
        def _is_noise(c):
            u = c.get("url") or ""
            return u.startswith("data:") or u.startswith("blob:")
        api_calls = [c for c in merged if not _is_noise(c)]
        total_all = len(api_calls)
        # 类型分布（帮助 AI 判断 hook 情况）
        type_dist = {}
        for c in api_calls:
            t = c.get("type", "unknown")
            type_dist[t] = type_dist.get(t, 0) + 1
        calls = api_calls
        if type_filter:
            calls = [c for c in calls if c.get("type") == type_filter]
        if url_filter:
            kw = url_filter.lower()
            calls = [c for c in calls if kw in (c.get("url") or "").lower()
                     or kw in (c.get("name") or "").lower()
                     or kw in (c.get("postData") or "").lower()]
        selected = calls[-limit:] if limit and limit > 0 else calls
        # 精简输出：只保留测试相关字段，避免撑爆上下文
        slim = []
        for c in selected:
            slim.append({
                "type": c.get("type"),
                "name": (c.get("name") or "")[:200],
                "url": (c.get("url") or "")[:300],
                "method": c.get("method"),
                "status": c.get("status"),
                "postData": (c.get("postData") or "")[:800],
                "result": c.get("result") if isinstance(c.get("result"), (dict, int, str)) else None,
                "error": c.get("error"),
                "ts": c.get("ts"),
            })
        return {
            "total_all": total_all,
            "total_matched": len(calls),
            "type_distribution": type_dist,
            "count": len(slim),
            "calls": slim,
        }

    async def _tool_replay_api(self, api_name, data=None):
        blk = self._guard_miniapp_conn("replay_api")
        if blk:
            return blk
        result = await self.wxapi.replay(api_name, data or {})
        return result

    async def _tool_capture_proxy(self, action="start", mode="local"):
        pc = getattr(self.state, "proxy_capture", None)
        if not pc:
            return {"ok": False, "error": "代理模块未初始化"}
        if action == "stop":
            return await pc.stop()
        r = await pc.start(mode=mode)
        # 启动后自动把代理并入捕获查询链路（get_wxapi_calls 会合并 proxy 流量）
        return r

    async def _tool_get_capture_detail(self, capture_id):
        """按 capture_id 下钻单条捕获完整数据包。

        解决自定义头隐身问题：slim 列表只回全部头名字+值预览，签名/凭证类完整值
        经这里拿；响应头（列表视图整个不回）与完整响应体也在此返回。
        响应体超 DATA_TOOL_MAX_CHARS 落盘 artifact（与工具结果同一读回机制）。
        """
        pc = getattr(self.state, "proxy_capture", None)
        if not pc:
            return {"error": "代理模块未初始化"}
        try:
            c = pc.get_capture(int(capture_id))
        except (TypeError, ValueError):
            return {"error": f"capture_id 非法: {capture_id}",
                    "hint": "capture_id 是 get_http_captures 返回里的负数序号（-1=最新）"}
        if not c:
            return {"error": f"capture_id 超出范围: {capture_id}",
                    "hint": "先重新 get_http_captures 获取本轮有效的 capture_id（每次调用重新编号）"}
        result = c.get("result") or {}
        body = result.get("body", "") if isinstance(result, dict) else ""
        full_body = body
        out = {
            "capture_id": int(capture_id),
            "ts": c.get("ts"),
            "url": c.get("url"),
            "method": c.get("method"),
            "status": c.get("status"),
            "request_headers": c.get("headers") or {},   # 全部头全值
            "postData": c.get("postData") or "",          # 完整请求体
            "response_headers": result.get("headers") if isinstance(result, dict) else None,
            "response_body": body,
        }
        if c.get("error"):
            out["error"] = c["error"]
        # 响应体超限落盘（add-on 侧 4000 截断时注明来源上限，防 AI 误判接口只回了这么多）
        max_len = 20000
        if len(out["response_body"]) > max_len:
            self._artifact_seq += 1
            aid = f"{int(time.time())}_{self._artifact_seq}_capture_detail"
            adir = os.path.join(self._artifacts_dir, self.current_sid or "adhoc")
            try:
                os.makedirs(adir, exist_ok=True)
                with open(os.path.join(adir, f"{aid}.txt"), "w", encoding="utf-8") as f:
                    f.write(out["response_body"])
                out["response_body"] = out["response_body"][:max_len]
                out["artifact_id"] = f"{self.current_sid or 'adhoc'}/{aid}.txt"
                out["note"] = f"响应体原 {len(full_body)} 字符，已存档可 read_artifact 分页读回"
            except Exception:
                out["note"] = "响应体存档失败，仅保留截断预览"
        if isinstance(result, dict) and result.get("body") and len(result.get("body", "")) >= 4000 \
                and result.get("body", "").endswith(("}", "]", '"')) is False and len(full_body) <= 4000:
            out.setdefault("note", "响应体为抓包层 4000 字符上限截断，并非接口返回全文")
        # 凭证头点名：AI 直接用这些原文重放，不要手抄（抄错教训）
        cred_names = [k for k in (c.get("headers") or {})
                      if k.lower() in (pc._cred_headers if hasattr(pc, "_cred_headers") else set())]
        if cred_names:
            out["replay_hint"] = (f"凭证头 {cred_names} 原文已在 request_headers 里，http_request 重放时"
                                  "省略 headers 让系统自动携带最新凭证，或从这里整段复制——禁止手抄长 token")
        return out

    async def _tool_get_http_captures(self, limit=30, url_filter=None):
        pc = getattr(self.state, "proxy_capture", None)
        if not pc:
            return {"error": "代理模块未初始化"}
        if not pc.running:
            return {"error": "捕获代理未启动，请先调用 capture_proxy(action='start')",
                    "hint": "local 模式（默认）启动后直接透明拦截 WeChatAppEx 进程流量，无需系统代理；"
                            "小程序里正常操作即可抓到业务流量。HTTPS 解密需已安装 mitmproxy CA 证书"}
        result = pc.get_captures(limit=limit, url_filter=url_filter)
        # 历史检索兜底（实测踩坑：长会话 325 条噪音把关键业务包滚出环形缓冲，
        # url_filter 返回 0 条，AI 只能重发请求拿假新包补证据）：当前缓冲查不到时
        # 自动落会话流量日志按 URL 子串检索——重放/并发/逻辑层请求全量留痕在
        # _traffic_log，历史包不用重发也能找回。命中的包标注留痕时间供判断新鲜度
        if result.get("count", 0) == 0 and url_filter:
            kw = str(url_filter).strip().lower()
            if kw:
                hits, seen = [], set()
                for t in reversed(getattr(self, "_traffic_log", []) or []):
                    u = str((t.get("meta") or {}).get("url", ""))
                    if kw not in u.lower():
                        continue
                    first_line = str(t.get("request", "")).splitlines()[0].strip() if t.get("request") else ""
                    if first_line in seen:
                        continue
                    seen.add(first_line)
                    hits.append({
                        "request": t.get("request", ""),
                        "response": t.get("response", ""),
                        "meta": {"url": u, "method": (t.get("meta") or {}).get("method", ""),
                                 "note": "历史留痕（非当前抓包窗口；来自此前主动请求的真实报文）"},
                    })
                    if len(hits) >= int(limit or 30):
                        break
                if hits:
                    result["count"] = len(hits)
                    result["captures"] = hits
                    result["source"] = "traffic_log_history"
                    result["hint"] = ("当前抓包窗口无此 URL（可能已滚出环形缓冲），以上来自会话流量日志的历史留痕。"
                                      "报文是当时真实收发的原文；若响应含 token 等时效性字段，"
                                      "以 get_credentials 重取的当前值为准")
        # 噪音提示：日志上报/埋点域名会淹没业务接口，且结果过大会被通用截断
        if not url_filter and result.get("count", 0) > 0:
            result["hint"] = ("未过滤时日志上报/埋点域名（如 tj./log./track. 开头）会占大头并触发截断。"
                              "找业务接口用 url_filter=关键字（如 order/pay/user）；"
                              "批量排除噪音可先看 url 分布再按业务域名过滤。"
                              "头值被截预览或标 suspect_cred_headers 的自定义签名头，"
                              "用 get_capture_detail(capture_id) 拿完整原文")
        else:
            result.setdefault("hint", "每条带 capture_id（-1=最新）；头值截预览/响应头需全文时 "
                                      "get_capture_detail(capture_id) 下钻单条完整数据包")
        # 0 流量诊断：代理在跑但拿不到包时，把关键链路状态一并回报，
        # 避免只回 total:0 让 AI 无法判断是「没流量」还是「链路坏了」
        if result.get("total", 0) == 0 and not url_filter:
            diag = pc.diagnostics()
            result["diagnostics"] = diag
            if diag.get("mitmdump_alive") and diag.get("jsonl_size", 0) > 0:
                result["hint"] = "子进程存活且捕获文件有数据但未入库：JSONL 解析线程可能滞后，稍候重试"
            elif diag.get("mitmdump_alive") and diag.get("elevated") is False:
                result["hint"] = ("local 模式子进程存活但服务非管理员权限，WinDivert 无法拦截进程流量 —— "
                                  "这是 0 流量的最常见原因。请以管理员身份重启服务（双击 启动Minihunt.bat）")
            elif diag.get("mitmdump_alive"):
                result["hint"] = ("代理链路正常但无流量：① 小程序流量可能未经过拦截（在微信中重新打开目标小程序）；"
                                  "② HTTPS 未装 mitmproxy CA 证书导致 TLS 握手失败（访问 http://mitm.it 安装）；"
                                  "③ 用户可能尚未在小程序中做任何操作")
        return result

    _WX_FINGERPRINT_DEFAULTS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "MicroMessenger/7.0.20.1781(0x67001435) XWEB/9135 Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://servicewechat.com/",
    }

    # 凭证类请求头名单：结果里回告 AI 实际带了哪些登录态（未授权测试证据链）
    _CRED_HEADER_NAMES = {"cookie", "authorization", "x-token", "token", "access-token",
                          "x-session-id", "sessionid", "x-csrf-token", "x-xsrf-token"}

    def _fingerprint_headers(self) -> dict:
        """重放请求的微信指纹头：优先从代理捕获的真实流量提取（目标域名最准），
        提取不到用通用 MicroMessenger UA 兜底。缺指纹时部分风控会软拦截并返回
        误导性业务错误（如「未找到订单」）而非 4xx，极易造成误判。"""
        picked = {}
        pc = getattr(self.state, "proxy_capture", None)
        if pc and pc.captures:
            for c in reversed(pc.captures[-200:]):
                hs = c.get("headers") or {}
                ua = next((v for k, v in hs.items() if k.lower() == "user-agent"), None)
                rf = next((v for k, v in hs.items() if k.lower() == "referer"), None)
                if ua and "MicroMessenger" in ua:
                    picked["User-Agent"] = ua
                if rf and rf.startswith("https://servicewechat.com/"):
                    picked["Referer"] = rf
                if len(picked) == 2:
                    break
        for k, v in self._WX_FINGERPRINT_DEFAULTS.items():
            picked.setdefault(k, v)
        return picked

    def _session_credential_headers(self) -> dict:
        """从捕获代理提炼的会话凭证构造请求头（重放时自动带上登录态）"""
        pc = getattr(self.state, "proxy_capture", None)
        if not pc or not pc.session_credentials:
            return {}
        headers = {}
        for k, v in pc.session_credentials.items():
            headers[k] = v
        return headers

    def _replay_headers(self, headers: dict, no_credentials: bool = False) -> dict:
        """重放请求头合成：凭证头 + 微信指纹（UA/Referer）+ 显式传入（优先级最高）。

        no_credentials=True 时不携带任何捕获的登录态凭证（Cookie/Authorization 等），
        用于纯未授权测试；指纹头（UA/Referer）保留，仍走客户端指纹防风控软拦截干扰判断。
        """
        merged = {} if no_credentials else self._session_credential_headers()
        merged.update(self._fingerprint_headers())
        if no_credentials:
            # 把显式传入的凭证头也屏蔽掉占位（如 Cookie: dummy_no_session 场景不再需要）
            for k in list(merged):
                if k.lower() in self._CRED_HEADER_NAMES:
                    del merged[k]
        merged.update(headers or {})
        return merged

    def _body_content(self, body, headers: dict, content_type=None):
        """请求 body 归一化：对象 → JSON 串；并按 body 形态补 Content-Type。
        网关按 Content-Type 头解析 body，JSON 报文缺 application/json 头时
        被当无效请求整包丢弃（share/getOrderInfo.json 实测踩坑：同报文带头即通）。
        规则：headers 已显式带 Content-Type 以用户为准；
        content_type 参数显式指定（表单接口场景）直接采用；
        对象 body 自动补 application/json；JSON 形态的字符串 body 也补；
        非对象且非 JSON 形态的字符串（表单串/加密报文）原样透传不强加头"""
        content = None
        if body is not None:
            content = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
            if any(k.lower() == "content-type" for k in headers):
                return content  # 用户显式传了，以用户为准（不改写）
            if content_type:
                headers["Content-Type"] = content_type
            elif not isinstance(body, str):
                headers["Content-Type"] = "application/json"
            elif content.lstrip()[:1] in ("{", "["):
                try:
                    json.loads(content)
                    headers["Content-Type"] = "application/json"
                except Exception:
                    pass
        return content

    def _credential_notice(self, merged_headers: dict) -> dict:
        """检查实际发出的请求头里带了哪些凭证类登录态，结果随工具返回，保证
        「未授权测试」的证据链可审计（此前自动带凭证导致无凭证测试不纯）。
        另做新鲜度核查：自动携带的凭证来自捕获快照，目标接口若做过 token 轮换
        （userLogin 每次进 tab 换 token），旧快照打新接口必 401——携带值与
        最新捕获的同名头不一致时警告「凭证可能已轮换」，指引重取而非误判漏洞"""
        creds = [k for k in merged_headers if k.lower() in self._CRED_HEADER_NAMES]
        out = {"credentials_sent": creds,
               "authenticated_request": bool(creds)}
        if creds:
            stale = self._stale_credential_notes(merged_headers)
            if stale:
                out["credential_warning"] = "；".join(stale)
        return out

    def _stale_credential_notes(self, merged_headers: dict) -> list:
        """自动携带凭证的新鲜度核查（手传凭证的比对走 _manual_cred_mismatch，
        此处只管「系统自动携带」这条路）。凭证头与最新捕获同头名的值不同 →
        token 已轮换（旧值打新接口大概率 401），提示从 get_credentials 重取"""
        pc = getattr(self.state, "proxy_capture", None)
        if not pc or not getattr(pc, "captures", None):
            return []
        notes = []
        # 最新 50 条捕获里同头名的最新值（倒序找，找到即停）
        for c in reversed(pc.captures[-50:]):
            hs = c.get("headers") or {}
            if not isinstance(hs, dict):
                continue
            hs_lc = {str(k).lower(): str(v) for k, v in hs.items() if v}
            for k in list(merged_headers):
                kl = str(k).lower()
                if kl in self._CRED_HEADER_NAMES and kl in hs_lc:
                    cur = str(merged_headers[k])
                    latest = hs_lc[kl]
                    # 历史轮换值命中（v1|v2 拼接或捕获历史）即视为新鲜，不告警
                    if cur == latest or cur in self._session_credential_history(kl):
                        continue
                    notes.append(
                        f"携带的 {k} 与最新捕获值不一致（token 可能已轮换）："
                        "本次请求若返回 401/403，优先 get_credentials 重取最新凭证再测，"
                        "不要直接定性为未授权漏洞")
                    break  # 每条捕获只出一次提示，避免 50 条捕获刷屏
            if notes:
                break
        return notes

    def _session_credential_history(self, header_lc: str) -> set:
        """同名凭证头在捕获记录里的全部历史值。
        会话内登录态轮换后（实测 7 个 token 并存），AI 手传的是其中某个
        历史有效 token——只比「最新值」会把有效凭证误报成抄错（credential_warning
        假警报全程骚扰，实际请求全部认证成功）。比对范围必须覆盖历史轮换值"""
        vals = set()
        pc = getattr(self.state, "proxy_capture", None)
        if not pc:
            return vals
        # ① 自动收编的凭证表：值可能是「v1|v2|v3」拼接或单值
        for k, v in (pc.session_credentials or {}).items():
            if str(k).lower() == header_lc:
                vals.update(x for x in str(v).split("|") if x.strip())
        # ② 全量捕获里同头名的真实出现值（权威：这是客户端真实发过的）
        for c in getattr(pc, "captures", []) or []:
            h = c.get("headers") or {}
            if isinstance(h, dict):
                for k, v in h.items():
                    if str(k).lower() == header_lc and v:
                        vals.add(str(v))
        return vals

    def _manual_cred_mismatch(self, explicit_headers: dict) -> list:
        """显式手传凭证头 vs 捕获的会话凭证逐一比对，同名不同值即列出。
        背景：AI 从截断预览里手抄长 token 抄错一位（签名段）→ 401 被误判为
        未授权漏洞。比对按共同前缀长度分级：前缀 <16 字符视为高度疑似抄错。"""
        if not isinstance(explicit_headers, dict) or not explicit_headers:
            return []
        sess = self._session_credential_headers()
        if not sess:
            return []
        sess_lc = {str(k).lower(): str(v) for k, v in sess.items()}
        out = []
        for k, v in explicit_headers.items():
            kl = str(k).lower()
            if kl not in self._CRED_HEADER_NAMES or kl not in sess_lc:
                continue
            ev = str(v)
            # 历史轮换值命中即放行：会话内 token 轮换过多次时，手传的历史
            # token 是真实有效凭证，不是抄错（假警报实测全程骚扰）
            if ev in self._session_credential_history(kl):
                continue
            sv = sess_lc[kl]
            if ev == sv:
                continue
            common = 0
            for a, b in zip(ev, sv):
                if a != b:
                    break
                common += 1
            sev = "高度疑似抄错" if common < 16 else "与捕获值不一致"
            out.append(f"{k}: {sev}（传入 len={len(ev)} vs 捕获 len={len(sv)}，共同前缀 {common} 字符）")
        return out

    async def _replay_request(self, url: str, method: str = "", body: str = "",
                              headers: list = None):
        """现场重发器：按给定 URL（可选方法/body/头）真实发一次请求，返回留痕包。
        用于「画报动作 ↔ 数据包」「报告步骤 ↔ 数据包」吻合性兜底——
        事后从流量里猜包已被实测证伪（扫描包混入/跨动作串包/同接口多轮错配），
        与其猜，不如按描述重发一次拿确定的包（自动带会话凭证与微信指纹）。
        返回 evidence 轮结构 {request, response, meta:{url,method,desc,note}}，失败返回 None"""
        try:
            url = str(url or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                return None
            r = await self._tool_http_request(url,
                                              method=str(method or "GET").upper(),
                                              headers=headers or None,
                                              body=body if body else None)
            if r.get("error") or not getattr(self, "_last_http_traffic", None):
                return None
            ev = self._last_http_traffic
            return {"request": ev.get("request", ""), "response": ev.get("response", ""),
                    "meta": {"url": ev.get("meta", {}).get("url", url),
                             "method": ev.get("meta", {}).get("method", method or "GET"),
                             "desc": self._round_desc(ev.get("request", ""), ev.get("response", "")),
                             "note": "按动作描述现场重发留痕"}}
        except Exception:
            return None

    def _record_traffic(self, request: str, response: str, url: str, method: str):
        """会话级流量日志：所有主动请求（http_request/concurrent/burst/wx_request）
        全量留痕报文原文，generate_report 按漏洞的 related_api(URL) 从这里直接解析
        数据包——_last_http_traffic 是单槽位（下一条即覆盖），历史报文一丢，
        报告数据包就无源可取（此前「报告没数据包」的直接原因之一）"""
        rec = {
            "request": str(request or "")[:10000],
            "response": str(response or "")[:10000],
            "meta": {"url": str(url or ""), "method": str(method or "")},
        }
        self._traffic_log.append(rec)
        # 500（原 200 实测滚出早期关键包——长会话 AI 被迫重发原包补证据，
        # 既多流量又多轮次）；单条最大 2 万字符，500 条最坏 10MB 可控
        if len(self._traffic_log) > 500:
            self._traffic_log = self._traffic_log[-500:]
        # 同时进「待消费」队列：registry_log 留痕时整批取走固化为本动作的 evidence。
        # 这是「测试时固化」的关键——每个测试动作实际发的包当场挂账，
        # 而不是事后从单槽位/全量日志里按接口猜（猜必错：XSS 提交 payload 的包
        # 会被后面的回读验证请求覆盖，画板上挂的就成了别的请求）
        self._pending_traffic.append(rec)
        if len(self._pending_traffic) > 20:
            self._pending_traffic = self._pending_traffic[-20:]

    def _traffic_log_hit(self, api_eps) -> str:
        """safe 降级前查全量流量日志（200 条）：本动作接口是否曾真实发过包。
        待消费队列只有 20 条（窗口机制），早前动作的包已被整批固化走，
        队列里查不到 ≠ 没发过——AI 复盘实锤：safe 动作被误降级 fail 全因只查队列。
        返回命中报文的请求行（含 URL），无命中返回空串。
        只做提示不自动挂包（守红线②：事后从全量日志挑包挂账易错绑）"""
        try:
            for t in reversed(getattr(self, "_traffic_log", []) or []):
                req = str(t.get("request", ""))
                if not req:
                    continue
                lines = req.splitlines()
                first = lines[0].strip() if lines else ""
                path = first.split(" ")[1] if len(first.split(" ")) > 1 else ""
                path = path.split("?", 1)[0]
                url_meta = str((t.get("meta") or {}).get("url", "")).split("?", 1)[0]
                if any(self._same_endpoint(p, e) for p in (path, url_meta) for e in api_eps):
                    return first or url_meta
        except Exception:
            pass
        return ""

    async def _tool_http_request(self, url, method="GET", headers=None, body=None, no_credentials=False):
        import httpx
        # 默认自动携带捕获到的会话凭证（Cookie/Authorization 等）与微信指纹头（UA/Referer），
        # 避免无指纹被风控软拦截返回误导性业务错误；显式传入的 headers 优先级最高。
        # no_credentials=true 用于未授权访问测试：不带任何登录态（结果里会标注凭证状态）
        explicit = headers if isinstance(headers, dict) else None
        merged = self._replay_headers(headers, no_credentials=bool(no_credentials))
        content = self._body_content(body, merged)
        # 手抄凭证防错：显式传了凭证头且与捕获值不一致时随结果告警（抄错一位的
        # 长 token 会导致 401 被误判为未授权漏洞）
        cred_warn = self._manual_cred_mismatch(explicit) if not no_credentials else []
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.request(
                    method, url,
                    headers=merged,
                    content=content,
                )
            text = resp.text[:20000]  # 对齐 DATA_TOOL_MAX_CHARS，避免商品列表等大响应关键字段丢失
            try:
                data = resp.json()
            except Exception:
                data = text
            # 暂存本次流量（标准 HTTP 报文格式），供 registry_log 留痕与报告数据包直接引用
            resp_body = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
            self._last_http_traffic = {
                "request": self._format_http_request(method, url, merged, content)[:8000],
                "response": f"HTTP/1.1 {resp.status_code}\n" +
                            "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) +
                            f"\n\n{resp_body[:8000]}",
                "meta": {"url": url, "method": method},
            }
            # 会话流量日志全量留痕（单槽位会被下一条覆盖，历史包丢了数据包就没了）
            self._record_traffic(self._last_http_traffic["request"],
                                 self._last_http_traffic["response"], url, method)
            out = {"status": resp.status_code, "headers": dict(resp.headers), "body": data,
                   **self._credential_notice(merged)}
            if cred_warn:
                out["credential_warning"] = "；".join(cred_warn)
                if resp.status_code in (401, 403):
                    out["credential_warning"] += (
                        "。⚠️ 本次 401/403 很可能是手抄凭证抄错所致，不是未授权漏洞："
                        "省略 headers 参数（自动携带捕获的会话凭证）重发一次核对；"
                        "或用 get_storage(key=...) 重取最新完整 token 后再传")
            return out
        except Exception as e:
            return {"error": str(e)}

    async def _tool_concurrent_request(self, url, method="GET", headers=None, body=None, count=10, content_type=None, no_credentials=False):
        """并发发送多个相同请求，测试竞态条件类业务逻辑漏洞"""
        import asyncio
        import httpx
        count = max(1, min(int(count or 10), 50))
        # 自动携带会话凭证与微信指纹（竞态测试必须在登录态+真实指纹下才有意义）
        merged = self._replay_headers(headers, no_credentials=bool(no_credentials))
        content = self._body_content(body, merged, content_type=content_type)
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                async def _one(i):
                    try:
                        resp = await client.request(
                            method, url,
                            headers=merged,
                            content=content,
                        )
                        try:
                            data = resp.json()
                        except Exception:
                            data = resp.text[:500]
                        return {"i": i, "status": resp.status_code, "body": data}
                    except Exception as e:
                        return {"i": i, "error": str(e)}
                results = await asyncio.gather(*[_one(i) for i in range(count)])
            # 竞态测试流量同样暂存为证据（标准报文格式，响应取全部结果摘要）
            self._last_http_traffic = {
                "request": self._format_http_request(method, url, merged, content)[:8000],
                "response": f"并发 x{count} 结果：{json.dumps(results, ensure_ascii=False)[:6000]}",
                "meta": {"url": url, "method": method, "count": count},
            }
            self._record_traffic(self._last_http_traffic["request"],
                                 self._last_http_traffic["response"], url, method)
            ok = sum(1 for r in results if r.get("status") == 200)
            bodies = {}
            for r in results:
                key = str(r.get("status")) + ":" + str(r.get("body", r.get("error", "")))[:120]
                bodies[key] = bodies.get(key, 0) + 1
            return {
                "total": count,
                "success_200": ok,
                "response_distribution": bodies,
                "results": results,
                **self._credential_notice(merged),
            }
        except Exception as e:
            return {"error": str(e)}

    async def _tool_burst_request(self, url, method="GET", headers=None, body=None, count=40, window_ms=1000, content_type=None, no_credentials=False):
        """高速并发：栅栏同步 + 连接预热，保证大量相同数据包在一个极短窗口内同时发出。

        与 concurrent_request 的区别：concurrent_request 是 gather 逐个调度（有毫秒级启动偏差，
        连接握手吃掉窗口时间）；burst_request 先预热好全部 keepalive 连接，再用 asyncio.Event
        栅栏让所有任务在同一事件循环刻度同时放行，真正逼近「同一瞬间 N 连发」。
        """
        import asyncio
        import time
        import httpx
        count = max(1, min(int(count or 40), 100))
        window_ms = max(100, min(int(window_ms or 1000), 5000))
        merged = self._replay_headers(headers, no_credentials=bool(no_credentials))
        content = self._body_content(body, merged, content_type=content_type)

        # 连接池限流：count 条连接全部预热，放行后无握手开销
        limits = httpx.Limits(max_connections=count, max_keepalive_connections=count)
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, limits=limits) as client:
                # 预热：对目标 host 先发 HEAD 请求把 TCP+TLS 连接建好放进 keepalive 池
                async def _warm():
                    try:
                        await client.head(url, headers=merged)
                    except Exception:
                        pass  # 预热失败不阻塞（有的接口不接受 HEAD，TLS 建立仍已完成）
                await asyncio.gather(*[_warm() for _ in range(min(count, 20))])
                await asyncio.sleep(0.2)  # 让连接完成入池

                # 栅栏：所有任务先挂起等待，同一瞬间放行
                gate = asyncio.Event()

                async def _one(i):
                    sent_at = None
                    try:
                        await gate.wait()
                        sent_at = time.perf_counter()
                        resp = await client.request(method, url, headers=merged, content=content)
                        try:
                            data = resp.json()
                        except Exception:
                            data = resp.text[:500]
                        return {"i": i, "status": resp.status_code, "body": data, "sent_at": sent_at}
                    except Exception as e:
                        return {"i": i, "error": str(e), "sent_at": sent_at}

                tasks = [asyncio.create_task(_one(i)) for i in range(count)]
                await asyncio.sleep(0.1)  # 确保全部任务都挂到 gate 上
                t0 = time.perf_counter()
                gate.set()  # 同一瞬间放行
                results = await asyncio.gather(*tasks)
                wall = (time.perf_counter() - t0) * 1000

            ok = sum(1 for r in results if r.get("status") == 200)
            bodies = {}
            for r in results:
                key = str(r.get("status")) + ":" + str(r.get("body", r.get("error", "")))[:120]
                bodies[key] = bodies.get(key, 0) + 1
            # 会话流量日志：栅栏齐发的竞态请求同样留痕（响应取逐包结果，可复现）
            self._record_traffic(
                self._format_http_request(method, url, merged, content)[:8000],
                f"burst x{count} @ {round(wall, 1)}ms 窗口，逐包结果：{json.dumps(results, ensure_ascii=False)[:6000]}",
                url, method)
            # 发送离散度：第一个发出到最后一个发出的时间差（栅栏同时性指标）
            sent_times = [r["sent_at"] for r in results if r.get("sent_at") is not None]
            spread_ms = (max(sent_times) - min(sent_times)) * 1000 if sent_times else None
            return {
                "total": count,
                "success_200": ok,
                "send_window_ms": round(wall, 1),
                "target_window_ms": window_ms,
                "send_spread_ms": round(spread_ms, 2) if spread_ms is not None else None,
                "within_target": wall <= window_ms,
                "response_distribution": bodies,
                "results": results,
                **self._credential_notice(merged),
            }
        except Exception as e:
            return {"error": str(e)}

    # ── 功能点登记册工具（发现 → 测试 → 闭环 强制跟踪） ──

    async def _tool_registry_add(self, name, entry="", api="", risk_hints=None, kind=None):
        out = self.feature_registry.add(name, entry=entry, api=api, risk_hints=risk_hints, kind=kind)
        # api 完整性提示：裸文件名（getOrderInfo.json）丢了网关路径前缀——
        # 对账补找/重发全按接口身份匹配，短路径经常查无此包（复盘实锤：
        # 登记成 getOrderInfo.json 的功能点证据全靠窗口兜底才挂上）
        api_txt = str(api or "").strip()
        if isinstance(out, dict) and out.get("ok") and api_txt:
            parts = [p.strip() for p in re.split(r"[,，;；\s]+", api_txt) if p.strip()]
            bare = [p for p in parts
                    if "/" not in p and "." in p
                    and not p.lower().startswith(("http://", "https://"))]
            if bare:
                out["warning"] = (
                    f"api 填了裸文件名（{', '.join(bare[:3])}），缺少网关路径前缀"
                    "（如 wsctrade/order/share/getOrderInfo.json）。证据对账按接口身份匹配，"
                    "不完整路径可能对不上真实包——从流量捕获（get_http_captures/请求响应）"
                    "复制完整路径后 registry_add 重登记覆盖")
        return out

    _API_NOISE = {"get", "post", "put", "delete", "request", "api", "index",
                  "http", "https", "token", "submit", "list", "detail", "test",
                  "order", "user", "data", "code", "info", "json", "true", "false",
                  # HTML/前端标签与通用技术词：intent 写「svg/img 标签」这类
                  # payload 描述曾被路径正则当接口抽出 → 对齐器假错配（实测踩坑）
                  "svg", "img", "image", "script", "body", "html", "div", "span",
                  "style", "path", "text", "view", "iframe", "form", "input",
                  "link", "meta", "head", "title", "table", "video", "audio",
                  "canvas", "onload", "onerror", "alert", "src", "href"}

    # 敏感字段名词表：intent 写「校验 password/salt/idcardNo 等字段」这类
    # 斜杠列举的组成词——各段全命中即判字段列举而非接口（AI 复盘实锤：
    # 此类列举被路径正则抽出当接口身份 → 对齐器假 misaligned 连环误报；
    # 实测补充：token/Cookie/Authorization 等鉴权头列举同样中招，一并收录）
    _FIELD_ENUM_WORDS = {"password", "passwd", "pwd", "salt", "idcard", "idcardno",
                         "id_card", "telephone", "phone", "mobile", "email",
                         "openid", "open_id", "session_key", "sessionkey",
                         "sessionid", "session_id", "unionid", "token", "jwt",
                         "cookie", "cookies", "authorization", "auth", "bearer",
                         "header", "headers", "useragent", "user_agent", "ua",
                         "referer", "origin", "sign", "signature", "timestamp",
                         "nonce", "appid", "app_id", "secret", "accesskey",
                         "access_key", "realname", "real_name", "bankcard",
                         "bank_card", "balance"}

    def _extract_apis(self, text: str, api_field: str = "") -> list:
        """从登记 api 字段与动作文本提取「接口身份」候选（供包对账白名单）。
        三种来源：完整 URL、反编译源码风格短路径（/addons/api/lc.order/detail、
        wscgoods/detail）、动作描述里写的调用路径（lc.order/detail、/api/recharge/submit、
        refund/list——写成 lc.order/cancel 与 lc.order/receipt 也各自单独提取）。
        此前只认登记 api + 文本里的 http:// 完整 URL，而登记 api 常是 AI 手写的
        乱码/错名/通配（/api/checkout/submitlc、/api/refund/*），动作文本里的
        短路径又全被忽略——接口白名单形同虚设，画报 6 个漏洞动作全部对不上包（实测实锤）"""
        out, seen = [], set()
        # 已知页面路由集：页面路径（packages/xxx/yyy、pages/index/index）不是接口
        # 身份——intent 描述「导航到 packages/trade/order/list」曾被当接口对账/
        # 触发重发，实锤 misaligned 假错配。页面路由不进接口白名单
        page_routes = set()
        try:
            for p in (self.navigator.pages if self.navigator else []):
                page_routes.add(str(p or "").strip().lstrip("/").split("?", 1)[0].rstrip("/").lower())
        except Exception:
            page_routes = set()

        def _add(u):
            # 幻影组合防护：漏拆的顿号/竖线连接串（「a、b」「a|b」整体进来）不是
            # 单一接口——顿号/竖线在合法 URL/路径里不出现，整串必是提取残留。
            # 整串参与对账永远匹配不上真实流量 → 假 misaligned（实测实锤），拆开各算
            for part in re.split(r"[、|｜]+", str(u or "")):
                _add_one(part)

        def _add_one(u):
            # 尾部标点剥除（半角+全角）：动作文本「调用 lc.order/detail。」
            # 句号/逗号粘在路径尾部 → 对齐永远差一字假错配（AI 复盘实锤）
            u = str(u or "").strip().rstrip(".,;:、。；：（）「」『』《》？！\"'")
            if len(u) < 4 or u.lower() in seen:
                return
            norm = u.lstrip("/").split("?", 1)[0].rstrip("/").lower()
            if norm and norm in page_routes:
                return  # 页面路由不是接口
            # 噪声段过滤：仅单段纯停词（GET /api）不是接口身份。多段不再做
            # 全停词过滤——user/index、order/detail 这类「两段全是高频词」的
            # 真实接口曾被整类误杀，对账白名单恒缺 → 假 misaligned + AI 修不动
            # 连环 StuckDetector（wxa33 实锤）；payload 噪声由 intent 卫生清洗
            # 拦截、字段列举由 _FIELD_ENUM_WORDS 规则覆盖，不受此放宽影响
            segs = [s for s in re.split(r"[/.]", u.lower()) if s]
            if len(segs) == 1 and segs[0] in self._API_NOISE:
                return
            # 斜杠列举过滤：各段全命中敏感字段名词表（password/salt/idcardNo）
            # = 字段列举描述，不是接口路径，不进对账白名单
            if len(segs) >= 2 and all(s in self._FIELD_ENUM_WORDS for s in segs):
                return
            if "*" in u:
                return
            seen.add(u.lower())
            out.append(u)

        if api_field:
            # 登记字段可能一条写多个接口（「a, b」「a、b」「a|b」），拆开各算。
            # 顿号/竖线此前漏拆：「a、b」整串当一个接口名对账必失败（实测实锤）
            for part in re.split(r"[,，;；、|｜\s]+", str(api_field)):
                _add(part)
        for m in re.findall(r"https?://[^\s'\"<>，。；）()、]+", text):
            _add(m)
        # 路径形态：斜杠分段 ≥2 段且含路径段（带不带前导 / 都收）。
        # 括号紧贴形态（如「校验(token/Authorization)」「(pages/index/index)」）是
        # 注释性列举/页面引用不是调用目标——括号直接贴着路径段说明这是解释文本
        # 而非动作里的请求描述，抽出必成假 misaligned（AI 复盘实锤），整体跳过
        _enum_text = re.sub(r"\((?:[^()（）]*/(?:[^()（）]*/)+[^()（）]*)\)", " ", text)
        _enum_text = re.sub(r"（(?:[^()（）]*/(?:[^()（）]*/)+[^()（）]*)）", " ", _enum_text)
        for m in re.findall(r"(?<![\w/])(?:/[a-zA-Z][\w-]*){2,}(?:/\w+)?", _enum_text):
            _add(m)
        for m in re.findall(r"(?<![\w/.])[a-zA-Z][\w-]*(?:/[\w-]+)+", _enum_text):
            _add(m)
        # 点分接口名（ThinkPHP 分发器路由）：lc.checkout/submit、lc.order/detail——
        # 名字里的点让上面的斜杠模式负向断言失效，必须单独提取；
        # 要求至少含一个字母（纯数字 0.01/版本号不是接口）
        for m in re.findall(r"(?<![\w/.])[a-zA-Z]\w*(?:\.\w+)+(?:/\w+)*", _enum_text):
            _add(m)
        return out[:8]

    # 发包类工具：动作本体就是发网络请求，收账时必须拿得到报文。
    # 拿不到报文（连接失败/超时/被 WAF 拦截无回包/窗口漏记）→ 自动判 fail，
    # 不允许留「无定性空轮」——实测实锤：这类动作 verdict 未定且 evidence 为空，
    # 画报只剩裸工具名+「失败」徽章、报告冒出空数据包
    _SEND_TOOLS = {"http_request", "wx_request", "replay_api",
                   "concurrent_request", "call_cloud"}

    def _auto_intent(self, tool: str, intent: str, api_field: str,
                     packets: list, result: str = "") -> str:
        """收账时 intent 为空的发包动作自动生成动作摘要（画报节点标题）。
        优先用报文请求行（最真实）：「POST /app/patient/user/userLogin」，
        多轮取首包；无报文时退登记 api；再退结论文本首句；绝不落裸工具名
        （画报卡片标题显示 http_request 不可读，实测踩坑）。
        带「篡改」语义的轮次在摘要中体现（如多个不同参数值的重放）"""
        cand = str(intent or "").strip()
        if cand:
            return cand
        # 首包请求行
        for t in packets or []:
            lines = str(t.get("request", "")).splitlines()
            first = lines[0].strip() if lines else ""
            if re.match(r"^[A-Z]+\s+\S+\s+HTTP/", first):
                cand = first.split(" HTTP/")[0].strip()
                break
        if not cand and api_field:
            cand = str(api_field).split(",")[0].split("，")[0].strip()[:80]
        if not cand:
            # 结论文本首句兜底（AI 写的动作描述/结果，可读性远优于工具名）
            head = re.split(r"[。；;\n]", str(result or ""))[0].strip()
            return (head or tool)[:120]
        # 多轮不同参数值 = 篡改/重放测试（非 UI 动作），补注语义
        if tool in self._SEND_TOOLS and len([t for t in (packets or []) if t.get("request")]) > 1:
            cand += "（多轮重放）"
        return cand[:120]

    async def _tool_registry_log(self, name, tool, intent="", result="", verdict="", key_packets=None):
        # 未登记自动补登记：先 log 后 add 的顺序失误不该返工一轮——
        # log 时发现功能点不在登记册，自动以 discovered 状态补入再记日志
        registered = {it["name"] for it in self.feature_registry.list_items()}
        if str(name)[:120] not in registered:
            self.feature_registry.add(str(name)[:120],
                                      entry="（registry_log 自动补登记）")
        # ── 两段式就地绑定（替代事后按锚点猜包，实测猜必错） ──
        # 每个测试动作分两段留痕，时序天然界定「这个动作用了哪些包」：
        #   段1 result 空：记意图 → 清空待消费队列（开收集窗口，从此刻起
        #     所有发包都归属本动作，直到下一段或下一条意图留痕）；
        #   段2 result 有：记结论 → 窗口内收到的包**整批**固化为该动作 evidence。
        # 窗口协议下无需锚点对账（包本来就是这个动作发的），锚点过滤
        # 只作为兜底路径的辅助（全量流量日志补找时防扫描包混入）。
        has_result = bool(str(result or "").strip())
        if not has_result:
            # 段1：意图留痕 = 开窗口。清队列，此后的发包全归本动作
            # （先记意图后发包的规范用法下，窗口边界即动作边界）
            self._pending_traffic = []
            # intent 卫生清洗（实测踩坑：payload 文本混入 intent 会产出假接口名，
            # 对齐器误报错配）。两版教训：v1 拒收要求重调——打断了「开窗→发包→收账」
            # 时序，AI 只能笔记留痕后返工；v2 用了未导入的 _re 抛 NameError 间歇性
            # 故障（段1 必炸段2 正常，时好时坏实锤）。v3 自动清洗：直接修好 intent
            # 继续开窗，AI 无感，时序不断
            clean = str(intent or "").strip()
            dirty_notes = []
            # ① payload/报文片段（标签/XML/JS 伪协议）：截到标签出现处
            m = re.search(r"<\w+[\s>]|<\?xml|javascript:", clean, re.IGNORECASE)
            if m or "svg" in clean.lower():
                cut = m.start() if m else clean.lower().find("svg")
                if cut > 12:  # 截断后仍保留动作主干
                    dirty_notes.append(f"截掉混入的 payload 片段（{clean[cut:cut+30]}…）")
                    clean = clean[:cut].rstrip(" ;；,，:：")
                else:  # 主干太短整条丢弃标签部分后仍可用 → 只告警不截
                    dirty_notes.append("疑似 payload 混入但主干过短未截断，请检查 intent 内容")
            # ② 过长压缩：动作描述保留首句/前 120 字（接口名几乎总在开头）
            if len(clean) > 120:
                head = re.split(r"[。；;\n]", clean)[0]
                clean = (head if len(head) <= 120 else clean[:120]).rstrip(" ;；,，:：")
                dirty_notes.append(f"intent 过长已压缩至 {len(clean)} 字符")
            if dirty_notes:
                intent = clean
            return self.feature_registry.log(name, tool, intent=intent, result=result, verdict=verdict)

        # 段2：结果留痕 = 收窗口。收账分流（实测踩坑：safe/fail 动作也挂数据包 →
        # 画板出现「无结论却有包」的动作、报告复现图文对不齐）：
        #   verdict=vuln → 照常收包固化 + 两项语义级检查（只 warning 不拒收——
        #                  500 错误页泄露/SQL 报错回显本身就是漏洞证据，
        #                  按状态码拒收会把真漏洞拦掉）；
        #   verdict=safe/fail → 包一律不落 evidence（fail 的包不是漏洞证据；
        #                  safe 的对照证据只以文字留痕），报告复现不引用；
        #                  兜底补找/重发/代理捕获全跳过——给失败动作补包
        #                  反而会把无关流量挂成它的证据
        v_norm = self.feature_registry._norm_verdict(verdict)
        # ── 收账强制化（发包类工具必须拿得到报文）──
        # 发包类动作收账时窗口里一个包都没有 = 报文没被捕获（连接失败/超时/
        # WAF 拦截无回包/窗口漏记）。此前直接落库 → verdict 未定且 evidence 空，
        # 画报冒出「裸工具名+失败徽章」的空轮、报告出现空数据包（实测实锤）。
        # 此处自动改判 fail 并写明原因；AI 已显式定性 fail 时尊重其判定；
        # AI 判 vuln 但无包时不在此处吞——走下方兜底补找，仍无包由语义检验揪出
        if tool in self._SEND_TOOLS:
            has_pending = any(t.get("request") for t in list(getattr(self, "_pending_traffic", []) or []))
            if not has_pending and v_norm not in ("vuln", "fail"):
                # safe 降级前先查全量流量日志（500 条）：待消费队列只有 20 条
                # （早前动作的包已整批固化走），队列查不到 ≠ 没发过——AI 复盘
                # 实锤：safe 动作被误降级 fail 全因只查队列。流量日志命中 =
                # 报文确实发过，保留 safe 定性 + 指引用 get_http_captures 取回，
                # 不自动挂包（守红线②：事后挑包挂账易错绑）
                traffic_hit = ""
                if v_norm == "safe":
                    _api_field = ""
                    for it in self.feature_registry.list_items():
                        if it["name"] == str(name)[:120]:
                            _api_field = it.get("api", "") or ""
                            break
                    hit_eps = self._extract_apis(f"{intent} {result}", _api_field)
                    traffic_hit = self._traffic_log_hit(hit_eps)
                if traffic_hit:
                    result = str(result or "").strip() or "动作已完成"
                    result += (f"（报文已在流量日志中留痕：{traffic_hit[:120]}。"
                               "用 get_http_captures(url_filter=该接口) 取回后重新 registry_log 收账，"
                               "key_packets 填返回的报文即可挂上证据；本次维持 safe 定性）")
                else:
                    result = str(result or "").strip()
                    if result:
                        result += "（发包未捕获到报文，按失败处理：连接失败/超时/无回包）"
                    else:
                        result = "发包未捕获到报文（连接失败/超时/被拦截无回包），动作无结论"
                    if v_norm == "safe":
                        result += "（原判定 safe，但无报文佐证，已自动改判 fail）"
                    verdict = "fail"
                    v_norm = "fail"
        # 段2 verdict 强制（实测实锤：AI 收账漏传 verdict → unknown 落库，
        # 画报动作没有状态标记、报告覆盖度统计失真）。上方自动改判链走完后
        # 仍无定性 = AI 真的没给结论 → 拒收并要求补传。拒收发生在窗口清空
        # 之前，_pending_traffic 与段1 意图条目原样保留，AI 补定性重调时
        # 原位覆盖收账，数据包一条不丢
        if not v_norm:
            return {"error": "registry_log 记结论（result 非空）时 verdict 必填："
                             "vuln=证实漏洞 / safe=证实无漏洞 / fail=动作失败无结论。"
                             "请按本动作真实结果补上定性后重新调用（intent 与本条保持一致，"
                             "系统原位覆盖收账，窗口内数据包不丢）"}
        # 接口身份：登记 api（拆分/清洗）+ 动作文本里的完整 URL 与短路径
        # （窗口绑定不依赖它；兜底补找/重发/代理捕获用它判定同源，防串包）
        api_field = ""
        for it in self.feature_registry.list_items():
            if it["name"] == str(name)[:120]:
                api_field = it.get("api", "") or ""
                break
        if v_norm in ("safe", "fail"):
            pending_all = [t for t in list(getattr(self, "_pending_traffic", []) or []) if t.get("request")]
            self._pending_traffic = []
            # intent 空的收账动作自动补摘要（画报标题）：发包类按报文生成，
            # 其余按登记 api 兜底——裸工具名节点（实测踩坑）就是这里漏补
            intent = self._auto_intent(tool, intent, api_field, pending_all, result)
            if v_norm == "safe" and pending_all:
                # 收账安全网：判定「无漏洞」但窗口包响应疑似含业务数据（HTTP 200
                # 且数据体非空）→ 提示复核（语义级 warning，绝不按状态码自动拒收）
                for t in pending_all:
                    resp = str(t.get("response", ""))
                    first = resp.splitlines()[0].strip() if resp.splitlines() else ""
                    if not re.match(r"HTTP/[\d.]+\s+200\b", first):
                        continue
                    body = resp.split("\n\n", 1)[-1]
                    if len(body) >= 60 and re.search(r"\{|：|数据|list|items|success|\"code\"", body[:300], re.I):
                        return {**self.feature_registry.log(name, tool, intent=intent, result=result, verdict=verdict),
                                "warning": "判定无漏洞（safe）但该动作窗口包响应疑似含业务数据（HTTP 200 + 数据体），"
                                           "请复核定性：确属漏洞则重测并以 verdict=vuln + key_packets 收账"}
            return self.feature_registry.log(name, tool, intent=intent, result=result, verdict=verdict)
        evidence = None
        warnings = []
        # 接口身份：登记 api（拆分/清洗）+ 动作文本里的完整 URL 与短路径
        # （窗口绑定不依赖它；兜底补找/重发/代理捕获用它判定同源，防串包）
        api_eps = self._extract_apis(f"{intent} {result}", api_field)
        # 动作声明目标（intent + 登记 api）：只有它才允许触发兜底重发。
        # result 是结论文本——里面凭空写出未实测的接口名（描述性措辞/推测）
        # 曾被兜底链当目标现场重发，把没测过的包挂成本动作证据（复盘实锤：
        # result 提及接口 ≠ 实测过该接口）
        intent_eps = self._extract_apis(f"{intent} {api_field}")
        pending = [t for t in list(getattr(self, "_pending_traffic", []) or []) if t.get("request")]
        self._pending_traffic = []
        if pending:
            # 窗口过滤：段1~段2 之间可能混入其他工具的扫描/探测包
            # （.env/.git/actuator/druid 等），真测试动作不会去打这些路径——
            # ① 明显探测路径直接剔除（动作文本里明确点名该路径则豁免）；
            # ② api_eps 非空时只保留与动作接口同源的包，一个都不匹配则
            #    退回①过滤后的整批（接口措辞差异时不至于丢光现场包）
            def _path_of(t):
                lines = str(t.get("request", "")).splitlines()
                first = lines[0].strip() if lines else ""
                path = first.split(" ")[1] if len(first.split(" ")) > 1 else ""
                path = path.split("?", 1)[0]
                return path or str((t.get("meta") or {}).get("url", "")).split("?", 1)[0]

            junk_hints = (".env", ".git", "actuator", "druid", "swagger",
                          "api-docs", "phpinfo", "phpmyadmin", "wp-admin", "wp-login")
            kept = [t for t in pending
                    if not (any(h in _path_of(t).lower() for h in junk_hints)
                            and not any(self._same_endpoint(_path_of(t), e) for e in api_eps))]
            if api_eps:
                matched = [t for t in kept
                           if any(self._same_endpoint(_path_of(t), e) for e in api_eps)]
                if matched:
                    kept = matched
            # AI 指认关键包优先（verdict=vuln 时 AI 用特征串点选证明漏洞的包）：
            # 窗口里先失败后成功的重试包、基线包都会整批进来，默认顺序取前几轮
            # 会把失败包挂成证据（实测实锤：评价动作挂了 order_id=1 的 500 包，
            # 真正成功的 CZ... 订单包被首行去重挤掉）。AI 指认的特征串
            # （路径段+参数值）逐一与报文原文匹配，命中的包排前面，
            # 其余包仍保留在后（上下文完整），note 标注来源
            kp_hints = [str(s).strip() for s in (key_packets or []) if str(s).strip()]

            def _pkt_text(t):
                return f"{t.get('request', '')}\n{(t.get('meta') or {}).get('url', '')}\n{t.get('response', '')[:400]}"

            def _hits(t):
                if not kp_hints:
                    return 0
                txt = _pkt_text(t).lower()
                n = 0
                for h in kp_hints:
                    parts = [p.strip().lower() for p in re.split(r"[+＋]|,|，", h) if p.strip()]
                    if parts and all(p in txt for p in parts):
                        n += 1
                return n

            key_note = ""
            if kp_hints and kept:
                scored = sorted(kept, key=lambda t: -_hits(t))
                if _hits(scored[0]) > 0:
                    ranked = [t for t in scored if _hits(t) > 0] + \
                             [t for t in scored if _hits(t) == 0]
                    kept = ranked
                    key_note = "AI 指认的关键数据包（证明漏洞）"
            evs, seen_first = [], set()
            for t in kept:
                # 去重：请求行（method+path+query）一致视为同一包的重复发送
                first_line = str(t["request"]).splitlines()[0].strip() if str(t.get("request")).splitlines() else ""
                if first_line and first_line in seen_first:
                    continue
                if first_line:
                    seen_first.add(first_line)
                evs.append({"request": t.get("request", ""), "response": t.get("response", ""),
                            "meta": {"url": (t.get("meta") or {}).get("url", ""),
                                     "method": (t.get("meta") or {}).get("method", ""),
                                     "desc": self._round_desc(t.get("request", ""), t.get("response", "")),
                                     "note": (key_note or "测试动作当时实际收发的数据包")
                                             + ("" if not _hits(t) else "（AI 指认）")}})
            if evs:
                evidence = evs[0] if len(evs) == 1 else {"rounds": evs, "multi": True}
        # AI 跳过段1直接记结果（旧习惯/合并留痕）→ 无窗口可用：
        # 按动作文本锚点+接口身份从全量流量日志补找（旧逻辑，防错配的过滤保留）
        if not evidence and api_eps:
            anchors = self._evidence_anchors(f"{intent} {result}", api_field)

            def _ep_of(t):
                return self._req_url(str(t.get("request", ""))) or str((t.get("meta") or {}).get("url", ""))

            def _match(t):
                u = _ep_of(t)
                if not u or not any(self._same_endpoint(u, e) for e in api_eps):
                    return False
                if not anchors:
                    return True  # 接口对上即可（无参数锚点时）
                text = f"{t.get('request', '')}\n{(t.get('meta') or {}).get('url', '')}"
                return any(a in text for a in anchors)

            found, seen_first = [], set()
            for t in reversed(self._traffic_log):
                if not _match(t) or not t.get("request"):
                    continue
                first_line = str(t["request"]).splitlines()[0].strip() if str(t.get("request")).splitlines() else ""
                if first_line and first_line in seen_first:
                    continue
                if first_line:
                    seen_first.add(first_line)
                found.append({"request": t.get("request", ""), "response": t.get("response", ""),
                              "meta": {"url": (t.get("meta") or {}).get("url", ""),
                                       "method": (t.get("meta") or {}).get("method", ""),
                                       "desc": self._round_desc(t.get("request", ""), t.get("response", "")),
                                       "note": "测试动作当时实际收发的数据包（自流量日志按接口锚点补找）"}})
                if len(found) >= 4:
                    break
            if found:
                evidence = found[0] if len(found) == 1 else {"rounds": list(reversed(found)), "multi": True}
        # 兜底 2：现场重发——只按动作声明目标（intent+登记 api）取 URL 重发，
        # result 文本里的接口名不参与（结论文本凭空提及 ≠ 实测过，重发会把
        # 没测过的包挂成本动作证据，错误证据比没有更糟）
        if not evidence and intent_eps:
            replay_url = next((u for u in intent_eps if str(u).lower().startswith(("http://", "https://"))), "")
            if not replay_url:
                for e in intent_eps:
                    full = self._kw_ep(str(e), self._traffic_log)
                    if str(full).lower().startswith(("http://", "https://")):
                        replay_url = full
                        break
            if replay_url:
                ev = await self._replay_request(replay_url)
                if ev:
                    evidence = ev if isinstance(ev, dict) and ev.get("request") else evidence
        # 兜底 3：代理捕获——代理通道下「UI 触发 → get_http_captures 读取」的
        # 动作不走 http_request，窗口/流量日志里都没有它的包；按登记接口
        # 从代理捕获里取同源最新一轮（UI 动作自己的包，非主动发不重发）
        if not evidence and intent_eps:
            try:
                caps = list(getattr(self.state.proxy_capture, "captures", []) or [])
            except Exception:
                caps = []
            for c in reversed(caps):
                u = str(c.get("url", ""))
                if u and any(self._same_endpoint(u, e) for e in intent_eps):
                    ev = self._packet_evidence(c)
                    if ev.get("request"):
                        ev["meta"] = {"url": u, "method": str(c.get("method", "GET")),
                                      "desc": self._round_desc(ev.get("request", ""), ev.get("response", "")),
                                      "note": "代理捕获的同接口数据包（UI 触发动作）"}
                        evidence = ev
                    break
        # 语义级检查（只 warning 不拒收——500 错误页泄露/SQL 报错回显本身就是
        # 漏洞证据，任何按状态码/关键词的硬拒收都会把真漏洞拦掉）：
        # ① 结论宣称的响应特征（如 code:200/orderId）在窗口包响应里全部找不到
        #    → 疑似挂错包或结论凭空写，提示复核；
        # ② verdict=vuln 却未传 key_packets 或特征串零命中 → 无法定位证明包
        ptext = f"{intent} {result}"
        if pending:
            resp_all = "\n".join(str(t.get("response", "")) for t in pending)
            claims = [s.strip() for s in re.findall(r"(?:code|status)[\"'\s:：=]*(\d{3})", ptext)]
            if claims and resp_all and not any(c in resp_all for c in claims):
                warnings.append("结论宣称的响应特征（如 code:" + claims[0] + "）在本动作窗口包响应中未出现，"
                                "请复核数据包是否挂错、结论是否凭空书写")
            kp_missing = (not kp_hints) or (not any(_hits(t) for t in pending))
            if kp_missing:
                warnings.append("verdict=vuln 但 key_packets 未传或与窗口包零命中：系统无法定位证明漏洞的关键包，"
                                "报告将默认取窗口全部包——请补测并用特征串（路径段+参数值）指认")
        # intent 空的收账动作自动补摘要（画报标题）：优先报文请求行，退登记 api。
        # 发包类动作收账后仍无任何报文（兜底链全落空）→ 结果里写明留痕缺失原因，
        # 杜绝「无定性空轮」落库（画报裸工具名+报告空包的根源，实测实锤）
        ev_packets = ([t for t in pending] if pending else
                      (list((evidence or {}).get("rounds") or [])
                       if isinstance(evidence, dict) and evidence.get("multi")
                       else ([evidence] if evidence else [])))
        intent = self._auto_intent(tool, intent, api_field, ev_packets, result)
        if tool in self._SEND_TOOLS and not evidence and not result.strip():
            result = "发包未捕获到报文（连接失败/超时/被拦截无回包），动作无结论"
            verdict = verdict or "fail"
        return self.feature_registry.log(name, tool, intent=intent, result=result, evidence=evidence, verdict=verdict,
                                         warnings=warnings)

    # ── 自检：动作 ↔ 数据包对齐审计（写完画报/写报告前强制核对） ──

    # 天然无 HTTP 包的工具：动作本体是本地状态读取/页面导航/静态源码检索，
    # 不产生网络流量，证据对账时不该报 no_evidence（此前 navigate_to/get_storage
    # 动作 8 次自检次次进 no_evidence，ok:true 后 warning 仍在骚扰，全是噪音）
    _NO_PACKET_TOOLS = {
        "navigate_to", "switch_tab", "navigate_back", "get_storage", "get_page_state",
        "ui_snapshot", "search_decompiled", "read_decompiled_file", "extract_identifiers",
        "get_app_info", "get_http_captures", "reconnect_engine",
        "registry_add", "registry_update_state", "registry_list",
        "beautify_code", "get_code_context", "find_references",
        "save_notes", "get_notes", "plan_set", "plan_update",
    }

    def _audit_evidence_alignment(self, sid=None) -> dict:
        """逐功能点核对「动作描述提到的接口 ↔ evidence 轮报文 URL」是否同源。
        只读不改；输出错配清单（want=动作文本里的接口，got=证据里的报文 URL）
        与无证据动作清单，供 AI 修复（重走两段式留痕）。
        extracted_apis 明细：每动作列出提取的接口候选与逐个比对结果——
        黑盒比对时 AI 只能反复试错（同一写法此处过彼处不过却不知道为什么，
        实测一个尾斜杠差异试了 4 轮），白盒化后一眼看懂差在哪"""
        problems, no_ev, details = [], [], []
        total = 0
        for it in self.feature_registry.list_items(sid):
            fname = it.get("name", "")
            # 复用登记册压实：分裂合并+重测去重+清半截（与画板视图同口径）
            for _, lg in self.feature_registry.compact_log(it.get("test_log", [])):
                total += 1
                text = f"{lg.get('intent', '')} {lg.get('result', '')}"
                # 无 HTTP 包工具（本地动作）直接豁免：留痕合法，无需证据包
                if str(lg.get("tool", "")) in self._NO_PACKET_TOOLS:
                    continue
                ev = lg.get("evidence")
                if not ev:
                    # no_evidence 分档（AI 复盘实锤：噪音淹没真缺口）——
                    # 只有 verdict=vuln 的动作缺包才是真问题（报告复现缺包）；
                    # safe/fail 本就无需包（safe 对照只留文字、fail 的包不是
                    # 漏洞证据），unknown 是半截动作，全部不再计数告警
                    if self.feature_registry._norm_verdict(lg.get("verdict")) == "vuln":
                        no_ev.append({"feature": fname, "action": str(lg.get("intent", ""))[:80]})
                    continue
                rounds = ev.get("rounds", []) if isinstance(ev, dict) and ev.get("multi") else [ev]
                urls = []
                for r in rounds:
                    if not isinstance(r, dict):
                        continue
                    u = self._req_url(str(r.get("request", ""))) or str((r.get("meta") or {}).get("url", ""))
                    if u:
                        urls.append(u)
                if not urls:
                    continue
                eps = self._extract_apis(text, it.get("api", "") or "")
                if not eps:
                    continue  # 动作文本没提接口（纯 UI 点击等）无法核对
                # 白盒明细：逐接口标注比对结果（hit=与某证据报文同源；
                # miss=未命中——对照报文 URL 看，写法差异一眼定位）
                per_ep = [{"api": str(e)[:80],
                           "match": any(self._same_endpoint(u, e) for u in urls)}
                          for e in eps]
                details.append({"feature": fname,
                                "action": str(lg.get("intent", ""))[:60],
                                "candidates": per_ep})
                if not any(c["match"] for c in per_ep):
                    problems.append({
                        "feature": fname,
                        "action": str(lg.get("intent", ""))[:80] or str(lg.get("tool", "")),
                        "动作提到的接口": [str(e)[:80] for e in eps[:3]],
                        "证据里的报文": [u[:100] for u in urls[:4]],
                    })
        return {"total": total, "no_evidence": no_ev, "misaligned": problems,
                "extracted_apis": details}

    # ── A' 报告参数落盘瘦身 ──
    # generate_report 的 findings/description/reproduction 等巨型参数写进 history 后
    # 永不压缩，之后每一轮请求整包重发（复利），是 token 消耗的最大单一来源。
    # 报告落库成功后原文已持久化进独立报告存储，画报/报告/登记册读取链路均不经过
    # 聊天 history——此处只把对话管道层的巨型 args 换成「摘要+说明」，数据链零接触
    # （红线②：registry 的 test_log/confirmed_packets 不在瘦身对象里，永不触碰）
    _REPORT_ARGS_SHRINK_CHARS = 4000   # args 序列化超过该值才瘦身（小参数不动）
    _SHRINK_FINDINGS_MAX = 30          # 摘要最多保留的 findings 条数

    def _shrink_report_call_args(self, hist, call_id):
        """把 history 中指定 tool_call_id 的 generate_report 巨型 arguments
        就地替换为摘要（title+findings_brief+瘦身说明）。
        仅在报告落盘成功后调用；结构不动（tool_calls 与 tool 回执的配对关系
        原样保留，不会产生孤儿 tool 消息），只换 args 内容"""
        try:
            for m in reversed(hist):
                if m.get("role") != "assistant" or not m.get("tool_calls"):
                    continue
                for tc in m["tool_calls"]:
                    if tc.get("id") != call_id:
                        continue
                    args = tc.get("arguments") or {}
                    raw = json.dumps(args, ensure_ascii=False)
                    if len(raw) < self._REPORT_ARGS_SHRINK_CHARS:
                        return  # 小参数不值得动
                    brief = []
                    for f in (args.get("findings") or [])[:self._SHRINK_FINDINGS_MAX]:
                        if isinstance(f, dict):
                            brief.append({
                                "title": str(f.get("title", ""))[:60],
                                "feature": str(f.get("feature", ""))[:60],
                                "severity": str(f.get("severity", "")),
                            })
                    tc["arguments"] = {
                        "title": str(args.get("title", ""))[:100],
                        "findings_brief": brief,
                        "_shrunk": (
                            f"本次 generate_report 已成功落盘，原参数共 {len(raw)} 字符，"
                            "已按上下文管理策略瘦身（仅保留 findings 摘要）。完整报告以"
                            "报告存储版本为准（报告页可见，含系统自动填充的真实数据包），"
                            "无需回读本参数。需要调整报告时重新调用 generate_report，"
                            "按工具描述增量产出 findings（系统自动填充真实数据包，"
                            "禁止手写 packets 报文）"),
                    }
                    return
        except Exception:
            pass  # 瘦身失败不影响主流程（报告已落盘，后续压缩自然会处理）

    def _shrink_saved_report_args(self, hist):
        """任务启动/history 回载时清扫历史遗留的巨型 generate_report args：
        仅当该调用后面跟着 ok=true 的工具回执（报告确已落盘）才瘦身；
        失败调用（ok=false，AI 正按 issues 修正）不动——修正循环依赖原参数。"""
        try:
            results = {m.get("tool_call_id"): m for m in hist
                       if m.get("role") == "tool" and m.get("tool_call_id")}
            for m in hist:
                if m.get("role") != "assistant" or not m.get("tool_calls"):
                    continue
                for tc in m["tool_calls"]:
                    if tc.get("name") != "generate_report":
                        continue
                    tr = results.get(tc.get("id", ""))
                    if not tr:
                        continue
                    try:
                        parsed = json.loads(tr.get("content") or "")
                        ok_saved = isinstance(parsed, dict) and parsed.get("ok") is True
                    except Exception:
                        ok_saved = False
                    if not ok_saved:
                        continue
                    raw = json.dumps(tc.get("arguments") or {}, ensure_ascii=False)
                    if len(raw) >= self._REPORT_ARGS_SHRINK_CHARS:
                        self._shrink_report_call_args(hist, tc.get("id", ""))
        except Exception:
            pass

    async def _tool_self_check_evidence(self):
        # B' 增量自检：与上次自检结果一致（登记册无新动作、无修复动作）时只回
        # unchanged 短回执——此前每次全量返回 extracted_apis 逐候选明细（数百行），
        # AI 反复查对时同一份大 JSON 反复进上下文烧 token。签名覆盖审计输出全文，
        # 任何动作/证据/接口提取变化都会改变签名触发全量下发
        r = self._audit_evidence_alignment()
        sig = hashlib.sha256(json.dumps(
            r, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        if sig == getattr(self, "_last_evidence_check_sig", None):
            # unchanged 快路径必须如实转述上次结论：上次就有 misaligned/no_evidence
            # 时硬编码「全部对齐」是假绿灯——AI 修不动时反复重跑 self_check 拿 ok，
            # 真问题被掩盖，直到报告侧审计才暴露（口径不一致，wx562 实测踩坑）
            brief = getattr(self, "_last_evidence_check_brief", {}) or {}
            if brief.get("misaligned") or brief.get("no_evidence"):
                return {"ok": False, "unchanged": True,
                        "conclusion": ("自检结果与上次一致且仍有未修复问题："
                                       f"{brief.get('misaligned', 0)} 个动作证据包与描述对不上、"
                                       f"{brief.get('no_evidence', 0)} 个 vuln 动作缺证据包。"
                                       "明细见上一次全量自检返回（可说明具体功能点单独复查）——"
                                       "先修复再生成报告，禁止带着未修复问题直接调 generate_report。"
                                       "本工具有签名缓存：登记册无变化时重跑必返回同一结论，"
                                       "勿原样重跑（重跑会触发卡死警报）——修复方向是按上次明细"
                                       "重走两段式留痕，或修正动作描述里写错/写偏的接口名"),
                        "last_check_summary": brief}
            return {"ok": True, "unchanged": True,
                    "conclusion": ("自检结果与上次完全一致（无新动作、无变化）：全部动作的"
                                   "描述与数据包对齐，无需修复，可直接进入报告生成。"
                                   "如需查看明细请说明具体功能点，单独复查该点"),
                    "last_check_summary": getattr(self, "_last_evidence_check_brief", {})}
        self._last_evidence_check_sig = sig
        self._last_evidence_check_brief = {
            "total": r.get("total"), 
            "no_evidence": len(r.get("no_evidence") or []),
            "misaligned": len(r.get("misaligned") or [])}
        out = {"ok": not r["misaligned"], **r}
        if r["misaligned"]:
            out["must_fix"] = (f"{len(r['misaligned'])} 个动作的证据包与动作描述对不上（见 misaligned）。"
                               "修复方式：对每个错配动作重走两段式留痕——registry_log 段1 的 intent 必须"
                               "与原动作**逐字相同**（同工具+同意图会自动原位覆盖旧记录，不会堆重复动作），"
                               "result 留空开窗口 → 只发该动作自己的包 → 段2 填结论收账，"
                               "修完再跑本工具复查，全绿才能写报告。"
                               "【对齐规则】提取器逐字比对动作文本与报文请求行：接口路径必须与包里路径一致"
                               "（尾斜杠/大小写差异会判 miss，见 extracted_apis 逐候选 match 明细）；"
                               "路径后直接接中文或标点会导致提取失败，路径写完加空格或句号收尾")
        elif r["no_evidence"]:
            out["warning"] = (f"{len(r['no_evidence'])} 个已定性 vuln 的动作没有证据包（见 no_evidence）："
                              "漏洞动作缺包 = 报告复现缺数据包。对每个动作重走两段式留痕补包"
                              "（段1 intent 与原动作逐字相同 → 只发该动作自己的包 → 段2 以 "
                              "verdict=vuln 收账）；safe/fail 动作无需包，不在检查范围")
        if out.get("ok"):
            out["conclusion"] = "自检通过：全部动作的描述与数据包对齐"
        return out

    # AI 真对比检验的每包原文截断（请求+响应各取头部，够 AI 判断成败/参数即可）
    _VERIFY_SNIPPET = 1600
    _VERIFY_MAX_ACTIONS = 25

    _VERIFY_PROMPT = """你是安全测试证据审核员。下面是若干测试动作及其挂账的数据包原文。

逐条判断：数据包内容能否支撑动作结论（result 文本）的宣称。
判定规则（从严格到宽松）：
- result 宣称"成功/code=1/返回数据"但包响应是失败(500/code=0/错误页) → mismatch
- result 宣称的接口/参数/订单号在包里找不到 → mismatch
- result 宣称泄露的敏感值（密码/调试页/他人数据）在包响应里没有出现 → mismatch
- 包确实是 result 描述的那次收发（成功对成功、失败对失败、参数吻合）→ ok
- 包只能证明动作的一部分（如多轮中只有基线轮），结论另有成功包 → partial

输出 JSON（不要 markdown 代码块）：{{"verdicts": [{{"i": 0, "verdict": "ok|partial|mismatch", "reason": "一句话"}}]}}。i 是动作序号。

待审核动作：
{actions}"""

    def _collect_semantics_items(self, feat_names=None) -> list:
        """从登记册收集带数据包的动作清单（语义检验输入素材，confirm 阻断与
        报告素材门共用）。feat_names 限定功能点集合（None=全部）"""
        items = []
        for it in self.feature_registry.list_items():
            fname = it.get("name", "")
            if feat_names is not None and fname not in feat_names:
                continue
            for _, lg in self.feature_registry.compact_log(it.get("test_log", [])):
                if str(lg.get("tool", "")) in self._NO_PACKET_TOOLS:
                    continue
                ev = lg.get("evidence")
                if not ev:
                    continue
                rounds = ev.get("rounds", []) if isinstance(ev, dict) and ev.get("multi") else [ev]
                body = []
                for r in rounds[:4]:
                    if not isinstance(r, dict):
                        continue
                    body.append(f"--- 包 ---\n{str(r.get('request', ''))[:self._VERIFY_SNIPPET]}"
                                f"\n[响应]\n{str(r.get('response', ''))[:self._VERIFY_SNIPPET]}")
                if not body:
                    continue
                items.append({
                    "feature": fname,
                    "intent": str(lg.get("intent", ""))[:150],
                    "result": str(lg.get("result", ""))[:250],
                    "verdict": str(lg.get("verdict", "")),
                    "packets": "\n".join(body)[:4000],
                })
        return items

    async def _semantic_mismatch_check(self, items: list) -> dict:
        """轻量版语义检验内核（confirm 阻断与报告素材门复用）：
        把动作描述与挂账包原文一起喂 AI 逐条判 mismatch/partial。
        AI 调用失败不阻塞（ok=True + warning）——门禁只在 AI 正常返回时执行，
        避免模型抖动把测试流程卡死"""
        if not items:
            return {"ok": True, "checked": 0, "mismatch": [], "partial": []}
        items = items[:self._VERIFY_MAX_ACTIONS]
        actions_text = "\n\n".join(
            f"[动作 {i}] 功能点: {x['feature']}\n意图: {x['intent']}\n结论: {x['result']}\n定性: {x['verdict']}\n数据包:\n{x['packets']}"
            for i, x in enumerate(items))
        prompt = self._VERIFY_PROMPT.format(actions=actions_text[:80000])
        provider = getattr(self, "_entry_provider", "") or ""
        model = getattr(self, "_entry_model", "") or ""
        try:
            resp = await self.ai.chat(
                [{"role": "user", "content": prompt}],
                tools=None, provider=provider, model=model, max_tokens=4000,
                override=getattr(self, "_entry_override", None))
            raw = (resp.get("content") or "").strip()
            m = re.search(r"\{[\s\S]*\}", raw)
            verdicts = json.loads(m.group(0)).get("verdicts", []) if m else []
        except Exception as e:
            return {"ok": True, "checked": len(items), "mismatch": [], "partial": [],
                    "warning": f"AI 语义检验执行失败（不阻塞）: {e}"}
        bad = []
        for v in verdicts:
            try:
                idx = int(v.get("i", -1))
            except (TypeError, ValueError):
                continue
            if not (0 <= idx < len(items)):
                continue
            vd = str(v.get("verdict", "")).lower()
            if vd in ("mismatch", "partial"):
                x = items[idx]
                bad.append({"feature": x["feature"], "intent": x["intent"][:80],
                            "verdict_ai": vd, "reason": str(v.get("reason", ""))[:150]})
        return {"checked": len(items),
                "mismatch": [b for b in bad if b["verdict_ai"] == "mismatch"],
                "partial": [b for b in bad if b["verdict_ai"] == "partial"],
                "ok": not bad}

    async def _tool_verify_evidence_semantics(self):
        """AI 真对比检验：把动作描述（intent+result）与挂账数据包原文**一起喂给 AI**，
        让 AI 逐条判断包内容能否支撑描述宣称——不是系统 URL 比对，是语义判定。
        mismatch/partial 的动作返回 must_fix 清单（照抄 intent 重走两段式重发包），
        AI 重测覆盖后复跑本工具，全绿才能写报告"""
        items = self._collect_semantics_items()
        if not items:
            return {"ok": True, "conclusion": "没有带数据包的动作，无需语义检验"}
        out = await self._semantic_mismatch_check(items)
        if out.get("mismatch") or out.get("partial"):
            n = len(out["mismatch"]) + len(out["partial"])
            out["ok"] = False
            out["must_fix"] = (f"AI 语义检验发现 {n} 个动作的数据包与描述不吻合（见 mismatch/partial 的 reason）。"
                               "修复方式：对每个不吻合动作重走两段式留痕——registry_log 段1 intent 与原动作**逐字相同**"
                               "（原位覆盖不堆节点）→ 重发该动作的包（这次确保结论宣称的成功包真的发出且在窗口内）"
                               "→ 段2 记结论并用 key_packets 指认证明漏洞的关键包 → 复跑本工具，全绿才能写报告")
        else:
            out["conclusion"] = f"AI 语义检验通过：{out['checked']} 个动作的描述与数据包语义吻合"
        return out

    @staticmethod
    def _round_desc(request: str, response: str = "") -> str:
        """从报文生成一句人类可读的发包描述（画报每轮展示用——
        只有「第 N 轮」用户看不懂这轮是干嘛的）。
        从请求行提取方法+路径，从 query/body 提取关键参数值；响应里带状态码。
        例：「POST /index.php?mod=xxx（access_token=dffc979d…）→ HTTP 200」"""
        try:
            req = str(request or "")
            lines = req.splitlines()
            first = lines[0].strip() if lines else ""
            m = re.match(r"([A-Z]+)\s+(\S+)", first)
            if not m:
                return ""
            method, target = m.group(1), m.group(2)
            path = target
            query = ""
            if "://" in target:
                mm = re.match(r"[a-z]+://[^/]+(/[^?#]*)(\?[^#\s]*)?", target)
                if mm:
                    path = mm.group(1) or "/"
                    query = (mm.group(2) or "")[1:]
            elif "?" in target:
                path, _, query = target.partition("?")
            # 关键参数值：token/id/code/order_id 类（值 ≥8 位才值得展示，
            # 短的页码类参数没有辨识度）
            kvs = []
            seen_k = set()
            for seg in query.split("&"):
                k, _, v = seg.partition("=")
                if k and v and len(v) >= 8 and k not in seen_k:
                    seen_k.add(k)
                    kvs.append(f"{k}={v[:16]}{'…' if len(v) > 16 else ''}")
            # body 里的关键参数（POST 的 JSON/form）
            body = ""
            for i, ln in enumerate(lines):
                if ln.strip() == "":
                    body = "\n".join(lines[i + 1:])
                    break
            if body:
                for k, v in re.findall(r"[\"']?(\w+)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{8,})[\"']?", body[:2000]):
                    if k not in seen_k and len(v) >= 8:
                        seen_k.add(k)
                        kvs.append(f"{k}={v[:16]}{'…' if len(v) > 16 else ''}")
            desc = f"{method} {path}"
            if kvs:
                desc += f"（{ '、'.join(kvs[:3]) }）"
            # 响应状态码：一眼看出这轮的结局
            r1 = str(response or "").splitlines()
            if r1 and re.match(r"HTTP/", r1[0].strip()):
                desc += f" → {r1[0].strip()[:30]}"
            return desc
        except Exception:
            return ""

    @staticmethod
    def _evidence_anchors(text: str, api_field: str = "") -> list:
        """从动作文本（intent+result）与登记接口提取证据锚点（仅参数值类），
        用于固化时按内容对账；接口身份对账由 _extract_apis 独立负责。

        意图说「money=0.01 篡改」、结果说「验证码 000000 可用」，
        对应包的请求里必然出现 0.01 / 000000；recon 扫描包一条锚点都不沾，自然被滤掉。

        提取规则（保守优先，宁缺勿滥——锚点错了会把真包滤掉）：
        - 「参数=值」「改为 X」语境的长 token（≥4 位：订单号/验证码/payload），
          纯数字 ≥6 位（id=307194 类 userId/手机号）；短的（1/2、true）太泛不做锚点；
          参数名/头名（access-token、token、sign…）本身绝不当锚点——
          头名撞报文头名会把错误包当「吻合」，实测实锤
        """
        text = f"{text} {api_field or ''}"
        anchors = set()
        # 参数名/头名黑名单：这些名字本身不当值锚点（access-token 是请求头名，
        # 步骤写「带 Access-Token 头」时报文头里必然有 access-token ——
        # 头名撞头名被误当参数值锚点，错误包顶替真篡改包进报告，实测实锤）
        _NAME_STOP = {"accesstoken", "access_token", "access-token", "token",
                      "session", "sessionid", "session_id", "cookie",
                      "authorization", "userid", "user_id", "orderid", "order_id",
                      "openid", "open_id", "sign", "signature", "nonce",
                      "timestamp", "captcha", "password", "passwd"}
        # 参数赋值/改值语境的值：「id=307194」「captcha 为 000000」「改为 SP2025…」
        for m in re.findall(r"(\w+)\s*[=＝:：]\s*[\"'“]?([A-Za-z0-9_\-./%+]{4,})[\"'”]?", text):
            if m[0].lower() not in _NAME_STOP:
                anchors.add(m[1].rstrip(".,;、"))
        for m in re.findall(r"(?:改为|改成|换成|替换为|为|使用|用)\s*[\"'“]?([A-Za-z0-9_\-./%+]{4,})[\"'”]?", text):
            anchors.add(m.rstrip(".,;、"))
        # 长数字串（≥6 位）：订单号/手机号/userId 类，天然唯一
        for m in re.findall(r"\b\d{6,}\b", text):
            anchors.add(m)
        # 裸长凭据值（≥12 位）：只认「上下文像值」的——前面跟 名字= / token 类词 /
        # 引号（「用被盗 token dffc979d」），纯参数名/头名（Access-Token、Session-Token）
        # 上下文不带值特征，不收
        for m in re.finditer(r"(?:[=＝:：]\s*|[\"'“]|(?:token|code|id|no|sn|key)[\s:：]*)([A-Za-z0-9_\-]{12,})", text, re.I):
            anchors.add(m.group(1))
        return [a for a in anchors if a and len(a) >= 4][:24]

    async def _tool_registry_update_state(self, name, state, note="", hint_resolutions=None):
        # confirmed 门禁：对该功能点带包动作先跑轻量语义检验，mismatch → 阻断确认
        # （此前纯靠 AI 自觉调用 verify_evidence_semantics，实测从未被调过；
        # 挂错包的漏洞在确认瞬间就该拦下，而不是等报告验收才发现）
        if str(state) == "confirmed":
            r = await self._semantic_mismatch_check(self._collect_semantics_items({str(name)[:120]}))
            if r.get("mismatch"):
                return {"error": f"「{name}」的漏洞动作语义检验未通过，暂不能确认：{r['mismatch'][0].get('reason', '')[:120]}。"
                                 "修复方式：registry_log 段1 用与原动作逐字相同的 intent 重新开窗 → 重发该动作的包 → "
                                 "段2 记结论并用 key_packets 指认，再 update_state confirmed"}
        out = self.feature_registry.update_state(name, state, note=note, hint_resolutions=hint_resolutions)
        # L2 分级上报：确认漏洞（confirmed）自动升级为 high 级事件，前端置顶高亮
        try:
            if isinstance(out, dict) and out.get("ok") and str(state) == "confirmed":
                self.state.push_event({"type": "finding", "level": "high", "data": {
                    "feature": name, "note": str(note or "")[:200], "sid": self._task_sid or ""}})
        except Exception:
            pass
        return out

    async def _tool_report_finding(self, title, severity, evidence_summary, feature=""):
        """L2 分级上报：发现疑似漏洞时即时上报（中高危才调，别把低价值噪音推给用户）。

        只做通知与日志沉淀，不改登记册状态（闭环仍以 registry_update_state 为准）。
        """
        sev = str(severity or "").lower()
        if sev not in ("critical", "high", "medium", "low"):
            return {"error": "severity 必须是 critical/high/medium/low（建议只上报中高危）"}
        self.state.push_event({"type": "finding", "level": "high" if sev in ("critical", "high") else "medium",
                               "data": {"feature": str(feature or title)[:80],
                                        "title": str(title)[:120],
                                        "severity": sev,
                                        "evidence": str(evidence_summary)[:500],
                                        "sid": self._task_sid or ""}})
        return {"ok": True, "title": str(title)[:120], "severity": sev,
                "note": "已实时上报用户并写入日志。登记册状态仍需 registry_update_state 置 confirmed 才算闭环；"
                        "报告 generate_report 的 findings 必须包含本条漏洞"}

    async def _tool_registry_list(self):
        items = self.feature_registry.list_items()
        cov = self.feature_registry.coverage()
        if not items:
            return {"count": 0,
                    "hint": "登记册为空。发现功能点后立即 registry_add 登记，测试过程 registry_log 留痕"}
        # 页面遍历覆盖度：让 AI 发现阶段自查哪些页面还没走到
        page_cov = {}
        try:
            pages_known = list(self.navigator.pages) if self.navigator else []
            page_cov = self.feature_registry.page_coverage(
                None, all_pages=pages_known) if pages_known else \
                self.feature_registry.page_coverage(None)
        except Exception:
            page_cov = {}
        out = {"count": len(items), "coverage": cov,
               "features": [{"name": it["name"], "api": it["api"], "state": it["state"],
                             "kind": it.get("kind", "feature"),
                             "attempts": len(it["test_log"])} for it in items]}
        if page_cov:
            out["page_coverage"] = {"visited": len(page_cov.get("visited", [])),
                                    "total": page_cov.get("total", 0),
                                    "missing": page_cov.get("missing", [])[:30]}
        return out

    @staticmethod
    def _parse_meta(meta):
        """留痕 meta 兼容解析：历史数据里 meta 被 str() 过，尽量还原成 dict"""
        if isinstance(meta, dict):
            return meta
        s = str(meta or "").strip()
        if not s:
            return {}
        for parser in (json.loads, ast.literal_eval):
            try:
                v = parser(s)
                if isinstance(v, dict):
                    return v
            except Exception:
                pass
        return {}

    def _collect_test_packets(self, sid: str, pick_kw: str = "") -> list:
        """从功能点登记册的测试留痕提取真实数据包（报告复现数据包以此为准，AI 手抄会失真）。
        返回 [{feature, api, packets:{rounds:[{tampered,response},...]}, ts}]。
        收集该功能点**全部轮次**的留痕包——复现步骤往往有多轮发包（先正常请求
        确认行为、再发篡改包验证），只取一轮会丢掉其余步骤的证据链。
        pick_kw 非空时按该关键字（漏洞 related_api）对登记 api 与轮报文双重过滤，
        供报告侧按漏洞文字从无 evidence 的动作留痕补捞真实流量（防串包）。
        纯 UI 触发的漏洞只有自然代理流量 → 代理请求+响应也为一轮（旧逻辑要求必须有
        主动请求，导致这类漏洞整条被跳过、报告一个包都没有）"""
        out = []
        try:
            for it in self.feature_registry.list_items(sid):
                # pick_kw 过滤：登记 api 与关键字同源、或轮报文 URL 与关键字同源，
                # 两者都不沾的功能点整条跳过（补捞口径下别的功能点的包绝不混入）
                if pick_kw:
                    api_txt = " ".join(re.split(r"[,，;；\s]+", str(it.get("api", "") or "")))
                    api_hit = bool(api_txt) and self._same_endpoint(api_txt, pick_kw)
                    if not api_hit:
                        kw_hit = False
                        for lg in it.get("test_log", []):
                            # 后备：动作文本里写了该接口（登记 api 常是乱码/错名，
                            # 一票否决会把真测试过的功能点整条跳过）
                            if any(self._same_endpoint(u, pick_kw)
                                   for u in self._extract_apis(
                                       f"{lg.get('intent', '')} {lg.get('result', '')}")):
                                kw_hit = True
                                break
                            ev0 = lg.get("evidence") or {}
                            rs = (ev0.get("rounds") if isinstance(ev0, dict) and ev0.get("multi")
                                  else [ev0]) if isinstance(ev0, dict) else []
                            for r0 in (rs or []):
                                u0 = self._req_url(str((r0 or {}).get("request", ""))) or \
                                    str(self._parse_meta((r0 or {}).get("meta")).get("url", ""))
                                if u0 and self._same_endpoint(u0, pick_kw):
                                    kw_hit = True
                                    break
                            if kw_hit:
                                break
                        if not kw_hit:
                            continue
                rounds = []
                for lg in it.get("test_log", []):
                    ev = lg.get("evidence") or {}
                    # 多包结构：一个测试动作的多轮发包（payload 提交+回读验证）逐轮展开
                    if ev.get("multi") and isinstance(ev.get("rounds"), list):
                        for r in ev["rounds"]:
                            req = str(r.get("request", ""))
                            if not req:
                                continue
                            rsp = str(r.get("response", ""))
                            r2 = {"tampered": req}
                            if rsp:
                                r2["response"] = rsp
                            # 轮描述透传（报告每包显示「这轮发包是干嘛的」）
                            rd = self._parse_meta(r.get("meta")).get("desc", "")
                            if rd:
                                r2["desc"] = rd
                            rounds.append(r2)
                        continue
                    req, resp = str(ev.get("request", "")), str(ev.get("response", ""))
                    if not req:
                        continue
                    # 代理兜底包与主动请求统一为一轮「请求包+响应包」证据
                    r2 = {"tampered": req}
                    if resp:
                        r2["response"] = resp
                    rd = self._parse_meta(ev.get("meta")).get("desc", "")
                    if rd:
                        r2["desc"] = rd
                    rounds.append(r2)
                if not rounds:
                    continue  # 完全没有真实流量的留痕不产出（纯文字说明不可复现）
                out.append({"feature": it.get("name", ""),
                            "api": it.get("api", ""),
                            "packets": {"rounds": rounds},
                            "ts": it.get("ts", 0)})
        except Exception:
            pass
        return out

    def _collect_traffic_packets(self, findings: list) -> list:
        """会话流量日志链路：按 finding.related_api（接口 URL 关键字）直接匹配真实流量，
        不依赖「漏洞标题 ↔ 功能点名称」的模糊对齐。
        返回 [{feature, api, packets:{rounds:[...]}, ts}]，related_api 的每个关键字
        各配其**全部轮次**（时间正序）：优先主动流量，无主动流量时取同接口代理捕获包"""
        out = []
        try:
            traffic = list(getattr(self, "_traffic_log", []) or [])
            try:
                caps = list(getattr(self.state.proxy_capture, "captures", []) or [])
            except Exception:
                caps = []
            if not traffic and not caps:
                return out
            seen = set()
            for f in findings:
                if not isinstance(f, dict):
                    continue
                keys = f.get("related_api") or []
                if isinstance(keys, str):
                    keys = [keys]
                for kw in keys:
                    kw = str(kw or "").strip()
                    if len(kw) < 3:  # 过短关键字会全网误配
                        continue
                    rounds = []
                    # 主动流量全部轮次（时间正序）= 请求包+响应包成对
                    for t in traffic:
                        if self._same_endpoint(str(t.get("meta", {}).get("url", "")), kw) \
                                and t.get("request") and t["request"] not in seen:
                            seen.add(t["request"])
                            r = {"tampered": str(t.get("request", ""))}
                            if t.get("response"):
                                r["response"] = str(t.get("response"))
                            rd = self._round_desc(r["tampered"], r.get("response", ""))
                            if rd:
                                r["desc"] = rd
                            rounds.append(r)
                    if rounds:
                        # 按「漏洞文字 ↔ 报文」内容挑轮：同接口多轮里只有部分是
                        # 漏洞动作的包（checkout 接口有 12 轮，金额篡改/0元购只占 3 轮），
                        # 全轮粗放会把「正常浏览轮」当成漏洞证据（f0 只捞到 1 轮
                        # 空包 500 轮的错包就是这么进报告的，实测实锤）。
                        # 规则：漏洞描述/复现文字里的参数值（k=v 值、篡改数字）在
                        # 报文里出现的排前；有交集的轮全收，无任何交集才退回全轮
                        ftext = " ".join(str(f.get(k, "")) for k in
                                         ("title", "description", "reproduction")).lower()
                        fvals = set()
                        for m in re.findall(r"(\w+)\s*[=＝]\s*[\"']?([A-Za-z0-9_\-./%]{2,})", ftext):
                            fvals.add(m[1].lower())
                        fvals |= set(re.findall(r"\d+(?:\.\d+)?", ftext))
                        fvals.discard("")
                        def _hit(r):
                            rl = str(r.get("tampered", "")).lower()
                            for v in fvals:
                                # 词边界匹配：裸子串会误撞（值 "1" 命中 HTTP/1.1、
                                # 值 "0" 命中 0.01 的前缀）——前后不能是字词/点
                                if re.search(rf"(?<![\w.]){re.escape(v)}(?![\w.])", rl):
                                    return True
                            return False
                        picked = [r for r in rounds if _hit(r)]
                        if picked and len(picked) < len(rounds):
                            rounds = picked
                    # 对照轮补充：主动轮头形态单一时，从代理捕获里补「头形态不同」的
                    # 同接口轮——加密类漏洞的对照组只在代理流量里（正常调用带
                    # x-e-k 加密头，测试动作重放时全删了头；缺了代理轮报告就没有
                    # 「带加密头 vs 删头」的对照包，复现步骤 1 只能空手，实测实锤）。
                    # 头形态判定：请求报文里的 cookie/access_token/x-e-k 三维度
                    def _hdr_form(txt, headers=None):
                        low = str(txt or "").lower()
                        hs = {str(k).lower(): v for k, v in (headers or {}).items()}
                        return ("cookie" if ("cookie:" in low or hs.get("cookie")) else "",
                                "token" if ("access_token=" in low
                                            or hs.get("access-token") or hs.get("access_token")) else "",
                                "x-e-k" if ("x-e-k:" in low or hs.get("x-e-k")) else "")
                    if rounds and len(rounds) < 24:
                        have_forms = {_hdr_form(r.get("tampered", "")) for r in rounds}
                        for c in reversed(caps):
                            if not self._same_endpoint(str(c.get("url", "")), kw):
                                continue
                            evc = self._packet_evidence(c)
                            if not evc.get("request"):
                                continue
                            form = _hdr_form(evc["request"], c.get("headers") or {})
                            if form in have_forms:
                                continue  # 头形态与已有轮相同，补了也是重复包
                            r = {"tampered": evc["request"]}
                            if evc.get("response"):
                                r["response"] = evc["response"]
                            rd = self._round_desc(evc["request"], evc.get("response", ""))
                            r["desc"] = rd if rd else "代理捕获（正常流量基线）"
                            rounds.append(r)
                            have_forms.add(form)
                            if len(rounds) >= 24:
                                break
                    # 无主动流量时：同接口的代理捕获包兜底（取最新一轮）
                    if not rounds:
                        for c in reversed(caps):
                            if self._same_endpoint(str(c.get("url", "")), kw):
                                ev = self._packet_evidence(c)
                                if ev.get("request"):
                                    r = {"tampered": ev["request"]}
                                    if ev.get("response"):
                                        r["response"] = ev["response"]
                                    rounds.append(r)
                                break
                    # 每个 related_api 关键字各产出一条（多接口漏洞每个接口都有自己的包，
                    # 此前 break 只配第一个关键字，第二个接口在报告里永远没包）
                    if rounds:
                        out.append({"feature": str(f.get("title", "")),
                                    "api": kw,
                                    "packets": {"rounds": rounds},
                                    "ts": int(time.time() * 1000)})
        except Exception:
            pass
        return out

    @staticmethod
    def _req_url(raw_req: str) -> str:
        """从标准报文请求行提取 URL（支持绝对形式与相对 path+Host 头两种）"""
        try:
            first = (raw_req or "").splitlines()[0].strip()
            parts = first.split()
            if len(parts) >= 2:
                target = parts[1]
                if target.startswith("http"):
                    return target
                # 相对形式：从 Host 头还原
                for line in raw_req.splitlines()[1:]:
                    if line.lower().startswith("host:"):
                        return "https://" + line.split(":", 1)[1].strip() + target
                return target
        except Exception:
            pass
        return ""

    @staticmethod
    def _urls_from_repro(f: dict) -> list:
        """从漏洞复现步骤文字中提取完整 URL（http/https 开头，截到空白或右括号）。
        报告前自动重发验证用：步骤里写了完整 URL 说明 AI 有明确可复现的请求路径"""
        urls, seen = [], set()
        txt = str(f.get("reproduction") or "") + "\n" + str(f.get("description") or "")
        for m in re.finditer(r"https?://[^\s'\"<>，。；）()、]+", txt):
            u = m.group(0).rstrip(".,;、）")
            if u not in seen:
                seen.add(u)
                urls.append(u)
        # related_api 里也可能有写全的 URL（补协议的场景少见，直接要 http 开头）
        return urls[:6]  # 上限防失控

    async def _reverify_missing_packets(self, findings: list):
        """报告生成前的「吻合性核验」：逐条漏洞逐步骤检查——
        每个复现步骤提到的接口在真实流量里有没有对应的留痕报文（接口+参数值都对上）。
        缺失的按步骤里的 URL 现场重发一次（自动带会话凭证与微信指纹），
        拿到「这一步描述的请求」自己的包再进报告——保证「步骤描述 ↔ 数据包」一一对应。
        只重发 GET / 无 body 请求（只读验证），不重放篡改 payload（避免重复攻击行为）"""
        try:
            traffic = getattr(self, "_traffic_log", []) or []
            # 静态类漏洞（反编译敏感信息/硬编码密钥）：证据是文件内容不是网络包，
            # 不做吻合性重发（重发=对无关接口发起真实请求，还会误挂包进报告）
            _static = ("反编译", "硬编码", "源码", "敏感信息", "密钥", "appsecret", "secret",
                       "accesskey", "private_key", "泄露")
            # 每个漏洞逐个检查复现步骤
            for f in findings:
                if not isinstance(f, dict):
                    continue
                _blob = str(f.get("title", "")) + str(f.get("description", ""))[:300]
                if any(h in _blob for h in _static) and not f.get("related_api"):
                    continue
                if not isinstance(f.get("related_api"), list):
                    f["related_api"] = [f["related_api"]] if f.get("related_api") else []
                repro = str(f.get("reproduction") or "")
                if not repro.strip():
                    continue
                # 逐步骤提取：文字里的 URL / related_api 短路径 + 参数值锚点
                step_urls = self._urls_from_repro(f)
                for raw in repro.splitlines():
                    text = raw.strip()
                    if len(text) < 4:
                        continue
                    # 本步的接口：完整 URL 优先，否则用 related_api 关键字做接口判定
                    step_ep = next((u for u in step_urls if u.lower() in text.lower()), "")
                    kws = f.get("related_api") or []
                    covered = False
                    for t in traffic:
                        req = str(t.get("request", ""))
                        turl = self._req_url(req) or str((t.get("meta") or {}).get("url", ""))
                        if not turl:
                            continue
                        # 接口吻合：步骤有完整 URL 用同源判定；没有则 related_api 任一关键字同源
                        ep_hit = (self._same_endpoint(turl, step_ep) if step_ep
                                  else any(self._same_endpoint(turl, kw) for kw in kws
                                           if len(str(kw)) >= 3))
                        if not ep_hit:
                            continue
                        # 参数值吻合：步骤文字里的长凭据值/数字应出现在报文里
                        # （「用被盗 token dffc979d」的步骤，报文里就该有 dffc979d；
                        #   无参数值的步骤只需接口吻合）。
                        # 参数名/头名本身不当锚点：「带 Access-Token 头」的步骤报文头里
                        # 必然有 access-token——头名撞头名把无关包误判为吻合（实测实锤）
                        vals = {v for v in re.findall(r"\b[A-Za-z0-9_\-]{12,}\b", text.lower())
                                if v not in ("accesstoken", "access_token", "access-token",
                                             "sessiontoken", "session_token")} | \
                            set(re.findall(r"\b\d{6,}\b", text))
                        # 「参数=值」对（值 ≥4 位）也参与核对：order_id=26510 这类
                        # 5 位订单号够不到 12/6 位阈值，但值错配（步骤要 26510、
                        # 流量里只有 26520 的包）同样该判不吻合 → 触发按步骤重发
                        vals |= {v.lower() for v in re.findall(
                            r"(\w+)\s*[=＝]\s*[\"']?([A-Za-z0-9_\-]{4,})", text)
                            if v.lower() not in ("access_token", "token", "session_token")}
                        if vals:
                            rl = req.lower()
                            if not any(v in rl for v in vals):
                                continue
                        covered = True
                        break
                    if covered:
                        continue
                    # 本步流量里没有吻合包 → 先按 URL+参数从 _traffic_log 精确捞回
                    # （同接口轮次里挑参数值最贴近步骤文字的；捞回的真包比现场重发
                    # 更可信——重发响应可能已变，且对写操作接口重发有副作用风险）
                    target = None
                    recovered = []
                    ep_pool = []
                    for t in traffic:
                        turl = self._req_url(str(t.get("request", ""))) or str((t.get("meta") or {}).get("url", ""))
                        if not turl:
                            continue
                        if step_ep and self._same_endpoint(turl, step_ep):
                            ep_pool.append(t)
                        elif any(self._same_endpoint(turl, kw) for kw in kws if len(str(kw)) >= 3):
                            ep_pool.append(t)
                    if ep_pool:
                        # 参数值交集优先，无交集退回接口同源轮（内容挑轮在报告收集阶段还有一道）
                        for t in reversed(ep_pool):
                            req_l = str(t.get("request", "")).lower()
                            vals = {v.lower() for v in re.findall(r"(\w+)\s*[=＝]\s*[\"']?([A-Za-z0-9_\-]{4,})", text)}
                            vals |= set(re.findall(r"\b\d{6,}\b", text))
                            vals |= {v for v in re.findall(r"\b[A-Za-z0-9_\-]{12,}\b", text.lower())
                                     if v not in ("accesstoken", "access_token", "access-token", "sessiontoken")}
                            if vals and any(v in req_l for v in vals):
                                recovered.insert(0, t)
                        if not recovered and ep_pool:
                            recovered = [ep_pool[-1]]
                    if recovered:
                        f.setdefault("_recovered", []).append(
                            {"api": step_ep or (kws[0] if kws else ""), "count": len(recovered),
                             "note": "自会话流量日志按 URL+参数捞回的真实留痕包"})
                        # 确保报告收集阶段能捞到：接口补进 related_api（_collect_traffic_packets
                        # 按 related_api 从 traffic_log 匹配，步骤参数值就是内容挑轮依据）
                        ep_keys = [self._req_url(str(t.get("request", ""))) or str((t.get("meta") or {}).get("url", ""))
                                   for t in recovered]
                        ep_keys = [u for u in ep_keys if u]
                        ra = f.setdefault("related_api", [])
                        for u in ep_keys:
                            if not any(self._same_endpoint(u, str(k)) for k in ra if len(str(k)) >= 3):
                                ra.append(u)
                        continue
                    # 流量日志也没有 → 现场重发。目标解析：
                    # 完整 URL 直接发；步骤只写了短路径（如「调用 GET user/index」）时，
                    # 用路径尾部匹配判定该步打的就是 related_api 里哪个接口，
                    # 再从流量里还原完整 URL 补协议——不能把整行文字喂 _same_endpoint（永假）
                    target = step_ep
                    if not target:
                        for kw in kws:
                            if self._step_ep_hit(text, str(kw)):
                                target = self._kw_ep(str(kw), traffic)
                                break
                        if not target:
                            for t in reversed(traffic):
                                u = self._req_url(str(t.get("request", ""))) or str((t.get("meta") or {}).get("url", ""))
                                if u and self._step_ep_hit(text, u):
                                    target = u
                                    break
                    if not target:
                        continue
                    # 步骤文字里写了参数值、而流量还原的 target 带旧值时，以步骤为准
                    # 改写 target 的同名参数再重发（步骤要 order_id=26510、流量包是
                    # 26520：直接发流量 URL 拿到的包与步骤描述对不上——「步骤↔包」又断了）
                    if target and "=" in text and "?" in target:
                        head, _, tq = target.partition("?")
                        pairs = [p for p in tq.split("&") if p]
                        changed = False
                        for i, p in enumerate(pairs):
                            k = p.partition("=")[0]
                            if not k or k in ("access_token", "token", "session_token"):
                                continue
                            m = re.search(rf"\b{re.escape(k)}\s*[=＝]\s*[\"']?([^\s&'\"<>，。；）(]{{4,}})", text)
                            if m:
                                v = m.group(1).rstrip(".,;、")
                                if v and v != p.partition("=")[2]:
                                    pairs[i] = f"{k}={v}"
                                    changed = True
                        if changed:
                            target = head + "?" + "&".join(pairs)
                    try:
                        r = await self._replay_request(target)
                        if r and r.get("request"):
                            # 留痕已写进 _traffic_log，报告包收集阶段自动取到
                            f.setdefault("_reverified", []).append(
                                {"api": target, "status": (r.get("response", "").splitlines() or [""])[0][:40]})
                            traffic = getattr(self, "_traffic_log", []) or []
                    except Exception:
                        continue
        except Exception:
            pass

    @staticmethod
    def _step_ep_hit(text: str, ep: str) -> bool:
        """步骤文字是否在说这个接口（供重发目标判定）：URL/路径尾部对齐。
        text 是整行复现步骤（可能没有完整 URL，如「调用 GET user/index 读取信息」），
        ep 是 related_api 关键字或流量里的 URL。判定：ep 去协议后的路径段（以 / 分隔
        取足够长可定位的尾部）出现在文字里即命中；分发器式 query 参数（mod=xxx）
        写进文字时也参与核对，防分发器接口张冠李戴"""
        text = str(text or "").lower().strip()
        ep = str(ep or "").lower().strip()
        if not text or not ep:
            return False
        if ep in text:
            return True
        path = ep.split("://", 1)[-1].split("?", 1)
        p = path[0].rstrip("/")
        q = path[1] if len(path) > 1 else ""
        if not p:
            return False
        # 路径尾部逐段放宽：a/b/c → b/c → c（至少 1 段，纯数字/单字符段不算身份）
        segs = [s for s in p.split("/") if s]
        for i in range(len(segs)):
            tail = "/".join(segs[i:])
            if len(tail) < 4 or tail.isdigit():
                continue
            if tail in text:
                break
        else:
            return False
        # 文字里写了分发参数时（mod=xxx / id=xxx），值必须与 ep 一致
        if q and "=" in text:
            for pair in q.split("&"):
                k, _, v = pair.partition("=")
                if not k or k in ("access_token", "token", "session_token"):
                    continue
                m = re.search(rf"{re.escape(k)}=([^&\s'\"<>，。；）(]+)", text)
                if m and m.group(1).rstrip(".,;、") != v:
                    return False
        return True

    def _kw_ep(self, kw, traffic=None):
        """related_api 关键字转完整 URL：已是 URL 原样；短路径从流量里找同源完整 URL
        （供「按步骤重发」补协议用——重发器要求完整 http(s) URL）"""
        kw = str(kw or "").strip()
        if kw.lower().startswith(("http://", "https://")):
            return kw
        for t in (traffic or getattr(self, "_traffic_log", []) or []):
            u = self._req_url(str(t.get("request", ""))) or str((t.get("meta") or {}).get("url", ""))
            if u and self._same_endpoint(u, kw):
                return u
        return kw

    @staticmethod
    def _same_endpoint(u1: str, u2: str) -> bool:
        """URL 同源判断（忽略 scheme/大小写）。
        普通接口：host+path 段级尾对齐 + query「共同参数值一致、参数名一侧 ⊆ 另一侧」。
        分发器式接口（path 尾段像文件名：index.php / plugin.php / handler.ashx）：
        path 恒定、真实接口在 query 路由参数里——风格无关通用提取：
        - s=/api/lc.order/detail、r=site/view（值含 / ）
        - s=lc.order.detail（点分多段）
        - m=user&c=center&a=order（ThinkPHP 三段式，按 query 顺序合并）
        - mod=dingyue / controller=user（已知路由键短值）
        提取后与对方 path/路由做段级尾对齐——否则登记短路径 api/lc.order/detail
        与真实包 index.php?s=... 永远对不上，画报/报告一个包都挂不上（实测实锤）。
        段级比较把 / . 都当分隔符：api/lc.order/detail 与 api/lc/order/detail 同序列。
        普通接口（path 尾段无点，如 api/user/index）不提取路由：op=info、m=month
        这类业务参数保持普通参数语义，防止误提走后对不上。
        剩余共同参数值必须一致（order_id=26510 ≠ 26520），防止 A 接口漏洞挂 B 接口的包；
        值对比只看两侧都出现的参数：单侧多出的一次性参数（code/userip/timestamp）不影响"""
        def _norm(u):
            u = str(u or "").lower().split("#", 1)[0]
            if "://" in u:
                u = u.split("://", 1)[1]
            return u.rstrip("/")
        def _segs(p):
            # 尾段是纯文件扩展名（.json/.php…）时剥掉再分段：网关路由后缀不是
            # 接口身份，带不带后缀应视为同一接口（getList ≡ getList.json）
            segs = str(p).split("/")
            if segs and "." in segs[-1] and segs[-1].rsplit(".", 1)[-1] in _FILE_EXTS:
                segs = segs[:-1] + [segs[-1].rsplit(".", 1)[0]]
            return [s for s in re.split(r"[/.]", "/".join(segs)) if s]
        def _pairs(qs):
            out = {}
            for p in qs.split("&"):
                if not p:
                    continue
                k, _, v = p.partition("=")
                out[k] = v
            return out
        _ROUTE_KEYS = {"s", "r", "m", "c", "a", "route", "mod", "controller",
                       "action", "module", "ctrl", "act", "op", "do"}
        # 文件扩展名尾段：网关路由形式（getList.json / index.php）不是接口身份。
        # 文本提取常把 getList.json 写成 getList（斜杠正则断在点上），一侧带扩展名
        # 一侧不带时尾对齐必失败 → 真实同源被误判错配（实测实锤）
        _FILE_EXTS = {"json", "php", "asp", "aspx", "ashx", "jsp", "do",
                      "action", "html", "htm", "cgi"}
        # ThinkPHP 模块/控制器/操作固定角色序：乱序 query（a=order&m=user&c=center）
        # 提取后仍按 m→c→a 重排，与斜杠路径 user/center/order 对齐
        _ROLE = {"m": 0, "c": 1, "a": 2}
        def _qroute(qs):
            """query 路由段提取（按角色序合并）→ (合并路由, 剩余query)。
            强特征：值含 /；值点分多段（lc.order.detail）。
            弱特征：已知路由键 + 纯字母值（m=user、mod=dingyue）。
            其余（id=26510、name=abc）不收，留给共同参数值核对"""
            segs, rest = [], []
            for p in qs.split("&"):
                if not p:
                    continue
                k, _, v = p.partition("=")
                lv = v.lower()
                route = False
                if v and re.search(r"[a-z]", lv):
                    if "/" in v:
                        route = True
                    elif re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+", lv):
                        route = True
                    elif k in _ROUTE_KEYS and re.fullmatch(r"[a-z_]{2,}", lv):
                        route = True
                if route:
                    role = _ROLE.get(k, 3)
                    for s in v.replace(".", "/").split("/"):
                        if s:
                            segs.append((role, len(segs), s))
                else:
                    rest.append(p)
            segs.sort(key=lambda x: (x[0], x[1]))
            return "/".join(s for _, _, s in segs), "&".join(rest)
        a, b = _norm(u1), _norm(u2)
        if not a or not b:
            return False
        ap, _, aq = a.partition("?")
        bp, _, bq = b.partition("?")
        # 分发器式判定：path 尾段像文件名（含点）——index.php / plugin.php / api.ashx
        da = "." in ap.rsplit("/", 1)[-1]
        db = "." in bp.rsplit("/", 1)[-1]
        if da or db:
            aqp, aq = _qroute(aq)
            bqp, bq = _qroute(bq)
            sa = _segs(aqp or ap)
            sb = _segs(bqp or bp)
            # 段级尾对齐：短序列是长序列的尾缀（登记短路径写不全时仍命中）
            n = min(len(sa), len(sb))
            if not n or sa[-n:] != sb[-n:]:
                return False
            if aq and bq:
                pa, pb = _pairs(aq), _pairs(bq)
                if any(pa[k] != pb[k] for k in pa if k in pb):
                    return False
            return True
        if not (ap == bp or ap.endswith(bp) or bp.endswith(ap)):
            return False
        if aq and bq:
            pa, pb = _pairs(aq), _pairs(bq)
            if any(pa[k] != pb[k] for k in pa if k in pb):
                return False
            return not (set(pa) - set(pb)) or not (set(pb) - set(pa))
        return True

    def _project_board_material(self, sid: str) -> dict:
        """画板 → 报告素材投影：每个 confirmed 功能点产出一条骨架。
        actions（intent/result/verdict + 每动作的接口提取）= 报告描述/复现的唯一来源；
        action_packets 数 = 该动作留痕的轮次数（包由系统按 feature 自动挂，AI 不用抄）。
        这是「描述↔数据包双向闭合」的素材层：AI 只准基于骨架写文本，两头都锚死画板"""
        out = []
        try:
            for it in self.feature_registry.list_items(sid):
                if it.get("state") != "confirmed":
                    continue
                acts = []
                for _, lg in self.feature_registry.compact_log(it.get("test_log", [])):
                    if str(lg.get("tool", "")) in self._NO_PACKET_TOOLS:
                        continue
                    intent = str(lg.get("intent", ""))[:120]
                    result = str(lg.get("result", ""))[:200]
                    if not intent and not result:
                        continue
                    # 该动作涉及的接口（描述核对白名单：报告里这些接口必须全部出现）
                    apis = self._extract_apis(f"{intent} {result}")
                    # 该动作留痕轮次数（快照窗口内实际发包数，报告包应覆盖这些动作）
                    ev = lg.get("evidence") or {}
                    n_rounds = (len(ev.get("rounds")) if isinstance(ev, dict)
                                and ev.get("multi") and isinstance(ev.get("rounds"), list)
                                else (1 if ev else 0))
                    acts.append({"intent": intent, "result": result,
                                 "verdict": str(lg.get("verdict", "")),
                                 "apis": apis, "packets": n_rounds,
                                 **({"note": "对照/排除步骤——系统只留文字不挂数据包，"
                                             "复现中仅文字引用本步骤，不占复现数据包"}
                                    if str(lg.get("verdict", "")) in ("safe", "fail") else {})})
                if not acts:
                    continue
                out.append({"feature": it.get("name", ""),
                            "api": it.get("api", ""),
                            "actions": acts[:10]})
        except Exception:
            pass
        return {"confirmed": out[:20]}

    # ── 静态敏感信息对账闸门（画板 sensitive 条目 ↔ 报告静态轨 finding）──
    # 地图 AK 漏报实测踩坑：报告骨架只由 confirmed 功能点驱动，静态发现全靠 AI 自觉
    # 补录，画板躺着「密钥：N 项」报告静态轨 0 条没有任何闸门拦——本闸堵这条缝

    @staticmethod
    def _sensitive_anchor_values(e: dict) -> list:
        """画板 sensitive 条目 → 可对账的样本值锚点（≥8 字符的具值文本）。
        detail 形态：scan_sensitive「val（file:line）、val2（…）…共 N 处」、
        get_storage「key：k\\n值：v」；detail 提不出来时从标题兜底
        （「发现AccessKey：AKIDxxx」取冒号后值段）"""
        vals = []

        def _push(x):
            # 先剥（文件:行号）位置尾巴再判长度——file:line 自带冒号不能先按冒号切
            x = re.sub(r"（[^）]*）\s*$", "", str(x).strip()).strip()
            if len(x) >= 8 and x not in vals:
                vals.append(x)

        txt = str(e.get("detail", "")).split("…共")[0]
        for chunk in re.split(r"[、\n]", txt):
            chunk = chunk.strip()
            if not chunk:
                continue
            m = re.match(r"^值：(.+)$", chunk)
            if m:
                _push(m.group(1))
                continue
            core = re.sub(r"（[^）]*）\s*$", "", chunk).strip()
            if re.search(r"[:：]", core):
                # 「发现AccessKey：AKIDxx」「key：user_token」形态取冒号后值段
                _push(re.split(r"[:：]", core, 1)[-1])
            else:
                # 纯值形态：密钥串/IP/手机号/JWT 直达
                _push(core)
        if not vals and re.search(r"[:：]", str(e.get("title", ""))):
            _push(re.split(r"[:：]", str(e.get("title", "")), 1)[-1])
        return vals

    def _static_sensitive_uncovered(self, sid, findings) -> list:
        """静态敏感信息对账：画板 type=sensitive 条目（scan_sensitive/get_storage 自动
        记录的密钥/JWT/手机号/AccessKey 等）逐条核对 findings——样本值没出现在任何
        finding 文本（标题/描述/复现/影响/evidence 文件原文）里 = 漏报。
        返回 [{title, detail, sample}]，空=全部覆盖或无可核对条目。
        提不出锚值的条目跳过（避免误报）"""
        try:
            entries = [e for e in self.board.entries(sid) if e.get("type") == "sensitive"]
            if not entries:
                return []
            parts = []
            for f in (findings if isinstance(findings, list) else []):
                if not isinstance(f, dict):
                    continue
                for k in ("title", "description", "reproduction", "impact"):
                    parts.append(str(f.get(k, "")))
                ev = f.get("evidence")
                if isinstance(ev, list):
                    for e0 in ev:
                        if isinstance(e0, dict):
                            parts.append(str(e0.get("path", "")))
                            parts.append(str(e0.get("content", "")))
            blob = "\n".join(parts)
            out = []
            for e in entries:
                vals = self._sensitive_anchor_values(e)
                if vals and not any(v in blob for v in vals):
                    out.append({"title": str(e.get("title", ""))[:80],
                                "detail": str(e.get("detail", ""))[:200],
                                "sample": vals[0][:60]})
            # 全量列出（不设 10 条上限）：截断清单会导致 AI 每轮补 10 条、
            # 每轮都要重传全量 findings（单轮 10 万+字符），5 轮试错远贵于
            # 一次给全（每条 ~340 字符，50 条也仅 1.7 万）；红线③净省
            return out
        except Exception:
            return []

    @staticmethod
    def _validate_findings(findings) -> tuple:
        """generate_report 入参校验：脏数据拒收（宁报错让 AI 重发，不落垃圾报告）。
        返回 (clean_findings, problems:list)"""
        problems = []
        if not isinstance(findings, list) or not findings:
            return [], ["findings 必须是非空数组"]
        # schema 白名单：塞非 schema 字段（_reverified/packet_source/repro_steps
        # 之类自造字段）曾污染报告数据结构，报告渲染直接崩——一律拒绝让 AI 重发
        allowed = {"title", "feature", "related_api", "severity", "description",
                   "reproduction", "packets", "impact", "recommendation", "evidence"}
        clean = []
        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                problems.append(f"findings[{i}] 不是对象")
                continue
            extra = [k for k in f.keys() if k not in allowed]
            if extra:
                problems.append(
                    f"findings[{i}] 含非 schema 字段: {', '.join(map(str, extra[:5]))}。"
                    "只允许 title/feature/related_api/severity/description/"
                    "reproduction/packets/impact/recommendation/evidence，删除后重新提交")
                continue
            title = str(f.get("title", "")).strip()
            if not title:
                problems.append(f"findings[{i}] 缺 title")
                continue
            # feature 三轨校验（漏洞只有三条合法出口，防止归类造假）：
            #   运行时轨A：feature=登记册功能点名 → 报告按此直取确认快照（画板同源）
            #   运行时轨B：不填 feature 但必须填 related_api ≥1 → 报告走流量日志补捞
            #   静态轨：feature="static" + 真文件 evidence（path 必须指向反编译产物/源码文件，
            #           URL/接口响应文本伪装文件证据 = 拒收，实测 AI 曾把 HTTP 404 响应
            #           填进 evidence 伪装静态证据）
            fv = str(f.get("feature", "")).strip()
            keys = f.get("related_api") or []
            if isinstance(keys, str):
                keys = [keys]
            keys = [str(k).strip() for k in keys if len(str(k).strip()) >= 3]
            if not fv:
                if not keys:
                    problems.append(
                        f"findings[{i}] 缺 feature 且缺 related_api。运行时漏洞二选一："
                        "通过已登记功能点复现 → 填 feature=功能点名（报告直取确认快照包）；"
                        "无法归入功能点（暴露面探测/独立接口）→ 填 related_api=[接口URL]"
                        "（报告从真实流量补捞）。反编译文件类漏洞 → feature 填 \"static\" 并附 evidence")
                    continue
            elif fv.lower() == "static":
                ev = f.get("evidence")
                if not (isinstance(ev, list) and ev):
                    problems.append(
                        f"findings[{i}] feature=static（静态文件类漏洞）必须带 evidence"
                        "（[{path, content, line}] 敏感内容所在文件路径+原文），"
                        "没有文件证据的漏洞不能归入静态轨")
                    continue
                # 静态证据真实性：path 必须是文件路径形态（反编译产物/源码），
                # 接口 URL/HTTP 响应文本伪装的「文件证据」整条拒收
                _bad_ev = []
                for e0 in ev[:6]:
                    p0 = str((e0 or {}).get("path", "")).strip()
                    if re.match(r"^(https?://|GET |POST |PUT |DELETE |HTTP/\d)", p0) or " " in p0:
                        _bad_ev.append(p0[:50])
                if _bad_ev:
                    problems.append(
                        f"findings[{i}].evidence.path 不是文件路径（{_bad_ev}）。"
                        "接口 URL/HTTP 响应不能当静态文件证据——这是运行时测试发现的漏洞，"
                        "改用运行时轨：feature 填功能点名，或 related_api 填接口")
                    continue
            else:
                try:
                    _names = {str(it.get("name", "")).strip()
                              for it in self.feature_registry.list_items()}
                except Exception:
                    _names = set()
                if _names and fv not in _names:
                    close = [n for n in _names if fv[:6] and fv[:6] in n or n and n[:4] in fv]
                    problems.append(
                        f"findings[{i}].feature \"{fv}\" 不在登记册功能点列表中"
                        f"{('，相近名称: ' + ' / '.join(close[:3])) if close else ''}。"
                        "从 registry_list 输出复制准确功能点名，或确实是反编译文件类"
                        "漏洞时填 \"static\"，或无法归入功能点时改填 related_api")
                    continue
            # 乱码检测：title/description 里可控字符占比过高（编码事故/二进制混入）
            for field in ("title", "description"):
                txt = str(f.get(field, ""))
                if not txt:
                    continue
                bad = sum(1 for ch in txt if ord(ch) == 0xFFFD or 0xE000 <= ord(ch) <= 0xF8FF)
                if txt and bad / max(len(txt), 1) > 0.05:
                    problems.append(f"findings[{i}].{field} 含乱码字符（{bad} 处），疑似编码事故，重新生成后再提交")
            # 占位报文检测：packets 里出现「测试说明/说明：」引导的非报文文本
            pk = f.get("packets")
            if isinstance(pk, dict):
                # rounds 结构（多轮）：[{tampered, response}, ...]；兼容旧平铺结构
                candidates = []
                if isinstance(pk.get("rounds"), list):
                    candidates = [r for r in pk["rounds"] if isinstance(r, dict)]
                else:
                    candidates = [pk]
                for r in candidates:
                    for k in ("tampered", "response"):
                        v = str(r.get(k, "")).strip()
                        if not v:
                            continue
                        # 真实报文必然以请求行/状态行开头（HTTP/xxx 或 METHOD /path）
                        first_line = v.splitlines()[0][:120] if v.splitlines() else ""
                        is_http = bool(re.match(r"^(HTTP/\d|GET |POST |PUT |DELETE |PATCH |HEAD |OPTIONS )", first_line))
                        looks_like_note = re.match(r"^(测试说明|说明[:：]|注[:：]|备注[:：])", first_line)
                        if looks_like_note or (len(v) > 80 and not is_http and "HTTP/1.1" not in v[:200]):
                            problems.append(
                                f"findings[{i}].packets.{k} 不是 HTTP 报文（开头: {first_line[:60]}）。"
                                f"系统会自动填充真实留痕包，packets 一律省略，禁止文字说明充当数据包")
            clean.append(f)
        return clean, problems

    async def _tool_generate_report(self, title, findings=None,
                                    findings_delta=None, reuse_last_findings=False):
        # ═══ r2 findings 暂存+增量（AI 复盘实测：6 次打回 × 每次 6 条 findings 全文
        # 重发是报告期最大 token 黑洞，还曾把 title/findings 直接撑爆参数截断）═══
        # 首次调用：findings 全量 → 存会话暂存区；
        # 被拒后重传：findings_delta（按 id 补丁）或 reuse_last_findings=true（无变化），
        # 系统合并暂存区得到完整 findings 后走完全相同的校验链（验收仍见全量，红线②不破）
        _sid_rep = self._task_sid if getattr(self, "_task_sid", None) else self.current_sid
        _store = getattr(self, "_findings_store_sid", None)
        if _store is None:
            _store = {}
            self._findings_store_sid = _store
        _last = _store.get(_sid_rep)
        if findings_delta is not None and not findings:
            if not _last:
                return {"ok": False,
                        "error": "本会话没有暂存的 findings 可应用增量（findings_delta 只能在一次全量"
                                 " findings 调用之后使用），请先用 findings 参数全量重发"}
            merged = [dict(f) for f in _last]  # 深拷贝，暂存区不被补丁污染
            _del_ids = set()
            for d in findings_delta if isinstance(findings_delta, list) else []:
                if not isinstance(d, dict):
                    continue
                try:
                    did = int(d.get("id", -1))
                except (TypeError, ValueError):
                    return {"ok": False,
                            "error": f"findings_delta 补丁项缺少有效 id（收到 {d.get('id')!r}），每项必须带 id(序号) 与 op"}
                op = str(d.get("op", "set"))
                if op == "del":
                    _del_ids.add(did)
                    continue
                if not (0 <= did < len(merged)):
                    # 超出暂存区序号 = 新增条目（id 填最大序号+1，允许紧邻空洞）
                    if did == len(merged):
                        merged.append({})
                    else:
                        return {"ok": False,
                                "error": f"findings_delta id={did} 越界（当前共 {len(merged)} 条，"
                                         f"新增请用 id={len(merged)}）"}
                patch = {k: v for k, v in d.items() if k not in ("id", "op") and v not in ("", None)}
                if not patch and op == "set" and did < len(merged):
                    return {"ok": False,
                            "error": f"findings_delta id={did} 是空补丁（没有任何要改的字段），"
                                     "要么写字段要么用 op=del"}
                merged[did].update(patch)
            if _del_ids:
                merged = [f for i, f in enumerate(merged) if i not in _del_ids]
            findings = merged
        elif reuse_last_findings and not findings:
            if not _last:
                return {"ok": False,
                        "error": "本会话没有暂存的 findings 可复用（reuse_last_findings 只能在一次全量"
                                 " findings 调用之后使用），请先用 findings 参数全量重发"}
            findings = [dict(f) for f in _last]
        if not findings:
            return {"ok": False, "error": "缺少 findings（首次调用必须传全量 findings 数组；"
                    "被打回后的重传可用 findings_delta 增量补丁或 reuse_last_findings=true 复用上次）"}
        # r2 补充：入参基础检查通过即暂存原始版本（实测：此前暂存写在 schema 校验
        # 之后，首次调用就被 schema 拒收时暂存区为空——「没有暂存的 findings 可应用
        # 增量」，AI 被迫全量重发 3 轮×约 5 万字符）。任何一层（schema/门/验收）打回
        # 后 AI 都可用 findings_delta 补丁；校验通过时 clean 与原始内容一致，红线②
        # 不破——delta 合并结果仍走完整校验链与验收，验收始终见全量
        _store[_sid_rep] = [dict(f) for f in findings if isinstance(f, dict)]
        # 入参校验：乱码/占位报文/空 findings 直接拒收返回问题清单（AI 修正后重发），
        # 防止脏数据落库产生垃圾报告记录（上一轮出现过 medium/low/info=1/1/1 的坏报告）
        findings, problems = self._validate_findings(findings)
        if problems:
            return {"ok": False, "error": "报告被拒收，findings 存在以下问题（修正后重新调用 generate_report，不要放弃）：",
                    "problems": problems[:10],
                    "hint": "packets 复现数据包一律省略（系统自动填充测试留痕的真实数据包）；乱码说明生成 findings 时编码出了问题，重新构造 JSON"}
        # ═══ 素材投影（报告以画板为唯一事实源）═══
        # 报告文本的唯一合法来源是画板 confirmed 功能点的测试动作（intent/result/verdict），
        # 数据包的唯一合法来源是对应动作的留痕快照。每个 confirmed 功能点投影成一条骨架
        # 塞进返回值，AI 描述/复现只能写骨架里有依据的内容——描述提到 N 个接口，骨架的
        # actions 里就有 N 个接口的动作记录，报告素材层杜绝「描述与包两头自由发挥」
        sid_pre = self._task_sid if getattr(self, "_task_sid", None) else self.current_sid
        material = self._project_board_material(sid_pre)
        # ═══ 三道门合并（r1）：素材门/静态敏感门/硬对账原是串行短路——每轮只
        # 报一道门的问题，7 轮打回=各门轮次求和（AI 复盘实测）。现改为一次全跑、
        # 问题合并一次返回：findings 明显问题 + 未覆盖敏感 + 计划/登记册缺口 +
        # hints 未申报，AI 一轮拿全清单，逐项修完再交
        gate_problems = []      # 合并问题列表（每项 {gate, error, ...}）
        # ── 门1：素材门（画板 confirmed 有内容时核对 findings 覆盖）──
        if material.get("confirmed"):
            cids = {b.get("id", "") + ":" + ",".join(
                sorted(a.get("name", "") for a in (b.get("actions") or []) if a.get("verdict") == "vuln"))
                for b in (material.get("branches") or [])}
            served = getattr(self, "_board_material_served_sid", {})
            if served.get(sid_pre) != cids:
                self._board_material_served_sid = {sid_pre: cids}
                uncov = self._static_sensitive_uncovered(sid_pre, findings)
                extra = [{"title": u["title"], "detail": u["detail"], "sample": u["sample"]}
                         for u in uncov]
                gp = {"gate": "素材门",
                      "error": "报告必须以画板确认的功能点为素材（描述/复现只能依据下面骨架里的真实测试动作写，"
                               "数据包由系统按 feature 自动填充，禁止凭记忆或会话流水账自由发挥）。"
                               "以下为每个确认漏洞的骨架，逐条对应产出 findings：",
                      "board_material": material,
                      "hint": "每个骨架一条 finding：feature 复制骨架名；description/impact 从 intent+result "
                          "提炼；reproduction 按骨架动作顺序逐步写（每步写清接口与参数值，只能用动作里"
                          "出现过的接口/参数）；静态类漏洞（反编译文件）不占骨架，feature 填 \"static\" 并附 evidence"}
                if extra:
                    gp["uncovered_sensitive"] = extra
                    gp["error"] += (f"\n另有 {len(extra)} 条画板敏感信息未进报告（见 uncovered_sensitive）："
                                     "scan_sensitive/本地存储发现的密钥、JWT、手机号、AccessKey 等必须"
                                     "逐条以 feature=\"static\" + evidence（path=反编译文件路径, "
                                     "content=敏感值所在原文, line=行号）补录进 findings，"
                                     "确属误报/无效的也要在 evidence.content 里写明排除理由")
                gate_problems.append(gp)
        # ── 门2：静态敏感独立闸门（纯静态会话 + 素材门已过但漏条目）──
        # 原「连续两次同一批条目拒收→放行」防死锁逻辑保留：合并模式下同批条目
        # 第二次出现即放行（AI 已见过清单仍补不进=有排除理由或能力上限）
        uncov2 = self._static_sensitive_uncovered(sid_pre, findings)
        if uncov2:
            sig = getattr(self, "_static_gate_sig_sid", {})
            this_sig = "|".join(sorted(u["title"] for u in uncov2))
            if sig.get(sid_pre) != this_sig:
                sig[sid_pre] = this_sig
                gate_problems.append({"gate": "静态敏感门",
                        "error": f"画板有 {len(uncov2)} 条敏感信息未进报告（见 uncovered_sensitive）："
                                 "scan_sensitive/本地存储发现的密钥、JWT、手机号、AccessKey 等，"
                                 "逐条以 feature=\"static\" + evidence（path=反编译文件路径, "
                                 "content=敏感值所在原文, line=行号）补录进 findings；"
                                 "确属误报/无效（测试密钥/占位值）也要以静态 finding 形式列出并在"
                                 " description 说明排除理由，不允许静默丢弃",
                        "uncovered_sensitive": [{"title": u["title"], "detail": u["detail"],
                                                 "sample": u["sample"]} for u in uncov2],
                        "hint": "evidence.content 直接引用反编译产物里的原文（含敏感值），"
                                "AI 无法确定该值是否有效时按 info 级别列出并注明「待验证」"})
        # ── 门3：L3 报告前硬对账（计划未完成 + 登记册非终态 + hints 未申报）──
        # r4 计划项自指排除：本次动作就是 generate_report——「生成报告」类计划项
        # 在报告调用时必然处于非终态（自己在对账自己），永远过不了 → 白名单排除
        gaps = []
        try:
            plan = self._plan_for(sid_pre or "")
            undone = [f"计划项{i+1}[{it.get('status')}]: {it.get('text')}"
                      for i, it in enumerate(plan.get("items", []))
                      if it.get("status") not in ("done", "blocked")
                      and not re.search(r"生成.{0,6}报告|输出.{0,6}报告|撰写.{0,6}报告|出报告",
                                        str(it.get("text", "")), re.I)]
            gaps += undone
        except Exception:
            pass
        try:
            cov = self.feature_registry.coverage(sid_pre)
            items = self.feature_registry.list_items(sid_pre)
            open_set = set(cov.get("open_names") or [])  # coverage 分列后只含 feature（r7）
            gaps += [f"登记册未闭环[{it['state']}]: {it['name']}（接口: {it['api'] or '无'}）"
                     for it in items if it.get("name") in open_set]
            # 门禁C（发现了就测）：终态功能点的 risk_hints 必须逐条处置申报
            # （【已测】/【豁免+理由】）——登记了联想却整条没处置 = 发现了没测，
            # 逐条列出打回；豁免是唯一合法出路但理由会随报告暴露给用户审
            from webapp.pentest.registry import parse_hint_marks
            for it in items:
                if it.get("state") not in ("tested", "confirmed", "clean", "skipped"):
                    continue  # 非终态的已由上面 open_set 打回，不重复报
                # r7 功能点分类：页面路由项（kind=page_route）不进闭环门禁——
                # 路由不是业务功能点，覆盖度按「已访问数」另列，不阻断报告
                if it.get("kind") == "page_route":
                    continue
                hints = [str(h).strip() for h in (it.get("risk_hints") or []) if str(h).strip()]
                if not hints:
                    continue
                parsed = parse_hint_marks(str(it.get("_last_note", "")) or "", hints)
                hs = it.get("hint_status") or []
                open_h = [e.get("hint", "") for e in hs if e.get("status") == "unhandled"]
                # 兜底：hint_status 缺失（老数据/异常路径）→ 按 note 现算
                if not hs:
                    open_h = [h for h in hints if parsed["marks"].get(h) in ("", None)]
                if open_h:
                    gaps.append(
                        f"漏洞联想未处置[{it['name']}]: {'; '.join(open_h[:5])}"
                        + ("…" if len(open_h) > 5 else "")
                        + "——registry_update_state 重发该功能点终态并带 hint_resolutions"
                          "=[{hint_index:序号, verdict:\"tested\"或\"waived\", reason:豁免理由}]"
                          "逐条申报（note 文本标记【已测】/【豁免】也可兜底）")
        except Exception:
            pass
        if gaps:
            gate_problems.append({"gate": "对账门",
                    "error": f"报告前对账发现 {len(gaps)} 项未闭环（见 unclosed_items），"
                             "逐项给出终态（registry_update_state 置 confirmed/clean/skipped 并附原因）"
                             "或 plan_update 处理后，重新调用 generate_report；确需立即出报告请在"
                             "下一轮消息里明确说明跳过对账的理由",
                    "unclosed_items": gaps[:40],
                    "hint": "终态= tested/confirmed/clean/skipped；「tested 未给结论」不算闭环"})
        # ── 合并返回：所有门的问题一次给全 ──
        if gate_problems:
            return {"ok": False,
                    "error": f"报告被拒收（{len(gate_problems)} 道门检出问题，已合并一次列出，"
                             "全部修正后再重新调用 generate_report，不要逐门试错）：",
                    "gates": gate_problems,
                    # 向后兼容旧字段：AI/提示词仍读 problems/error 统一入口
                    "problems": [g["error"][:200] for g in gate_problems],
                    "hint": "gates 数组每项是一道门的完整问题清单（含 board_material/"
                            "uncovered_sensitive/unclosed_items 明细），全部处理完再交报告"}
        # 覆盖度强制门：未闭环功能点直接写进报告，测试覆盖情况不可隐藏
        # 任务执行期间固定用任务会话（_task_sid），防止用户切开会话把数据写进别的会话
        sid = self._task_sid if getattr(self, "_task_sid", None) else self.current_sid
        reg = self.feature_registry.coverage_report_section(sid)
        # 页面遍历覆盖度：清单页面未访问的并入覆盖度缺口（发现覆盖，不只是测试覆盖）
        try:
            pages_known = list(self.navigator.pages) if self.navigator else []
            pcov = self.feature_registry.page_coverage(sid, all_pages=pages_known)
            if pcov.get("open"):
                reg["coverage"]["open"] += pcov["open"]
                reg["coverage"]["total"] += pcov["total"]
                reg["coverage"]["open_names"] = list(reg["coverage"].get("open_names", [])) + \
                    [f"[未访问页面] {p}" for p in pcov["missing"][:20]]
        except Exception:
            pass
        # 兜底（F-②）：finding 没填 related_api（运行时类漏洞：CORS/错误页泄露/
        # 暴露面等，实测 packets=None 反复被验收拒收的根因）→ 从复现文本提取
        # URL 补进 related_api，让后续流量日志补捞/验收比对有据可依
        try:
            for f in findings:
                ra = f.setdefault("related_api", [])
                if isinstance(ra, str):
                    f["related_api"] = ra = [ra] if ra else []
                if ra:
                    continue
                urls = []
                for m in re.finditer(r"https?://[^\s'\"<>()]+|(?<![a-z0-9])/[a-z][\w./?=&%-]{2,120}",
                                     f"{f.get('reproduction', '')} {f.get('description', '')}", re.I):
                    u = m.group(0).strip(".,;:！？。，；")
                    if u and u not in urls:
                        urls.append(u)
                f["related_api"] = urls[:4]
        except Exception:
            pass
        # 吻合性补验证：复现步骤提到但流量里没有留痕的接口，按步骤 URL 主动重发一次
        # （GET 只读验证，自动带凭证），保证报告里「漏洞描述的接口 ↔ 数据包」一一吻合
        await self._reverify_missing_packets(findings)
        # 自检门：动作↔数据包对齐审计（d6），错配进 warning，不阻断出报告但强制暴露
        try:
            audit = self._audit_evidence_alignment(sid)
        except Exception:
            audit = {"total": 0, "no_evidence": [], "misaligned": []}
        # 测试留痕的真实数据包：报告复现数据包以「确认漏洞瞬间固化的快照」为准。
        # confirmed 时 update_state 已把该功能点 verdict=vuln 动作的包整批固化进
        # confirmed_packets（AI 确认漏洞时实际发包的原文）——报告按功能点整批直引
        # 快照，不再按接口关键字全注册表/全流量日志匹配（匹配过宽把对照轮/
        # 基线轮/其他功能点的垃圾包混进报告，且描述与包错位，实测踩坑）
        real_pk = []
        try:
            for it in self.feature_registry.list_items(sid):
                snaps = list(it.get("confirmed_packets") or [])
                # 孤儿包预清理（只读 + 打标记，绝不改写登记册、不阻断填包链）：
                # 快照固化时刻早于 evidence 补挂/修正时，固化的轮可能是错包
                # （实测：订单取消快照里是 getOrderDetail 的包，本功能点正确
                # 包 userCancelOrder 在留痕里）。判定「孤儿」= 轮请求行 URL 与
                # 功能点 api 字段、全部 vuln 留痕轮（复验并入源）都对不上。
                # 孤儿轮剔除并降级标记 packet_source 附注，供验收层/人工复核
                it_api = str(it.get("api", "") or "")
                _api_eps = []
                for u in re.split(r"[,，;；、|｜\s]+", it_api):
                    u = u.strip().lower()
                    if u:
                        _api_eps.append(u if "://" in u else "http://x" + u if u.startswith("/") else u)
                def _vuln_reqs():
                    out = []
                    for lg in it.get("test_log") or []:
                        if str(lg.get("verdict", "")).strip().lower() != "vuln":
                            continue
                        ev = lg.get("evidence") or {}
                        vr = ev.get("rounds") if ev.get("multi") else [ev]
                        for r in (vr or []):
                            if isinstance(r, dict) and str(r.get("request", "")).strip():
                                out.append(str(r.get("request", "")))
                    return out
                _vreqs = _vuln_reqs() if _api_eps else []
                def _orphan(r):
                    u = self._req_url(str(r.get("request", "")))
                    if not u:
                        return False  # 提不出 URL 的轮不动（保守）
                    eu = u.lower()
                    if "://" not in eu:
                        eu = "http://x" + eu
                    for a in _api_eps:
                        try:
                            if self._same_endpoint(eu, a):
                                return False
                        except Exception:
                            pass
                    for q in _vreqs:
                        v = self._req_url(q)
                        if v and self._same_endpoint(eu, v.lower()):
                            return False
                    return True
                _orphans = [r for r in snaps if _orphan(r)] if _vreqs else []
                if _orphans:
                    snaps = [r for r in snaps if r not in _orphans]
                # 快照固化时刻可能早于后续复验/补测轮（画报 test_log 里 verdict=vuln
                # 的动作在 confirmed 之后追加）——把留痕里 vuln 动作的包并入快照池，
                # 否则报告只拿到确认瞬间的探测轮，画报里明明有的接管/复验轮进不了报告。
                # 按请求行+body 指纹去重：快照已含的轮不重复收
                if it.get("test_log"):
                    def _vfp(r):
                        req = str((r or {}).get("request", ""))
                        lines = req.splitlines()
                        return "|".join([lines[0].strip() if lines else "",
                                         req.split("\n\n", 1)[-1].strip()[:200]])
                    snap_fps = {_vfp(r) for r in snaps}
                    for lg in it["test_log"]:
                        if str(lg.get("verdict", "")).strip().lower() != "vuln":
                            continue
                        ev = lg.get("evidence") or {}
                        vr = ev.get("rounds") if ev.get("multi") else [ev]
                        for r in (vr or []):
                            if not (isinstance(r, dict) and str(r.get("request", "")).strip()):
                                continue
                            fp = _vfp(r)
                            if fp in snap_fps:
                                continue
                            snap_fps.add(fp)
                            snaps.append(r)
                if not snaps:
                    continue
                rounds = []
                for r in snaps:
                    req = str(r.get("request", ""))
                    if not req:
                        continue
                    r2 = {"tampered": req}
                    if r.get("response"):
                        r2["response"] = str(r["response"])
                    md = self._parse_meta(r.get("meta")).get("desc", "") if isinstance(r.get("meta"), (dict, str)) else ""
                    if md:
                        r2["desc"] = md
                    rounds.append(r2)
                if rounds:
                    real_pk.append({"feature": it.get("name", ""),
                                    "api": it.get("api", ""),
                                    "packets": {"rounds": rounds},
                                    "ts": it.get("ts", 0),
                                    **({"orphan_dropped": len(_orphans)} if _orphans else {})})
        except Exception:
            real_pk = []
        if not real_pk:
            # 兜底：历史数据（confirmed 早于本版快照机制）没有快照 → 旧链路收集
            real_pk = self._collect_test_packets(sid)
        # 流量日志链路降级为补缺：只给「快照/登记册集合没盖到」的漏洞补包
        # （按漏洞 related_api 找已覆盖的接口，跳过不重复捞；
        # 此前全量叠加会重复/混入非漏洞轮次，实测 f0 错包就是这么进报告的）
        try:
            _covered = set()
            for g in real_pk:
                for u in re.split(r"[,，;；\s]+", str(g.get("api", "") or "")):
                    if u:
                        _covered.add(u.lower())
                for r in g.get("packets", {}).get("rounds", []):
                    u = self._req_url(str(r.get("tampered", ""))) or ""
                    if u:
                        _covered.add(u.lower())
            _gap_findings = []
            for f in findings:
                keys = f.get("related_api") or []
                if isinstance(keys, str):
                    keys = [keys]
                if keys and all(
                        any(self._same_endpoint(u, str(k)) for u in _covered)
                        for k in keys if len(str(k)) >= 3):
                    continue  # 该漏洞的接口登记册集合已盖到，流量日志不再重复捞
                _gap_findings.append(f)
            real_pk = self._collect_traffic_packets(_gap_findings) + real_pk
        except Exception:
            real_pk = self._collect_traffic_packets(findings) + real_pk
        # 补捞链路：画板判 vuln 但动作留痕没有 evidence 的（AI 忘挂包），
        # 漏洞流量其实在 _traffic_log 里有全量留痕——按动作文本里的接口
        # 逐个补捞：先试登记册 evidence（同接口轮次），空了用流量日志
        # 伪 finding 复用「内容挑轮」（checkout 全部动作无 evidence 的场景
        # 只能靠这条，实测实锤）；覆盖判定用轮报文 URL（api 字段常是乱码）
        try:
            covered_eps = set()
            for g in real_pk:
                for u in re.split(r"[,，;；\s]+", str(g.get("api", "") or "")):
                    if u:
                        covered_eps.add(u.lower())
                for r in g.get("packets", {}).get("rounds", []):
                    u = self._req_url(str(r.get("tampered", ""))) or ""
                    if u:
                        covered_eps.add(u.lower())
            for fb in self.board.test_branch(sid):
                for a in (fb.get("actions") or []):
                    if a.get("verdict") != "vuln" or a.get("has_evidence"):
                        continue  # 已有 evidence 的动作不需要补
                    lg_ev = None
                    for it in self.feature_registry.list_items(sid):
                        if it.get("name") == fb.get("name"):
                            logs = it.get("test_log", [])
                            if 0 <= a.get("tidx", -1) < len(logs):
                                lg_ev = logs[a["tidx"]]
                            break
                    if lg_ev is None or lg_ev.get("evidence"):
                        continue
                    intent_txt = f"{lg_ev.get('intent', '')} {lg_ev.get('result', '')}"
                    for kw in self._extract_apis(intent_txt):
                        if any(self._same_endpoint(u, kw) for u in covered_eps):
                            break  # 该接口已有包，不重复捞
                        picked = self._collect_test_packets(sid, pick_kw=kw)
                        if not picked:
                            # 登记册没留痕包 → 流量日志伪 finding 补捞
                            # （description/reproduction 用动作原文，内容挑轮
                            #  按「篡改值 ↔ 报文」选出漏洞动作自己的轮次）
                            picked = self._collect_traffic_packets([{
                                "title": str(fb.get("name", ""))[:40],
                                "description": intent_txt,
                                "reproduction": str(lg_ev.get("intent", "")),
                                "related_api": [kw],
                            }])
                        if picked:
                            real_pk.extend(picked)
                            covered_eps.add(kw.lower())
                            break
        except Exception:
            pass
        report = self.state.report_builder.build(
            title=title,
            findings=findings,
            # 报告署名用会话身份快照：单例是进程属性，连测两个小程序时
            # 第二份报告会署上第一个小程序的残留身份（实测踩坑）
            app_info=self._session_identity(self._task_sid) or self.navigator.app_info,
            routes=self.navigator.pages,
            cloud_calls=self.state.cloud_calls,
            wxapi_calls=self.state.wxapi_calls,
            feature_coverage=reg,
            test_packets=real_pk,
        )
        # ═══ AI 验收层（报告落库前质量闸门，双轮：规则验收 → AI 语义验收）═══
        # fail 带具体问题清单重发（AI 当轮修正再调 generate_report），上限 2 轮；
        # 验收结果写 report["acceptance"] 元数据供排查，前端不显示
        acceptance = await self._acceptance_check(report, findings, real_pk)
        # 验收重试计数跨工具调用累计（每任务重置）：fail → 拒收带 issues 让 AI 修正重发；
        # 连续 2 轮 fail 后第 3 次强制落库（verdict=fail 留档），流程不死锁
        if acceptance.get("verdict") != "pass":
            self._accept_fails = getattr(self, "_accept_fails", 0) + 1
            if self._accept_fails <= 2:
                _tail = (f"还剩 {2 - self._accept_fails} 次重试机会" if self._accept_fails < 2
                         else "这是最后一次修正机会，再不通过报告将带 fail 标记落库")
                return {"ok": False,
                        "error": f"报告验收未通过（第 {self._accept_fails} 轮，{_tail}）。"
                                 "以下问题逐项修正后重新调用 generate_report：",
                        "issues": acceptance.get("issues", [])[:12],
                        "hint": "issues 里每个 finding 的 problem 都必须解决：描述与数据包不符的改描述或"
                                "补齐该功能的确认留痕；缺包的先去对应功能点补两段式留痕（挂 evidence）"
                                "再置 confirmed；编造的接口/参数删掉或用真实流量里的值"}
        report["acceptance"] = {"verdict": acceptance.get("verdict", "fail"),
                                "rounds": getattr(self, "_accept_fails", 0),
                                "issues": acceptance.get("issues", [])[:10],
                                "checked_at": time.time()}
        # 报告归属任务会话，存独立存储（删除会话后报告仍保留）
        # state.report_data 保留为镜像，供旧接口兼容
        self.set_report(sid, report)
        # 报告成功落库 → 静态敏感闸门签名清零（新一轮报告生成重新核对全部 sensitive 条目）
        sig = getattr(self, "_static_gate_sig_sid", {})
        if sig.pop(sid, None) is not None:
            pass
        # r2：报告落库成功 → findings 暂存区更新为本次成功版本（下轮增量补丁基于它）
        _store = getattr(self, "_findings_store_sid", None)
        if _store is None:
            _store = {}
            self._findings_store_sid = _store
        _store[sid] = [dict(f) for f in findings if isinstance(f, dict)]
        self.state.report_data = report
        self.state.push_event({"type": "report", "data": report})
        cov = reg["coverage"]
        result = {"ok": True, "summary": report["summary"],
                  "feature_coverage": {k: cov[k] for k in ("total", "closed", "open")},
                  "untested_features": cov["open_names"]}
        if audit.get("misaligned"):
            result["warning_evidence"] = (
                f"动作↔数据包对齐自检：{len(audit['misaligned'])} 个动作的证据包与动作描述对不上"
                f"（{json.dumps(audit['misaligned'][:5], ensure_ascii=False)}）。"
                "报告已生成，但建议修复后重新生成：对这些动作重走两段式留痕再跑 self_check_evidence")
        elif audit.get("no_evidence"):
            result["warning_evidence"] = (
                f"动作↔数据包对齐自检：{len(audit['no_evidence'])} 个已定性 vuln 的动作没有证据包，"
                "对应漏洞的复现步骤缺数据包，建议补包后重新生成报告"
                "（safe/fail 动作无需包，未计入）")
        if cov["open"] > 0:
            result["warning"] = (f"覆盖度缺口：{cov['open']}/{cov['total']} 个功能点未测试闭环"
                                 f"（{', '.join(cov['open_names'][:10])}）。"
                                 f"这些功能点已在报告中「测试覆盖度」章节显式列为未测试；"
                                 f"建议继续测试后再重新生成报告")
        return result

    async def _tool_add_board(self, type, title, detail="", source="AI 补充登记", data=None):
        return self.board.add(type, title, detail=detail, source=source)

    # ── AI 验收层：报告落库前质量闸门（规则验收 → AI 语义验收）──

    async def _acceptance_check(self, report, findings, test_packets) -> dict:
        """报告验收：先跑确定性规则（0 成本），全过再跑 AI 语义验收。
        返回 {verdict: pass|fail, issues: [{finding, problem, hint}]}"""
        issues = []
        fmap = {id(f): str(f.get("title", "")) for f in findings if isinstance(f, dict)}
        # ── 第 1 层：规则验收（确定性，不走 AI）──
        for f in report.get("findings", []) if isinstance(report.get("findings"), list) else []:
            if not isinstance(f, dict):
                continue
            t = str(f.get("title", ""))[:50]
            pk = f.get("packets") or {}
            groups = pk.get("groups") if isinstance(pk, dict) else None
            # 静态判定与 report._is_static_finding 同款：feature="static" 显式静态轨
            # （schema 层已强制文件 evidence）→ 不查包——此前漏了这半边，静态信息项
            # 被误报「复现数据包为空」，报错还指引 AI 去建 name="static" 假锚点收账
            # （实测踩坑：3 轮无效劳动）；运行时身份（related_api/具名 feature）优先
            # ——功能点确认的运行时漏洞附了 evidence 源码佐证也不算静态（否则包
            # 检查被跳过，无包报告一路放行，实测踩坑）；无名+evidence 兜底判静态
            fv = str(f.get("feature", "")).strip()
            is_static = (
                fv.lower() == "static"
                or (not (f.get("related_api") or [])
                    and not fv
                    and isinstance(f.get("evidence"), list) and bool(f["evidence"])))
            # 规则 1：运行时 finding 必须有包（静态 finding 用 evidence）
            if is_static:
                continue  # 静态轨在 validate 已强制 evidence，这里不重复
            if not groups:
                # feature 快照缺失且无 related_api 补捞 → 报告里这个漏洞没证据。
                # 报错必须带可执行的恢复路径（AI 复盘实锤：裸报错无指引 → 5 轮
                # 试错收敛烧 token）；三选一按实际场景取一即可
                issues.append({"finding": t, "problem": "复现数据包为空（没有真实流量证据）",
                               "hint": f"三选一修复：①检查 feature「{fv}」是否已 registry_log "
                                       "verdict=vuln 确认（确认时自动固化留痕快照），未确认就对"
                                       "该功能点重新收账（intent 与原动作逐字相同即可原位覆盖）；"
                                       "②该漏洞不属于已登记功能点（暴露面/独立接口）→ 改填 "
                                       "related_api=[接口URL]，报告会从流量日志补捞真实报文；"
                                       "③feature 名与登记册不一致 → registry_list 核对后用准确"
                                       "功能点名重发本条 finding，不要自己造名"})
                continue
            # 规则 1b（B1'）：步骤零命中打回——漏洞有包但复现步骤全没写任何
            # 组接口（尾两段对不上任何组标签路径）→ 步骤与包对应不起来，
            # 打回一次要求 AI 把调用的接口路径写明（F2 补写只在报告装配层，
            # 验收层核对的是 AI 原文；写明接口后装配层逐轮分配自然织包）
            repro_txt = str(f.get("reproduction", ""))
            repro_lines = [ln.strip() for ln in repro_txt.splitlines() if ln.strip()]
            api_paths = [str(g.get("api") or "").split("?")[0].lower()
                         for g in groups if isinstance(g, dict) and g.get("api")]
            api_paths = [p for p in api_paths if p]
            if repro_lines and api_paths:
                step_hit = False
                for ln in repro_lines:
                    ln_l = ln.lower()
                    for ap in api_paths:
                        segs = [s for s in ap.rstrip("/").split("/") if s]
                        tail2 = "/".join(segs[-2:]) if len(segs) >= 2 else ap
                        tail1 = segs[-1] if segs else ap
                        if (len(tail2) > 4 and tail2 in ln_l) or \
                                (len(tail1) >= 5 and re.search(rf"(?<![a-z0-9]){re.escape(tail1)}(?![a-z0-9])", ln_l)):
                            step_hit = True
                            break
                    if step_hit:
                        break
                if not step_hit:
                    issues.append({"finding": t,
                                   "problem": "复现步骤没有写明任何数据包对应的接口路径，步骤与证据对不上",
                                   "hint": f"每步开头写明调用的接口（如「调用 POST {api_paths[0]}」），"
                                           "复现文字其余内容保持不变，重新提交"})
            # 规则 2：提及接口逐一核对（双向闭合的验收侧）——复现/描述/related_api
            # 每个提到的接口都必须在包里有至少一轮真实命中（参数级 URL 比对，
            # 不再是接口前缀模糊匹配：实测 info/1' 前缀命中 info/24 全组导致漏报）
            api_keys = f.get("related_api") or []
            if isinstance(api_keys, str):
                api_keys = [api_keys]
            all_text = str(f.get("reproduction", "")) + str(f.get("description", ""))[:400]
            # 提取复现/描述里写出的具体 URL（GET https://x/y、GET /path 等）
            # 保序去重（同一 URL 在复现+描述重复出现会把同一条 issue 报两遍，实测踩坑）
            # 两个提取坑（AI 写报告实测反馈）：
            # ① \w 在 Python 匹配中文——「/info/5返回」被整段吞成 URL 导致对不上，
            #   字符类必须限 ASCII（后缀「返回」「的响应」剥离交给 strip+regex）
            # ② 字段列举「realname/idcardNo/telephone」含斜杠会被当接口路径，
            #   裸路径（无 ://）要求带定位特征：方法前缀（GET /x）或键值对（?id=1）
            #   或出现在括号/代码引号内——纯散文里的斜杠串不是接口引用
            # P1-5 冤案排除集（wxa33 实测：三类裸路径被当接口对账，烧掉 2/2 重试轮、
            # 逼 AI 把复现文本「去路径化」迁就验收器）——只作用于裸路径，完整 URL 不受影响
            _FS_HEADS = {"www", "wwwroot", "usr", "etc", "opt", "var", "home", "root",
                         "srv", "tmp", "mnt", "thinkphp", "library", "vendor",
                         "runtime", "bootstrap", "node_modules"}
            _FILE_EXTS = {"php", "html", "htm", "sql", "log", "env", "java", "class",
                          "jar", "py", "conf", "ini", "xml", "asp", "aspx", "jsp",
                          "bak", "zip", "rar", "gz", "tar"}
            _MIDDLEWARE = {"druid", "nacos", "swagger", "knife4j", "actuator",
                           "phpmyadmin", "adminer"}
            mentioned_urls = []
            for m in re.finditer(
                    r"(?:GET|POST|PUT|DELETE|PATCH)?\s*((?:https?://[^\s'\"<>()]+|/[a-z][a-z0-9_./?=&%-]{2,120}))",
                    all_text, re.I):
                u = m.group(1)
                # 剥中文标点与紧贴的中文后缀（/info/5返回 → /info/5）
                u = re.sub(r"[\u4e00-\u9fff].*$", "", u).strip(".,;:！？。，；：）(")
                if not u or "://" not in u and u.count("/") < 1:
                    continue
                # 头部行值排除（P2-2）：Origin:/Referer:/Host: 后面的 URL 是
                # HTTP 头原文（来源域/基址），不是动作声明的接口——
                # 「Origin: https://api.example.com」写进复现不该成为 must-hit
                pre_ctx = all_text[max(0, m.start() - 12):m.start()]
                if re.search(r"(?:Origin|Referer|Host)\s*[:：]\s*$", pre_ctx, re.I):
                    continue
                if "://" in u:
                    # 完整 URL 收紧：裸基址（host 后无路径段且无 query）不是接口
                    # 声明——「请求基址 https://api.example.com」这类描述性提及
                    # 不该参与对账（基址出现在描述里却永无对应轮次 → 假 issue）；
                    # 带路径或带 query（https://x.com?foo=1）都算真实声明
                    _rest = u.split("://", 1)[1]
                    _head_q = _rest.split("?", 1)
                    _tail = _head_q[0].split("/", 1)[1] if "/" in _head_q[0] else ""
                    _has_query = len(_head_q) > 1 and _head_q[1].strip()
                    if not (_tail.strip() or _has_query):
                        continue
                if "://" not in u:
                    # 裸路径定位特征：请求方法前缀已由正则可选组捕获过——这里补
                    # query 键值 或 多段路径（≥2 个 /，如 /api/rooms/12）两种特征。
                    # 单段路径（realname/idcardNo 其实是字段列举，/info/5 是接口）
                    # 无特征不参与对账（宁放过不误杀：报 issue 打回的代价远高漏检）
                    has_kv = "=" in u
                    multi_seg = u.count("/") >= 2
                    ctx = all_text[max(0, m.start() - 12):m.start()]
                    has_method = bool(re.search(r"(?:GET|POST|PUT|DELETE|PATCH|请求|调用|访问)\s*$", ctx, re.I))
                    if not (has_kv or multi_seg or has_method):
                        continue
                    # 冤案排除三类（集合定义见上方）：/www/wwwroot/...、
                    # /Druid/Nacos/Swagger、/thinkphp/.../App.php 都是暴露面/
                    # 源码路径描述不是业务接口声明。注意 index.php?s=/api/...
                    # 分发式路由：首段含点但扩展名截出「php?s=」不在黑名单，
                    # 且 query 路由是真实接口 → 照常参与对账
                    _segs0 = [s for s in u.lower().strip("/").split("/") if s]
                    if _segs0 and _segs0[0] in _FS_HEADS:
                        continue
                    _ext0 = _segs0[-1].rsplit(".", 1)[-1] if _segs0 and "." in _segs0[-1] else ""
                    if _ext0 and _ext0 in _FILE_EXTS:
                        continue
                    if any(s in _MIDDLEWARE for s in _segs0):
                        continue
                mentioned_urls.append(u)
            mentioned_urls = list(dict.fromkeys(mentioned_urls))

            def _safe_fail_left_trace(feat: str, kw: str) -> bool:
                """豁免规则：复现提到接口但包里没有 → 查该功能点 safe/fail 动作的
                留痕文字是否出现过该接口（真实对照步骤——warmup 401/无凭证对照
                的接口只以文字留痕不挂数据包，属合法引用）；没出现=编造，照样报。
                留痕是自由文本，完整 URL 逐字匹配命中率极低（AI 写「warmup 401 请先登录」
                而复现写完整路径 /api/rooms/12/warmup，实测打回两轮）——补两级候选：
                尾段匹配（warmup）与去参路径匹配（/api/rooms/12），任一命中即豁免"""
                kw_l = str(kw).strip().lower()
                if not kw_l:
                    return False
                kw_path = kw_l.split("://", 1)[-1].split("?", 1)[0].rstrip("/")
                tail = kw_path.rsplit("/", 1)[-1] if "/" in kw_path else kw_path
                tail = tail.rsplit(".", 1)[0] if "." in tail else tail
                cands = {kw_l}
                if len(kw_path) >= 4:
                    cands.add(kw_path)
                if len(tail) >= 5:
                    cands.add(tail)
                for it in self.feature_registry.list_items():
                    if it.get("name", "") != feat:
                        continue
                    for lg in it.get("test_log", []):
                        if self.feature_registry._norm_verdict(lg.get("verdict")) not in ("safe", "fail"):
                            continue
                        txt = f"{lg.get('intent', '')} {lg.get('result', '')}".lower()
                        if any(c in txt for c in cands):
                            return True
                    break
                return False

            for u in mentioned_urls[:8]:
                # 该提及 URL 至少一轮真实命中：轮请求行 URL 与提及 URL 段级同源
                # 且关键参数值一致（提及 id=26 → 轮里也得有 id=26 的轮，
                # 前缀同源但参数不同的轮不算数——「确认遍历到 26」需要 26 的轮）
                um = re.search(r"([\w-]+)=([\w\-@+]{2,40})", u)
                uk, uv = (um.group(1).lower(), um.group(2)) if um else ("", "")
                hit = False
                for g in groups if isinstance(groups, list) else []:
                    r = (g or {}).get("round") or {}
                    ru = self._req_url(str(r.get("tampered", "")))
                    if not ru or not self._same_endpoint(ru, u):
                        continue
                    if uk and uv:
                        rum = re.search(re.escape(uk) + r"=([\w\-@+]{2,40})", ru, re.I)
                        if rum and rum.group(1).lower() != uv.lower():
                            continue  # 同接口但参数值不同（id=24 vs 提及 id=26）
                    hit = True
                    break
                if not hit and _safe_fail_left_trace(str(f.get("feature", "")), u):
                    continue  # safe/fail 留痕出现过的接口 = 真实对照步骤，豁免
                if not hit:
                    # 实测复盘：只给接口级提示，AI 要人工逐字比对全包才能定位参数
                    # 差异（手机号尾号碰撞类）——报错附包内同接口轮的实际请求行，
                    # 「提及 id=26 / 包里 id=24」类差异一眼可见，省逐轮翻包
                    ep_urls = []
                    for g in groups if isinstance(groups, list) else []:
                        r = (g or {}).get("round") or {}
                        ru = self._req_url(str(r.get("tampered", "")))
                        if ru and self._same_endpoint(ru, u) and ru not in ep_urls:
                            ep_urls.append(ru)
                    if ep_urls:
                        ep_note = ("；包内同接口轮次的实际请求行："
                                   + "；".join(x[:120] for x in ep_urls[:3]))
                    else:
                        ep_note = "；包内没有任何该接口的轮次"
                    issues.append({"finding": t,
                                   "problem": f"复现提到 {u[:80]}，但数据包里没有该接口该参数的轮次{ep_note}",
                                   "hint": "补该步骤的真实包：重走该步骤留痕后重新置 confirmed，"
                                           "或修正复现文本为数据包里真实出现的接口/参数"})
            for kw in api_keys:
                if len(str(kw)) < 3:
                    continue
                hit = any(self._same_endpoint(str(g.get("api", "")) or str(kw), str(kw))
                          for g in groups if isinstance(g, dict))
                # 组内逐轮 URL 再核一次（api 字段可能空，轮报文请求行必带 URL）
                if not hit:
                    hit = any(self._same_endpoint(self._req_url(str(r.get("tampered", ""))) or "", str(kw))
                              for g in groups if isinstance(g, dict)
                              for r in [g.get("round") or {}] if isinstance(r, dict))
                if not hit and kw.lower() in all_text.lower():
                    if _safe_fail_left_trace(str(f.get("feature", "")), str(kw)):
                        continue  # safe/fail 留痕出现过的接口 = 真实对照步骤，豁免
                    issues.append({"finding": t,
                                   "problem": f"复现内容提到接口 {kw}，但数据包里没有该接口的任何轮次",
                                   "hint": "去对应功能点补留痕：重走该步骤挂 evidence 后重新置 confirmed，"
                                           "或修正 related_api 为数据包里真实出现的接口"})
            # 规则 3：串包检测——包组 api 与 related_api/feature 主接口同源校验
            # （组 api 与所有声明接口都不沾边 = 别的漏洞的包串进来了）
            if api_keys:
                for gi, g in enumerate(groups if isinstance(groups, list) else []):
                    if not isinstance(g, dict):
                        continue
                    gapi = str(g.get("api", ""))
                    if not gapi:
                        continue
                    if not any(self._same_endpoint(gapi, str(k)) for k in api_keys if len(str(k)) >= 3):
                        ru = self._req_url(str((g.get("round") or {}).get("tampered", ""))) or ""
                        if ru and not any(self._same_endpoint(ru, str(k)) for k in api_keys if len(str(k)) >= 3):
                            issues.append({"finding": t,
                                           "problem": f"第 {gi + 1} 组数据包（{gapi[:60]}）与该漏洞声明的"
                                                      f"接口 {', '.join(map(str, api_keys[:3]))} 不沾边，疑似串包",
                                           "hint": "检查 feature 是否写错（串的都是别的功能点的包）；"
                                                   "或删除 related_api 里不相干的接口声明"})
        # 规则验收 fail → 直接返回，不浪费 AI 调用
        if issues:
            return {"verdict": "fail", "issues": issues}
        # ── 第 2 层：AI 语义验收（LLM 审「描述声称的行为 ↔ 包内容」对齐）──
        try:
            ai_issues = await self._acceptance_semantic(report)
            if ai_issues:
                return {"verdict": "fail", "issues": ai_issues}
        except Exception as e:
            # 验收异常留痕（失败=假通过风险的遮掩点，必须可见）
            try:
                self._record_display("system", f"[验收] AI 语义验收异常跳过（规则层已过）：{type(e).__name__}: {e}")
            except Exception:
                pass
        return {"verdict": "pass", "issues": []}

    async def _acceptance_semantic(self, report) -> list:
        """AI 语义验收：审描述↔包内容一致性、步骤顺序↔包顺序、无编造接口。
        返回 issues 列表（空=通过）。复用 provider 单轮调用（JSON in/out）"""
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        if not findings:
            return []
        # 构造审查输入：每 finding 的文本 + 包组摘要（请求行+状态行，截断控 token）
        blocks = []
        for i, f in enumerate(findings[:12]):
            if not isinstance(f, dict):
                continue
            pk = f.get("packets") or {}
            groups = pk.get("groups") if isinstance(pk, dict) else None
            lines = [f"[{i}] {str(f.get('title', ''))[:60]}",
                     f"描述: {str(f.get('description', ''))[:300]}",
                     f"复现: {str(f.get('reproduction', ''))[:400]}"]
            if isinstance(f.get("evidence"), list) and f["evidence"]:
                for e in f["evidence"][:4]:
                    lines.append(f"文件证据: {e.get('path', '')}:{e.get('line', '?')} → {str(e.get('content', ''))[:80]}")
            elif isinstance(groups, list):
                for gi, g in enumerate(groups[:8]):
                    if not isinstance(g, dict):
                        continue
                    r = g.get("round") or {}
                    req1 = str(r.get("tampered", "")).splitlines()
                    resp1 = str(r.get("response", "")).splitlines()
                    # body 片段：关键词聚焦切片——响应全文扫描敏感关键词
                    # （password/token/id 等）命中处取 ±150 上下文，检验器
                    # 能看到 12KB 大响应中段的敏感字段（固定头尾 160 切片
                    # 永远看不到，同一 confirmed 连拒 4 次的根因）；无命中
                    # 退回头尾切片（保留否定证据「用户未登录」类）
                    req_body = str(r.get("tampered", "")).split("\n\n", 1)
                    rsp_body = str(r.get("response", "")).split("\n\n", 1)
                    req_tail = re.sub(r"\s+", " ", req_body[-1])[-120:] if len(req_body) > 1 else ""
                    rsp_full = re.sub(r"\s+", " ", rsp_body[-1]) if len(rsp_body) > 1 else ""
                    rsp_tail = self._sensitive_focus_slice(rsp_full)
                    lines.append(f"包{gi + 1}: 请求[{req1[0][:110] if req1 else '?'}]"
                                 + (f" 请求体尾: {req_tail}" if req_tail else "")
                                 + f" 响应[{resp1[0][:110] if resp1 else '?'}]"
                                 + (f" 响应体尾: {rsp_tail}" if rsp_tail else ""))
            else:
                lines.append("数据包: 无")
            blocks.append("\n".join(lines))
        prompt = (
            "你是渗透测试报告质量审查员。逐条核对每个漏洞的「描述/复现步骤声称的行为」"
            "与「数据包实际内容」是否一致。只报真问题，宁缺勿滥：\n"
            "1. 描述说\"返回了他人数据/篡改成功/绕过验证\"，但对应数据包响应看不出来"
            "（状态码不对、响应是错误页、没有描述声称的数据）→ 报\n"
            "2. 复现步骤与数据包轮次明显对不上（步骤说先 A 后 B，包顺序/内容完全不符）→ 报\n"
            "3. 描述里的接口/参数值在所有包和文件证据里都找不到（编造嫌疑）→ 报\n"
            "4. 文件证据内容与漏洞声称的敏感信息不符 → 报\n"
            "不要报：措辞风格、严重级别高低、建议是否完善、包被截断（…结尾是正常截断）。\n"
            "输出 JSON 数组，每项 {\"finding\": 序号数字, \"problem\": \"问题一句话\", "
            "\"hint\": \"怎么修一句话\"}；全部通过输出 []。\n\n" + "\n\n".join(blocks))
        # 单轮 LLM 调用：复用 self.ai.chat（与 verify_evidence_semantics 同款签名）
        try:
            resp = await self.ai.chat(
                [{"role": "user", "content": prompt}],
                tools=None,
                provider=getattr(self, "_entry_provider", "") or "",
                model=getattr(self, "_entry_model", "") or "",
                max_tokens=1500,
                override=getattr(self, "_entry_override", None))
            raw = (resp.get("content") or "").strip()
            m = re.search(r"\[[\s\S]*\]", raw)
            if not m:
                return []
            arr = json.loads(m.group(0))
            out = []
            for it in arr if isinstance(arr, list) else []:
                if not isinstance(it, dict):
                    continue
                try:
                    idx = int(it.get("finding", -1))
                except (TypeError, ValueError):
                    continue
                title = str(findings[idx].get("title", ""))[:50] if 0 <= idx < len(findings) else "?"
                out.append({"finding": title,
                            "problem": str(it.get("problem", ""))[:200],
                            "hint": str(it.get("hint", ""))[:200]})
            return out
        except Exception:
            return []

    _SENSITIVE_KW = re.compile(
        r"(password|passwd|salt|idcard|id_card|telephone|phone|mobile|email|"
        r"token|openid|open_id|session_key|balance|amount|price|realname|"
        r"real_name|address|bank|order_id|user_id|userid|role|is_admin|secret)", re.I)

    @staticmethod
    def _sensitive_focus_slice(text: str, budget: int = 2000, ctx: int = 150) -> str:
        """响应 body 关键词聚焦切片：敏感关键词命中处取 ±ctx 上下文窗口，
        窗口去重合并，总预算 budget 封顶；无命中退回头尾切片。
        用途：语义检验器报文摘要（大响应中段的敏感字段不再丢失）"""
        t = text or ""
        if len(t) <= ctx * 2:
            return t
        hits = [m for m in PenetrationAgent._SENSITIVE_KW.finditer(t)]
        if not hits:
            # 无敏感关键词：退回头尾（保留「用户未登录」类否定证据）
            return t[:160] + ("…" + t[-160:] if len(t) > 320 else "")
        windows, out, used = [], [], 0
        for m in hits:
            s, e = max(0, m.start() - ctx), min(len(t), m.end() + ctx)
            if windows and s <= windows[-1][1]:
                windows[-1] = (windows[-1][0], e)  # 相邻窗口合并
            else:
                windows.append((s, e))
        for s, e in windows:
            frag = t[s:e]
            if used + len(frag) > budget:
                frag = frag[:max(0, budget - used)]
            if frag:
                out.append(("…" if s > 0 else "") + frag)
                used += len(frag)
            if used >= budget:
                break
        return "".join(out)

    async def _tool_get_board(self):
        view = self.board.view()
        n_recon, n_test = len(view["recon"]), len(view["test"])
        return {"ok": True, "root": view["root"],
                "recon_count": n_recon, "feature_count": n_test,
                "recon": view["recon"][-40:], "test": view["test"][:40]}

    # ── 画板自动记录：信息搜集类工具结果 → 资产条目（简短、去重） ──

    # 信息来源渠道（画板「来源」只写渠道，不写工具名）
    SRC_DECOMPILE = "反编译的文件"   # 从解包目录/源码文件里读出来的
    SRC_CAPTURE = "响应数据包"       # 从 HTTP 抓包/接口响应里看到的
    SRC_RUNTIME = "小程序运行时"     # 运行时直接读取（配置/存储/API 返回）
    SRC_STATIC = "源码分析"          # 运行时 JS 源码静态提取

    def _auto_board_from_tool(self, name: str, result, sid: str):
        """信息搜集类工具执行成功后自动在画板画资产条目。
        格式：标题=「信息名：具体信息」（小程序名：xxx / 发现的key：值 / 发现API：N 个…），
        来源=渠道（反编译的文件/响应数据包/小程序运行时），并尽量附带溯源证据
        （数据包原文 / 文件:行号 / 运行时原始数据），前端点叶子可回看"""
        try:
            if not isinstance(result, dict) or result.get("error"):
                return
            B = self.board  # auto_recon(source, title, detail, type_, evidence, sid)
            if name == "get_app_info":
                info = result.get("app_info") or result
                nm, appid = info.get("name"), info.get("appid")
                if nm:
                    B.auto_recon(self.SRC_RUNTIME, f"小程序名：{nm}",
                                 detail=f"appid={appid or '?'}", sid=sid,
                                 evidence={"kind": "runtime", "note": "小程序运行时配置读取",
                                           "raw": json.dumps(info, ensure_ascii=False)[:4000]})
                elif appid:
                    B.auto_recon(self.SRC_RUNTIME, f"appid：{appid}", sid=sid,
                                 evidence={"kind": "runtime", "note": "小程序运行时配置读取"})
            elif name == "list_routes":
                pages = result.get("pages") or []
                if not pages:
                    return
                tb = result.get("tabBar") or result.get("tab_bar_pages") or []
                ev = {"kind": "runtime", "note": "小程序运行时页面配置",
                      "raw": json.dumps({"pages": pages[:80], "tabBar": tb[:20]}, ensure_ascii=False)[:8000]}
                B.auto_recon(self.SRC_RUNTIME, f"发现API：{len(pages)} 个页面路由",
                             detail="、".join(str(p) for p in pages[:4]) + ("…" if len(pages) > 4 else ""),
                             evidence=ev, sid=sid)
            elif name == "decompile_wxapkg":
                if result.get("ok") is False:
                    return
                n = result.get("file_count") or result.get("files") or ""
                title = "小程序源码" + (f"（{n} 文件）" if n != "" else "")
                B.auto_recon(self.SRC_DECOMPILE, title,
                             evidence={"kind": "file", "path": result.get("output_dir", "decompiled/"),
                                       "note": "解包输出目录"}, sid=sid)
            elif name == "static_scan":
                fns = result.get("cloud_functions") or []
                if not fns:
                    return
                names = [f.get("name", "") for f in fns[:3] if isinstance(f, dict)]
                B.auto_recon(self.SRC_STATIC, f"发现API：{len(fns)} 个云函数",
                             detail="、".join(n for n in names if n),
                             evidence={"kind": "runtime", "note": "运行时 JS 源码静态分析",
                                       "raw": json.dumps(fns[:5], ensure_ascii=False)[:4000]}, sid=sid)
            elif name == "scan_sensitive":
                # 画板只收高价值类别；API路径/不完整路径/URL/静态资源噪声太大，
                # 不入板（敏感信息页仍保留全量数据）
                labels = {"ip": "IP", "ip_port": "IP:端口", "sfz": "身份证",
                          "mobile": "手机号", "mail": "邮箱", "jwt": "JWT",
                          "algorithm": "加密函数", "secret": "密钥"}
                locs = result.get("locations") or {}

                def _loc_of(cat, val):
                    """查值在反编译文件里的位置 →「文件:行号」（查不到返回空串）"""
                    return (locs.get(cat) or {}).get(str(val), "")

                def _loc_evidence(cat, val, note):
                    """带文件:行号+行原文的证据（供前端点叶子溯源）"""
                    ev = {"kind": "file", "note": note}
                    loc = _loc_of(cat, val)
                    if loc:
                        path, _, ln = loc.rpartition(":")
                        ev["path"], ev["line"] = path or loc, ln
                        ev["snippet"] = self._file_line_snippet(path, ln)
                    return ev

                def _val_disp(cat, val):
                    """样例展示文本：值（文件:行号），让用户能直接定位"""
                    loc = _loc_of(cat, val)
                    return f"{val}（{loc}）" if loc else str(val)

                # 每类敏感信息一条：「手机号：N 项」detail=样例值+各自文件:行号
                for k, v in (result.get("results") or {}).items():
                    if k not in labels or not isinstance(v, list) or not v:
                        continue
                    if k == "secret":
                        # 密钥类先滤掉变量引用/占位符误报再计数
                        v = [x for x in v if self._is_valuable_secret(x)]
                        if not v:
                            continue
                    samples = [str(x) for x in v[:3]]
                    detail = "、".join(_val_disp(k, s) for s in samples)
                    if len(v) > 3:
                        detail += f" …共 {len(v)} 处"
                    # 证据挂在首个样例的位置上（有点可查）
                    B.auto_recon(self.SRC_DECOMPILE, f"{labels.get(k, k)}：{len(v)} 项",
                                 detail=detail,
                                 type_="sensitive" if k in ("secret", "jwt", "mobile", "mail", "sfz") else "recon",
                                 evidence=_loc_evidence(k, samples[0], f"共 {len(v)} 处"),
                                 sid=sid)
                for k, v in (result.get("custom_results") or {}).items():
                    if isinstance(v, list) and v:
                        samples = [str(x) for x in v[:3]]
                        detail = "、".join(_val_disp(k, s) for s in samples)
                        if len(v) > 3:
                            detail += f" …共 {len(v)} 处"
                        B.auto_recon(self.SRC_DECOMPILE, f"{k}：{len(v)} 项",
                                     detail=detail,
                                     type_="sensitive",
                                     evidence=_loc_evidence(k, samples[0], f"自定义规则 {k}，共 {len(v)} 处"),
                                     sid=sid)
            elif name == "get_storage":
                st = result.get("storage")
                if not isinstance(st, dict) or not st:
                    return
                ev = {"kind": "runtime", "note": "wx.getStorageSync 运行时读取",
                      "raw": json.dumps(st, ensure_ascii=False)[:8000]}
                # 只挑出对渗透有价值的 key（凭据/身份类），一个 key 一条叶子；
                # UI 配置/缓存的噪声 key 不入板
                valuable = {k: v for k, v in st.items() if self._is_valuable_key(k, v)}
                # 聚合概览一条（detail 不罗列 key，避免一叶多 key）
                B.auto_recon(self.SRC_RUNTIME,
                             f"本地存储：{len(st)} 个 key（有价值 {len(valuable)} 个）",
                             evidence=ev, sid=sid)
                # 每个 key 单独一条：「发现AccessKey：AKIDxxxx — 小程序运行时」
                # 标题=类型+值（用户一眼看到是什么 key、值是什么），detail=完整值
                for k, v in valuable.items():
                    vs = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
                    ktype = self._classify_key_type(k, vs)
                    B.auto_recon(self.SRC_RUNTIME, f"发现{ktype}：{vs[:60]}",
                                 detail=f"key：{k}\n值：{vs[:400]}",
                                 type_="sensitive", evidence=ev, sid=sid)
            else:
                return
        except Exception:
            pass

    # 本地存储 key 价值判断（严格白名单）：只收凭据/身份标识类。
    # 每条规则=(类型名, key 名特征, 值特征)；值特征为空=只看 key 名，
    # 非空=key 名和值都要匹配。user/uid/order 等宽泛词不在白名单里，
    # 走末尾「值像长凭据串」的兜底，避免业务缓存（salesman_sl_user_id、
    # _ADDRESS_MAP_KEY_）混入画板
    _KEY_TYPE_RULES = [
        # (类型名, key 名特征, 值特征)
        ("AccessKey",      r"access[_-]?key|^ak$|[^a-z]ak[^a-z]|^lta",  r"^(LTAI|AKID|AKLT|LTC)[A-Za-z0-9]"),
        ("SecretKey",      r"secret[_-]?key|app[_-]?secret|[^a-z]sk[^a-z]", r""),
        ("SessionKey",     r"session[_-]?key|sessionid|session_id",      r""),
        ("Token",          r"token|jwt|satoken",                          r""),
        ("Authorization",  r"authoriz|^auth$",                            r""),
        ("Cookie",         r"cookie",                                     r""),
        ("Ticket",         r"ticket",                                     r""),
        ("SignatureKey",   r"sign[_-]?key|sign_type",                     r""),
        ("Password",       r"password|passwd|pwd",                        r""),
        ("Credential",     r"credential|code_verifier",                   r""),
        ("APIKey",         r"api[_-]?key",                                r""),
        ("OpenID",         r"openid",                                     r"^o[A-Za-z0-9_-]{20,}$"),
        ("UnionID",        r"unionid",                                    r"^o[A-Za-z0-9_-]{20,}$"),
        ("SessionID",      r"phpsessid|jsessionid|^sess",                 r""),
        ("手机号",          r"mobile|phone",                               r"^1[3-9]\d{9}$"),
        ("身份证号",        r"sfz|idcard|id_card",                         r"^\d{17}[\dXx]$"),
        ("邮箱",            r"mail",                                       r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
        ("银行卡号",        r"bank[_-]?card",                              r"^\d{13,19}$"),
    ]
    _NOISE_KEY_PAT = re.compile(
        r"__SPM__|canwebp|prefetch|show_loading|loading|replacehost|log_sdk|"
        r"config|setting|flag|version|theme|language|font|cached|expried|"
        r"last_|first_|has_|is_|guide|tip|advice|banner|tabbar|nav_?bar|entry",
        re.I)

    # 值侧佐证：宽泛 key 名（user/uid/order/address 等）必须值像凭据/身份标识才收
    _VALUE_TOKENISH = re.compile(r"[A-Za-z0-9+/=_-]{16,}")

    @classmethod
    def _is_valuable_key(cls, key, value=None) -> bool:
        """有价值的 storage key：严格规则命中（key+值）或宽泛词+值佐证，且非噪声"""
        k = str(key)
        if cls._NOISE_KEY_PAT.search(k):
            return False
        v = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False) if value is not None else ""
        # 无效值直接丢：undefined/null/布尔/空/短值（UI 状态类）
        if not v or len(v.strip()) < 6 or v.strip().lower() in ("undefined", "null", "true", "false", "{}", "[]"):
            return False
        v = v.strip()
        for _, kpat, vpat in cls._KEY_TYPE_RULES:
            if re.search(kpat, k, re.I) and (not vpat or re.search(vpat, v)):
                return True
        # 宽泛词兜底：user/uid/member/account/order/address/card/login 等
        # 只有值本身像长凭据串（≥16 位字母数字）才收，业务缓存/纯数字 ID 不入板
        if re.search(r"user|uid|member|account|order|address|card|login|pay", k, re.I):
            return bool(cls._VALUE_TOKENISH.fullmatch(v) or cls._VALUE_TOKENISH.search(v) and not re.fullmatch(r"\d{1,10}", v))
        return False

    @classmethod
    def _classify_key_type(cls, key: str, value: str) -> str:
        """识别 key 的具体类型：AccessKey / SecretKey / Token / OpenID / 手机号…"""
        k = str(key)
        for tname, kpat, vpat in cls._KEY_TYPE_RULES:
            if re.search(kpat, k, re.I) and (not vpat or re.search(vpat, value or "")):
                return tname
        # key 名没认出来，值本身像 JWT 就归 Token
        if value and re.match(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", value):
            return "Token"
        # 宽泛词兜底命中的（值像长凭据串）按值形态归类
        if re.search(r"user|uid|member|account|order|address|card|login|pay", k, re.I):
            return "用户凭据"
        return "Key"

    # 密钥误报特征：变量引用、占位符、通用单词、模板串
    _SECRET_NOISE_PAT = re.compile(
        r"^\W*\$\{|^\W*\$\w|function|return\s|typeof|this\.|window\.|document\.|"
        r"\.props|\.state|\.length|undefined|null\b|true\b|false\b|"
        r"^password$|^username$|^account$|^token$|^secret$|^app_?id$|^test|"
        r"^e\.|res\.|data\.|item\.|row\.|params\.|config\.|options\.|headers\.|"
        r"[=:]\s*e\.",
        re.I)

    @classmethod
    def _is_valuable_secret(cls, text: str) -> bool:
        """过滤 secret 误报：跳过变量赋值/占位符/通用字段名等假密钥"""
        s = str(text).strip()
        if not s:
            return False
        if cls._SECRET_NOISE_PAT.search(s):
            return False
        # 有长随机串特征才算真密钥
        return bool(re.search(r"[A-Za-z0-9+/=_-]{16,}", s))

    @staticmethod
    def _file_line_snippet(path: str, line: str) -> str:
        """读取文件指定行原文（证据快照，读不到留空）"""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for i, ln in enumerate(f, 1):
                    if i == int(line):
                        return ln.strip()[:500]
        except Exception:
            pass
        return ""

    @staticmethod
    def _format_http_request(method: str, url: str, headers: dict, body=None) -> str:
        """统一请求包格式（与响应包对称的标准 HTTP 报文）：
        请求行用相对形式 POST /path?query HTTP/1.1 + Host 头，避免绝对 URL 把请求行撑到数百字符。
        所有请求包来源（主动测试工具/代理捕获）共用此格式，报告与画板展示一致"""
        try:
            from urllib.parse import urlsplit
            sp = urlsplit(str(url or ""))
            path = sp.path or "/"
            if sp.query:
                path += "?" + sp.query
            host = sp.netloc
            lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1"]
            if host:
                lines.append(f"Host: {host}")
            for k, v in (headers or {}).items():
                if k.lower() == "host":
                    continue  # Host 已放请求行后第一行，避免重复
                lines.append(f"{k}: {v}")
            if body is not None and str(body):
                lines.append("")
                lines.append(str(body))
            return "\n".join(lines)
        except Exception:
            return f"{method} {url} HTTP/1.1"

    @staticmethod
    def _packet_evidence(cap: dict) -> dict:
        """代理捕获记录 → 数据包证据（请求/响应原文，前端点叶子回看）"""
        req = PenetrationAgent._format_http_request(
            cap.get("method", "GET"), cap.get("url", ""), cap.get("headers") or {},
            str(cap.get("postData"))[:6000] if cap.get("postData") else None,
        )
        res = cap.get("result") or {}
        resp = ""
        if res:
            resp = f"HTTP/1.1 {res.get('status', '')}\n"
            for k, v in (res.get("headers") or {}).items():
                resp += f"{k}: {v}\n"
            resp += f"\n{str(res.get('body', ''))[:6000]}"
        return {"kind": "packet", "url": str(cap.get("url", ""))[:300],
                "method": str(cap.get("method", "GET")), "request": req, "response": resp}

    # ════════════════════════════════
    #  上下文长度管理
    #  （参考 Claude Code 工具结果清理 / Codex 交接摘要，纯客户端、协议无关）
    # ════════════════════════════════

    @staticmethod
    def _is_context_overflow(e: Exception) -> bool:
        """F1：识别「上下文超限」类 API 错误（OpenAI/Anthropic/各中转站措辞各异）"""
        s = str(e).lower()
        return any(k in s for k in (
            "context length", "context_length_exceeded", "maximum context",
            "prompt is too long", "too many tokens", "input length",
            "上下文长度", "超出上下文", "请求过长", "token 超限", "上下文超限"))

    def _estimate_tokens(self, messages: list, raw: bool = False) -> int:
        """近似 token 估算（C' 校准版）。

        基准：逐消息取 max(字符数/2.2, UTF-8 字节数/3)——中文 1 字约 0.6~1 token，
        旧公式「字符÷2.2」对中文严重低估（约打对折），是压缩迟迟不触发、巨型上下文
        反复重发（40M token 问题）的成因之一；字节÷3 对中文≈字数（偏高、偏安全），
        取两者大者偏向早压缩。usage 校准：主循环每轮拿到 API 真实 prompt_tokens
        后按 EMA 回写 _tok_ratio，估算自动贴合当前模型 tokenizer；
        raw=True 返回未乘系数的基准值（校准用）。
        """
        base = 0
        for m in messages:
            s = str(m.get("content") or "")
            base += max(len(s) / 2.2, len(s.encode("utf-8")) / 3)
            for tc in m.get("tool_calls") or []:
                s = json.dumps(tc, ensure_ascii=False)
                base += max(len(s) / 2.2, len(s.encode("utf-8")) / 3)
        if raw:
            return int(base)
        return int(base * getattr(self, "_tok_ratio", 1.0))

    def _build_send_view(self, history: list) -> list:
        """发送视图：只保留最近 N 条 tool 消息全文，更早的替换为占位符。

        不修改 history 本身（全量存档不动），仅裁剪发给模型的内容。
        assistant/tool 配对完整性由占位替换保证（只改 content，不删消息）。
        老 assistant 长回复同样压缩—— GLM 类思考模型单条回复可达数千字，
        「继续」接续后老推理文本在上下文里只烧 token 不产生新信息。
        """
        view = [dict(m) for m in history]
        # 任务计划 + 会话笔记每轮注入视野（紧跟 system 之后），防分析结论与
        # 任务进度被上下文压缩蒸发——这是长任务跨压缩/跨重启的方向锚点
        sid = getattr(self, "_task_sid", None) or self.current_sid
        inject = "\n\n".join(b for b in (self._plan_block(sid) if sid else "",
                                         self._skill_block(),
                                         self._notes_block()) if b)
        if inject and view and view[0].get("role") == "system":
            view[0] = {**view[0], "content": view[0]["content"] + "\n\n" + inject}
        elif inject:
            view.insert(0, {"role": "system", "content": inject})
        tool_idx = [i for i, m in enumerate(view) if m.get("role") == "tool"]
        if len(tool_idx) > self.SEND_KEEP_RECENT_TOOLS:
            for i in tool_idx[:-self.SEND_KEEP_RECENT_TOOLS]:
                m = view[i]
                raw = m.get("content", "")
                if len(raw) <= 400:
                    continue  # 短结果保留（多为 ok/错误提示，有状态价值）
                name = m.get("name", "tool")
                # 占位符保留结构化关键行（URL/status/凭证状态/元素清单头行等）：
                # 此前只有 200 字符头预览，AI 判断不了旧结果内容，被迫重发工具确认
                keys = []
                for line in raw.splitlines():
                    ls = line.strip()
                    if not ls or ls in keys:
                        continue
                    if re.search(r'"?(url|status|method|navigated_to|verified|stack_top|'
                                 r'credentials_sent|authenticated_request|artifact_id|'
                                 r'count|ok|error|page|frames)"?\s*[:=]', ls) \
                            or re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+\S{4,}"
                                         r"|(?:https?://|/api/)\S{6,}", ls):
                        keys.append(ls)
                    if len(keys) >= 8:
                        break
                head = raw[:200]
                keep = ("\n".join(keys[:8])) if keys else head
                # E1：占位符「截断窗 + 真实总数」并排——AI 看到省略规模与总数，
                # 不再误把窗口当全量、也不会因「数据不全」重复拉取
                omitted = max(0, len(tool_idx) - self.SEND_KEEP_RECENT_TOOLS)
                view[i] = {**m, "content": f"[上下文管理：已省略较早的 {name} 结果（原 {len(raw)} 字符）。当前共 {omitted} 条较早结果被省略，登记册/画板/笔记里的是完整清单，以此为准]\n关键行:\n{keep}\n开头片段: {head}\n如需完整内容请重新调用该工具（若结果带 artifact_id 存档提示可直接 read_artifact 读回，无需重跑）。"}
        # 老 assistant 长回复压缩：只保留最近 2 条 assistant 全文，更早的超 600 字
        # 换开头摘要（tool_calls 字段原样保留，不破坏配对）
        asst_idx = [i for i, m in enumerate(view) if m.get("role") == "assistant"]
        if len(asst_idx) > 2:
            for i in asst_idx[:-2]:
                m = view[i]
                raw = m.get("content", "") or ""
                if len(raw) <= 600:
                    continue
                head = raw[:300]
                view[i] = {**m, "content":
                           f"[上下文管理：较早的助手回复已压缩（原 {len(raw)} 字符），工具调用记录保留]\n开头片段: {head}"}
        return view

    @staticmethod
    def _is_paired_boundary(body: list, i: int) -> bool:
        """F3：切分点校验——body[i] 是否可以作为「被压缩段」的开头。

        硬性约束：开头不能是孤立 tool 消息（其配对 assistant 被压进摘要后，
        保留段开头出现无主 tool 会直接被 API 拒收）；其次不带 tool_calls 的
        assistant 回复（纯文本）留在旧段才有价值，压掉纯文本回复收益小、
        还可能截断「继续接续」语境。
        """
        if i <= 0 or i >= len(body):
            return False
        if body[i].get("role") == "tool":
            return False
        if body[i].get("role") == "assistant" and not body[i].get("tool_calls"):
            return False
        return True

    def _trim_tool_result(self, result_str: str, tool_name: str = "", sid: str = "") -> str:
        """写时处理：单条工具结果入库前「落盘卸载」而非硬截断。

        超限结果全文写 webapp/artifacts/<sid>/ 留档（复盘问题 8：关键响应被截断后
        只能靠 registry_log 回填），历史里只留 head+tail 预览 + artifact_id 句柄，
        模型按需 read_artifact(offset/max_lines) 读回原文——参考 agentscope
        Offloader / eino Backend.Write 的「卸载而非丢弃」模式。
        数据型工具（DATA_TOOLS）放宽到 DATA_TOOL_MAX_CHARS，避免捕获数据被截断丢失"""
        limit = self.DATA_TOOL_MAX_CHARS if tool_name in self.DATA_TOOLS \
            else self.TOOL_RESULT_MAX_CHARS
        if len(result_str) <= limit:
            return result_str
        artifact_id = ""
        try:
            self._artifact_seq += 1
            aid = f"{int(time.time())}_{self._artifact_seq}_{tool_name or 'tool'}"
            adir = os.path.join(self._artifacts_dir, sid or "adhoc")
            os.makedirs(adir, exist_ok=True)
            with open(os.path.join(adir, f"{aid}.txt"), "w", encoding="utf-8") as f:
                f.write(result_str)
            artifact_id = f"{sid or 'adhoc'}/{aid}.txt"
        except Exception:
            artifact_id = ""  # 落盘失败退化为纯截断，不阻塞任务
        # E3：头 60% + 尾 40% 切片（参考 Strix output_store 的 head/tail 保留策略）——
        # 工具结果的开头是发现/清单主体（AI 决策依赖），结尾是验证结论/状态汇总，
        # 中间明细是可回读部分；比旧版「头 70%+尾 30%」对结尾信息更友好
        head = int(limit * 0.6)
        tail = limit - head
        ref = (f"\n\n[完整原文已存档 artifact_id={artifact_id}，"
               f"调用 read_artifact 可分页读回]" if artifact_id else "")
        return (result_str[:head]
                + f"\n...[结果过长（原 {len(result_str)} 字符），中间部分已存档]...\n"
                + result_str[-tail:]
                + ref)

    _SUMMARY_PROMPT = """你是一个 AI 渗透测试 Agent 的上下文压缩器。此前的测试工作历史即将超出上下文窗口，请把以下历史压缩为一份「交接摘要」，供下一个接手的 Agent 继续工作。

要求（用中文，总长不超过 1200 字）：
1. 测试目标：appid / 小程序名 / 用户指令
2. 已完成的工作及关键结论
3. 关键数据（逐字保留，一字不差，丢失即无法继续测试）：接口地址（含完整 URL）、
   参数名与字段名、签名/加密算法名与参数、token/密钥/凭证的值、云函数名、数据库集合名、
   越权/注入点详情、已确认漏洞的编号与结论
4. 死路清单：已尝试并确认无效的路径（接口 404/参数无回显/断连原因等），一句话一条——
   接手者看到死路清单可避免原样重试浪费预算
5. 未完成的工作 / 下一步计划（含进行到哪一步、卡在何处）

严禁事项：
- 禁止概括性略写关键数据（如「发现若干接口」「token 已获取」），必须逐字列出具体值
- 禁止编造历史中不存在的内容；不确定的标注「待核实」

历史内容：
{history}"""

    def _redline_block(self) -> str:
        """C3 红线重申块：压缩交接时随摘要注入（摘要压缩会稀释纪律，红线必须随行）"""
        return ("## 测试纪律红线（压缩后重申，接手者必须遵守）\n"
                "- 未授权测试一律 http_request(no_credentials=true)，结论先看 authenticated_request\n"
                "- 发现的每个功能点立即测试到闭环（测试/确认/无漏洞/跳过），不允许只登记不测\n"
                "- 每个动作 registry_log 两段式留痕（意图+结果），证据包不挂 evidence 的漏洞不算实锤\n"
                "- 进度以任务计划与登记册为准，禁止凭记忆报进度；已加载 Skill 用完 release_skill 卸载")

    async def _maybe_compact(self, history: list, provider: str, model: str) -> list:
        """任务中途上下文超限时自动摘要压缩（Codex 交接式）。

        返回新 history；不压缩时原样返回。summary 保留在 session 上用于展示。
        """
        # 上下文窗口：模型列表可配置 context_window，默认保守 64k
        # ① 预留式预算（Swarm context-budget 思路）：先从窗口扣除本轮回复的
        # max_tokens 输出预算与工具回执中间态安全余量，得到 usable，再按比例算
        # 压缩/预警阈值——旧逻辑阈值按全窗口算、仅触发前 +4000 预留，回复预算
        # 8192 时预留被低估近一半，压缩偏晚
        window = self._model_window(provider, model)
        reply_reserve = int(getattr(self, "_reply_max_tokens", 8192) or 8192) + 2000
        usable = max(8192, window - reply_reserve)
        threshold = int(usable * self.CTX_THRESHOLD)
        est = self._estimate_tokens(history)
        # C2 预压缩预警：0.6 阈值（硬压缩 0.7 之前）注入「立即留痕」提醒——
        # 压缩不可逆，tool 消息里的渗透证据（接口/token/报文）蒸发后无法找回，
        # 让模型赶在被压前把关键结论 save_notes / registry_log 落到常驻通道
        warn_threshold = int(usable * 0.6)
        if est >= warn_threshold and not getattr(self, "_compact_warned", False):
            self._compact_warned = True
            self._compact_warn_count = getattr(self, "_compact_warn_count", 0) + 1
            self.state.push_event({"type": "log", "data": {
                "level": "warn",
                "text": f"上下文水位 {est}/{threshold} tokens——即将压缩，已注入留痕预警"}})
            return history + [{
                "role": "user",
                "content": ("[系统] 上下文即将达到压缩阈值（水位 "
                            f"{est}/{threshold} tokens）。压缩会把较早的工具结果替换为摘要，"
                            "渗透证据（接口路径/token/报文/密钥）会随之蒸发。**立即**把当前"
                            "所有未沉淀的关键结论落盘：① save_notes 写签名算法/接口契约/"
                            "密钥来源等结论；② registry_log 留痕本轮测试动作与证据；"
                            "③ 超长原文依赖 read_artifact 回读，无需重跑。完成后再继续当前动作")
            }]
        if est < int(usable * 0.5):
            self._compact_warned = False   # 水位回落（如压缩后）重置预警，下轮还能再报
        # 回复预留已折算进 usable（见上），这里不再重复扣 4000
        if est < threshold:
            return history
        # ② 重历史检测（Swarm history-slim 思路）：token 估算偏低估时可能漏触发，
        # 但「旧 turn 里堆了多少超长工具结果」是硬指标——渗透场景的 scan_sensitive/
        # get_http_captures 大回显就是最重的上下文残留。近窗消息（保留段）豁免，
        # 更早部分出现 8 条 ≥3000 字符的 tool 结果即直接压缩
        body_est = history[1:] if (history and history[0].get("role") == "system") else history
        heavy_recent = body_est[-4:]
        heavy_count = sum(
            1 for m in body_est[:-4]
            if m.get("role") == "tool" and len(str(m.get("content") or "")) >= 3000)
        if heavy_count >= 8 and len(body_est) > len(heavy_recent) + heavy_count // 2:
            return await self._do_compact(
                history, provider, model,
                reason=f"重历史（旧段 {heavy_count} 条超长工具结果）")
        return await self._do_compact(history, provider, model, reason="水位到达压缩阈值")

    async def _maybe_compact_force(self, history: list, provider: str, model: str) -> list:
        """F1 溢出兜底专用：跳过水位判断直接压缩（API 已报超限，估算已不可信）"""
        return await self._do_compact(history, provider, model, reason="API 报上下文超限")

    async def _do_compact(self, history: list, provider: str, model: str, reason: str = "") -> list:
        """压缩执行体（_maybe_compact 与 F1 强制压缩共用）：
        切分（F3 配对校验）→ 摘要（F2 加固 prompt）→ 拼接交接头。不压缩时原样返回。"""
        sys_head = 1 if (history and history[0].get("role") == "system") else 0
        body = history[sys_head:]
        # 至少保留最近 4 条消息原文
        if len(body) <= 4:
            return history
        # cut 只受「保留最近 4 条」约束，不再被 last_user 卡死——
        # 死穴现场：「继续」指令之后新堆了上百条消息，旧逻辑 cut=min(len-4, last_user)
        # 里 last_user 停在「继续」处，之后的长 tool 结果永远压不到（token 大头恰在那）
        cut = len(body) - 4
        # F3 切分点校验：cut 落在孤立 tool / 无 tool_calls 的纯文本 assistant 上时向后推进，
        # 直到落在「带 tool_calls 的 assistant」上——其后的 tool 消息随保留段一起保留，
        # 配对完整，杜绝「保留段开头是无主 tool」被 API 拒收
        while cut < len(body) and not self._is_paired_boundary(body, cut):
            cut += 1
        if cut >= len(body):
            return history

        old_body, keep_body = body[:cut], body[cut:]
        # C2 摘要材料补全：此前只喂 user/assistant content，tool 消息全剔除——
        # 渗透证据几乎全在 tool 结果里（URL/status/凭证/报文），压缩即蒸发。
        # 现在为每条 tool 消息提取关键行（与 _build_send_view 占位符同一套提取规则）
        mat = []
        for m in old_body:
            role = m.get("role")
            content = m.get("content") or ""
            if role in ("user", "assistant") and content:
                mat.append({"role": role, "content": content[:6000]})
            elif role == "tool":
                keys = []
                for line in str(content).splitlines():
                    ls = line.strip()
                    if not ls or ls in keys:
                        continue
                    if re.search(r'"?(url|status|method|credentials_sent|'
                                 r'authenticated_request|artifact_id|error|ok)"?\s*[:=]', ls):
                        keys.append(ls)
                    if len(keys) >= 5:
                        break
                if keys:
                    mat.append({"role": "tool", "name": m.get("name", "tool"),
                                "content": "\n".join(keys)})
        summary_text = json.dumps(mat, ensure_ascii=False)
        prompt = self._SUMMARY_PROMPT.format(history=summary_text[:60000])
        try:
            resp = await self.ai.chat(
                [{"role": "user", "content": prompt}],
                tools=None, provider=provider, model=model, max_tokens=2000,
                override=getattr(self, "_entry_override", None))
            summary = (resp.get("content") or "").strip()
        except Exception:
            return history  # 摘要失败不阻塞任务，维持原样
        if not summary:
            return history

        compact_head = {
            "role": "user",
            "content": f"[系统] {reason}，以下是此前测试工作的交接摘要（原始历史已归档，可重新调用工具获取细节）：\n\n{summary}\n\n{self.board.board_context(self._task_sid) if self._task_sid else ''}\n\n{self.feature_registry.registry_context(self._task_sid) if self._task_sid else ''}\n\n" + self._redline_block(),
        }
        compact_ack = {"role": "assistant", "content": "收到交接摘要，将在此基础上继续测试，不重复已完成的工作。"}
        new_history = history[:sys_head] + [compact_head, compact_ack] + keep_body
        self.state.push_event({"type": "log", "data": {"level": "info", "text": f"上下文压缩（{reason}）：{len(old_body)} 条消息 → 交接摘要（{self._estimate_tokens(new_history)} tokens）"}})
        return new_history

    def _model_window(self, provider: str, model: str) -> int:
        """上下文窗口统一按 128K 处理"""
        return 131072

    @staticmethod
    def _shrink_hist_tail(hist: list, drop: int = 20):
        """从历史尾部往前丢弃最早的 drop 条 tool 结果全文（保留配对结构）。

        输出被 length 截断时的输入瘦身手段：只把超长 tool content 换成
        占位摘要，不删消息、不破坏 assistant(tool_calls)/tool 配对。
        """
        n = 0
        for i, m in enumerate(hist):
            if m.get("role") != "tool":
                continue
            raw = m.get("content", "") or ""
            if len(raw) <= 400 or raw.startswith("[上下文瘦身"):
                continue
            if n < drop:
                head = raw[:150]
                hist[i] = {**m, "content":
                           f"[上下文瘦身：已省略较早的 {m.get('name', 'tool')} 结果"
                           f"（原 {len(raw)} 字符）]\n开头片段: {head}"}
                n += 1
            else:
                break
        return hist

    # ════════════════════════════════
    #  Agent 循环
    # ════════════════════════════════

    def _extract_value(self, result):
        if not result:
            return None
        r = result.get("result", {})
        inner = r.get("result", {})
        return inner.get("value")

    @staticmethod
    def _detect_mode(user_message: str) -> str:
        """根据用户输入自动判断执行模式，替代前端手动选择。

        - 明确要求完整测试/全流程 → full_pentest
        - 明确指向单一目标/具体动作（单独操作特征）→ manual
        - 无法判断时：默认 full_pentest（宁全勿缺）
        """
        text = (user_message or "").strip()
        if not text:
            return "manual"
        full_kw = ("全流程", "完整测试", "全面测试", "完整渗透", "全面渗透", "全部测一遍",
                   "整体测试", "标准流程", "三阶段", "测整个", "整个小程序")
        manual_kw = ("只测", "仅测", "单独", "看一下", "试试", "帮我点", "点击", "跳转到",
                     "跳到", "打开", "读一下", "查看", "抓一下", "重放", "扫一下", "测下",
                     "测一下", "试下")
        for kw in full_kw:
            if kw in text:
                return "full_pentest"
        for kw in manual_kw:
            if kw in text:
                return "manual"
        return "full_pentest"

    async def run_task(self, user_message: str, provider: str = "", model: str = "", mode: str = "", entry_override: dict = None):
        """执行一次完整的 Agent 任务循环（消息记录到当前会话）

        entry_override: 模型条目自带的连接配置（base_url/api_key），非空时本次任务以条目配置为准
        mode: 兼容旧参数。为空时按用户输入自动判断（全流程/单独操作）
        """
        self._entry_override = entry_override or {}
        # 任务模型身份必须随 override 一起落盘：语义检验（_semantic_mismatch_check）与
        # 统一留痕（L7020）按 _entry_provider/_entry_model 调 AI——只存 base_url 不存
        # 协议+模型名，检验调用会拿任务网关地址打全局协议（模型名在网关不存在）→ 404，
        # 报告前必跑的 AI 语义校验形同虚设（实测踩坑）
        self._entry_provider = provider or ""
        self._entry_model = model or ""
        if self.running:
            return {"ok": False, "error": "已有任务在运行"}
        # 执行模式：前端不再传递，按用户输入自动判断
        mode = mode or self._detect_mode(user_message)
        # 无会话时由对话自动创建新会话，首条消息作为会话标题
        sid = self.current_sid
        if not sid or sid not in self.sessions:
            sid = self.create_session(user_message.strip()[:20] or "")
            self.current_sid = sid
        if not self.engine.miniapp_clients:
            # 断连不在此处拦截：纯对话/生成报告/分析结果等请求无需小程序环境，
            # 工具级守门（_guard_miniapp_conn）+ reconnect_engine 已覆盖断连场景。
            # 仅记一条日志提示，AI 在任务内按需自行恢复连接
            self.state.push_log("warn", "[Agent] 小程序调试通道离线 — 不依赖小程序的请求照常执行，涉及操作的需先恢复连接")

        self.running = True
        self._stop_requested = False
        self.current_mode = mode   # 当前任务执行模式，画板工具据此开关
        self._task_sid = sid       # 当前任务会话，供信息搜集工具自动命名会话
        self._board_material_served_sid = getattr(self, "_board_material_served_sid", {})  # 素材门按 sid 记忆，跨任务保留
        self._static_gate_sig_sid = getattr(self, "_static_gate_sig_sid", {})  # 静态敏感闸门拒收签名，跨任务保留
        self._accept_fails = 0               # 报告验收连续 fail 计数：每任务重置
        self._overflow_retries = 0           # F1 溢出兜底重试计数：每任务重置
        # 代理残留自动清库（每任务开场）：代理是全局单例，上一任务留下的
        # 旧包与旧凭证若不清，会被本任务 get_http_captures 读到、旧 token
        # 被 _replay_headers 自动带进重放（未授权类判定失真）。证据链用的
        # 全是 registry_log 时的深拷贝快照，清缓冲对已留痕证据零影响；
        # 用户无需手动重启代理（提示会被人错过，自动清没有这个问题）
        try:
            pc = getattr(self.state, "proxy_capture", None)
            if pc is not None:
                stale = len(getattr(pc, "captures", []) or [])
                if stale > 0:
                    pc._reset_buffers()
                    self.state.push_log("info", f"[Agent] 任务开场已自动清理代理残留："
                                                f"上一任务 {stale} 条捕获与会话凭证")
        except Exception:
            pass
        task_started = time.time()  # 任务耗时统计起点
        task_tool_calls = 0         # 本次任务工具调用次数
        # 执行模式持久化到会话：老会话下次打开/刷新仍保留自己上次用的模式
        sess0 = self.sessions.get(sid)
        if sess0 is not None:
            sess0["mode"] = mode
            self._save_sessions()
        self._touch(sid)
        self.state.push_event({"type": "agent_status", "data": {"running": True, "sid": sid}})

        try:
            sess = self.sessions.get(sid)
            if sess is not None and not sess.get("history"):
                system = SYSTEM_PROMPT.format(now=datetime.now().strftime("%Y-%m-%d %H:%M"))
                # 授权语境固定注入（本工具即授权安全测试场景，无需用户开关）：
                # 消除 AI 在报告前质检环节因「读到真实 PII + 被要求重发测试包」触发的道德中止
                system += self._AUTHZ_CLAUSE
                # C1 Skill 按需加载：system 层只放索引（名称+场景+触发词），正文由
                # load_skill 工具按需注入——此前全文拼进 system，hunt-xss 等 174 案例
                # 的 Skill 常驻上下文烧 token 且稀释注意力，而单任务通常只用到 2-3 个
                skills = []
                try:
                    skills = self.state.enabled_skills()
                except Exception:
                    pass
                if skills:
                    skill_index = "\n".join(
                        f"- **{s.get('name', '未命名')}**：{(s.get('description') or '').strip()[:80] or '（无描述）'}"
                        for s in skills)
                    system += (f"\n\n## 已启用 Skill 索引（正文不在此处！用 load_skill(name) 加载全文）\n"
                               f"{skill_index}\n"
                               "匹配到功能点特征后、开始该功能点测试前，调用 load_skill 加载对应 Skill 正文"
                               "作为测试方法论；每个 Skill 用完（该功能点测完 save_notes 沉淀结论后）"
                               "可调用 release_skill 卸载释放注意力空间")
                sess["history"].append({"role": "system", "content": system})
            if sess is not None:
                # 老会话续聊但 system 里没有授权声明（历史会话/压缩重建前）时补注入
                if sess.get("history"):
                    h0 = sess["history"][0]
                    if h0.get("role") == "system" and self._AUTHZ_MARK not in h0.get("content", ""):
                        h0["content"] += self._AUTHZ_CLAUSE
                # 执行模式注入：只进 AI 上下文（history），显示层始终用原始消息，
                # 避免前端出现「原始消息 + 带前缀消息」两条重复气泡
                if mode == "full_pentest":
                    sess["history"].append({"role": "user", "content": f"[执行模式:全流程渗透] {user_message}"})
                elif mode == "manual":
                    sess["history"].append({"role": "user", "content": f"[执行模式:单独操作] {user_message}"})
                else:
                    sess["history"].append({"role": "user", "content": user_message})
            hist = list(sess["history"]) if sess is not None else []   # 任务本地历史，与会话切换隔离
            # A'：回载清扫——上次任务落盘成功的巨型 generate_report args 在进上下文前瘦身
            self._shrink_saved_report_args(hist)
            self._record_display("user", user_message)
            self.state.push_event({"type": "agent_message", "data": {"role": "user", "content": user_message, "sid": sid}})

            steps = 0
            # 两种模式均不设步数上限，任务自然完成或由用户手动停止
            step_limit = None
            empty_streak = 0     # 连续空回复计数（连续 3 次才收尾，防中转站抖动掐断任务）
            self._reply_max_tokens = 8192  # 输出预算：被 length 截断时砍半自适应
            task_status = "已完成"  # 收尾状态：已完成 / 已被用户手动停止 / 提前结束（模型空回复）
            while step_limit is None or steps < step_limit:
                if self._stop_requested:
                    task_status = "已被用户手动停止"
                    self._record_display("assistant", "⏹ 已被用户手动停止")
                    self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": "⏹ 已被用户手动停止", "sid": sid}})
                    break
                steps += 1
                self.state.push_event({"type": "agent_step", "data": {"step": steps, "sid": sid}})
                # 步级检查点（LangGraph 思想）：每步落盘任务状态，进程异常退出后
                # 重启时可识别「上次还在 running」并留恢复锚点（__init__ 里做检测提示）
                self._checkpoints[sid] = {"status": "running", "step": steps,
                                          "message": user_message[:100],
                                          "updated_at": time.strftime("%m-%d %H:%M:%S")}
                self._save_json_file(self._checkpoints_path, self._checkpoints)

                # 上下文管理：估算接近窗口阈值时自动交接摘要压缩
                hist = await self._maybe_compact(hist, provider, model)

                # chat 请求可中断：思考型模型单轮生成几十秒 + providers 层最多 5 次退避
                # 重试，旧版停止标志要等这整轮自然结束才生效——用户点停止后长时间无响应。
                # 0.5s 轮询停止标志，命中即取消底层请求（httpx 收到 CancelledError 断连）
                async def _interruptible_chat():
                    chat_task = asyncio.ensure_future(self.ai.chat(
                        self._build_send_view(hist),
                        tools=self.registry.get_tool_schemas(),
                        provider=provider, model=model,
                        max_tokens=self._reply_max_tokens,
                        override=getattr(self, "_entry_override", None)))
                    try:
                        while True:
                            done, _ = await asyncio.wait({chat_task}, timeout=0.5)
                            if done:
                                return chat_task.result()
                            if self._stop_requested:
                                chat_task.cancel()
                                raise asyncio.CancelledError()
                    except asyncio.CancelledError:
                        if not chat_task.done():
                            chat_task.cancel()
                        raise

                try:
                    response = await _interruptible_chat()
                except asyncio.CancelledError:
                    task_status = "已被用户手动停止"
                    self._record_display("assistant", "⏹ 已被用户手动停止（AI 回复已中断）")
                    self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": "⏹ 已被用户手动停止", "sid": sid}})
                    break
                except Exception as e:
                    # F1 溢出兜底：API 报上下文超限时强制压缩重试（限 2 次）——
                    # 估算偏差或网关窗口比配置小导致 _maybe_compact 没拦住时，这是最后防线。
                    # 压缩走同一套交接摘要流程，证据落盘纪律与红线不变
                    if self._is_context_overflow(e) and not getattr(self, "_stop_requested", False):
                        ovf_tries = getattr(self, "_overflow_retries", 0) + 1
                        self._overflow_retries = ovf_tries
                        if ovf_tries <= 2:
                            self.state.push_event({"type": "log", "data": {
                                "level": "warn",
                                "text": f"API 报上下文超限（第 {ovf_tries} 次），强制压缩后重试"}})
                            compacted = await self._maybe_compact_force(hist, provider, model)
                            if compacted is not hist:
                                hist = compacted
                                continue  # 压缩成功，原样重发（本轮不计步失败）
                            # 压缩没产出（历史太短/摘要失败）→ 瘦身历史尾部再试
                            self._shrink_hist_tail(hist, drop=30)
                            continue
                        # ③ 溢出终态（Swarm context-budget 终态语义）：重试额度耗尽
                        # 说明压缩已救不回来（历史极小仍超限=窗口配置远小于模型要求，
                        # 或摘要持续失败）——确定性停机+明确指引，不再无限循环重试。
                        # 收尾走正常流程：hist 原样留存落盘，已执行的工具结果一条不丢
                        msg = ("⚠ 上下文超限且压缩后仍无法恢复（已重试 2 次），任务已停止。"
                               "已完成的测试动作与留痕全部保留，请开新会话发「继续」接续测试"
                               "（新会话会自动带上登记册/画板/笔记交接）")
                        self._record_display("assistant", msg)
                        self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": msg, "sid": sid}})
                        task_status = "提前结束（上下文超限，压缩无法恢复）"
                        break
                    # AI 请求失败（配置错误/网络/额度）不再炸掉整个任务循环，
                    # 转为错误消息正常收尾，会话历史与已执行的工具结果全部保留。
                    # 瞬时错误（超时/5xx/429）已被 providers 层重试过 4 次，到这里
                    # 多为持续故障——收尾并如实标注状态，可发「继续」接续测试
                    msg = f"⚠ AI 请求失败: {e}"
                    self._record_display("assistant", msg)
                    self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": msg, "sid": sid}})
                    task_status = f"提前结束（AI 请求失败: {str(e)[:60]}）"
                    break
                content = response.get("content", "")
                tool_calls = response.get("tool_calls", [])

                # 会话 token 消耗累计（prompt+completion；usage 缺失时按字符数粗估，
                # 中文约 1.6 字符/token）：会话卡片以 M（百万）为单位展示
                usage = response.get("usage") or {}
                pt = int(usage.get("prompt_tokens") or 0)
                ct = int(usage.get("completion_tokens") or 0)
                # C' 校准：API 返回真实 prompt_tokens 时回写估算系数（EMA 平滑防抖动），
                # _estimate_tokens 从此贴合当前模型 tokenizer（修掉中文估算打对折的偏差）
                if pt > 0:
                    try:
                        raw_est = self._estimate_tokens(
                            self._build_send_view(hist), raw=True)
                        if raw_est > 0:
                            ratio = pt / raw_est
                            if 0.3 <= ratio <= 3.0:  # 离谱值（网关乱报）不采信
                                old = getattr(self, "_tok_ratio", 1.0)
                                self._tok_ratio = old * 0.8 + ratio * 0.2
                    except Exception:
                        pass
                if pt <= 0 and ct <= 0:
                    est = len(self._build_send_view(hist).__str__()) // 2
                    pt, ct = est, max(1, len(content) * 3 // 5)
                sess_tok = self.sessions.get(sid)
                if sess_tok is not None:
                    # 只累计内存，落盘随任务收尾统一进行（避免每步全量写 sessions.json）
                    sess_tok["token_total"] = sess_tok.get("token_total", 0) + pt + ct

                # 空回复防护：空 content 且无 tool_calls 有两种真身——
                # ① finish_reason=length：输出被 max_tokens 掐断（实测 glm-5.3-flash
                #   上下文肥大时思考烧满 8192 顶格、content 落空，API 日志却显示
                #   「成功 · 输出 8.2K」）——这不是空回复，重试无用，必须降
                #   max_tokens + 瘦身重发；
                # ② 真空回复：网关抖动，追加提醒重试即可。
                # 两种都连续 3 次才认输收尾，状态标「提前结束」而非「已完成」
                if not content and not tool_calls:
                    empty_streak += 1
                    truncated = (response.get("finish_reason") == "length")
                    if truncated:
                        # 截断：砍半回复预算（下限 2048），并从历史尾部丢弃最老的
                        # 一对 tool 消息给输入瘦身（不破坏 assistant/tool 配对）
                        self._reply_max_tokens = max(2048, self._reply_max_tokens // 2)
                        self._shrink_hist_tail(hist)
                        hist.append({"role": "user", "content":
                                     f"[系统] 模型输出被 max_tokens 截断（finish_reason=length，"
                                     f"思考/输出预算已降为 {self._reply_max_tokens}，输入已瘦身）。"
                                     "请直接输出下一步动作或结论，勿长篇推理。"})
                        self.state.push_event({"type": "log", "data": {
                            "level": "warn",
                            "text": f"输出截断（length）：max_tokens 降为 {self._reply_max_tokens} 并瘦身历史后重试（第 {empty_streak} 次）"}})
                        if empty_streak < 3:
                            continue
                    else:
                        if empty_streak < 3:
                            hist.append({"role": "assistant", "content": ""})
                            hist.append({"role": "user", "content":
                                         f"[系统] 第 {empty_streak} 次收到空回复。任务尚未完成"
                                         f"（登记功能点 {len(self.feature_registry.list_items())} 个，"
                                         f"其中未测试的仍需继续），请从中断处继续执行；若确已完成请输出总结。"})
                            continue
                    msg = ("⚠ 模型连续输出截断（max_tokens 顶格仍无正文），任务提前结束"
                           "（已执行的工作已保存，可发送「继续」并在模型页换更大输出预算的模型接续）"
                           if truncated else
                           "⚠ 模型连续返回空回复，任务提前结束（已执行的工作已保存，可发送「继续」接续测试）")
                    self._record_display("assistant", msg)
                    self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": msg, "sid": sid}})
                    task_status = "提前结束（输出截断）" if truncated else "提前结束（模型空回复）"
                    break
                empty_streak = 0
                self._reply_max_tokens = 8192  # 正常回复后恢复默认输出预算

                # 截断残废调用：finish_reason=length 掐断 arguments JSON → providers 层
                # 置空参数并标记 args_broken。直接给该调用回填「瘦身重发」指令（不执行
                # 工具、不计 StuckDetector——空参数原样重发必再截断，会把 AI 推进
                # 「空参数轰炸」卡死循环，实测踩坑），并主动砍半输出预算防下次再截
                if response.get("args_broken"):
                    self._reply_max_tokens = max(2048, self._reply_max_tokens // 2)
                    for tc in tool_calls:
                        hist.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                     "content": json.dumps({"error":
                                         "上一次调用的参数 JSON 被输出截断（max_tokens 顶格），参数没有传到。"
                                         "这不是参数校验错误，重发同样内容还会截断。瘦身要求：本轮只发这一个工具调用，"
                                         "findings 只保留当前正在写的这一条（其余下轮再发），"
                                         "packets 一律省略（系统按 feature 自动填充真实留痕包，不需要你手写报文），"
                                         "description/复现各控制在 200 字以内"}, ensure_ascii=False)})
                    self.state.push_event({"type": "log", "data": {
                        "level": "warn",
                        "text": f"工具调用参数被输出截断，已注入瘦身指引并降预算至 {self._reply_max_tokens}"}})
                    continue  # 不进入工具执行循环，直接下一轮让 AI 按瘦身指引重发

                if content:
                    self._record_display("assistant", content)
                    self.state.push_event({"type": "agent_message", "data": {"role": "assistant", "content": content, "sid": sid}})

                if not tool_calls:
                    # 任务完成
                    break

                # 记录 assistant 消息（含 tool_calls）
                hist.append({
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {"id": tc["id"], "name": tc["name"], "arguments": tc["arguments"]}
                        for tc in tool_calls
                    ],
                })

                # 执行工具
                for tc in tool_calls:
                    if self._stop_requested:
                        break
                    task_tool_calls += 1
                    self.state.push_event({
                        "type": "agent_tool",
                        "data": {"name": tc["name"], "arguments": tc["arguments"], "sid": sid},
                    })
                    result = await self.registry.execute(tc["name"], tc["arguments"])
                    # A'：报告落盘成功后立刻瘦身 history 里的巨型 args（复利重发最大头）
                    if tc["name"] == "generate_report" and isinstance(result, dict) \
                            and result.get("ok") is True:
                        self._shrink_report_call_args(hist, tc.get("id", ""))
                    # StuckDetector：同工具+同参数在窗口内重复 → 注入换策略提醒
                    # （结果回告进本轮 tool content，AI 下一步即读到；不修改 history 结构）
                    try:
                        stuck_hint = self._check_stuck(tc["name"], tc["arguments"])
                        if stuck_hint:
                            result = {**result, "stuck_warning": stuck_hint} if \
                                isinstance(result, dict) else result
                            self.state.push_event({"type": "log", "data": {
                                "level": "warn", "text": f"StuckDetector：{tc['name']} 疑似循环卡死，已注入换策略提醒"}})
                    except Exception:
                        pass
                    # L1 同目标失败熔断：同目标（URL 主干/接口）不同参数的连续失败
                    # （盲猜前缀 404 换前缀再猜）是 StuckDetector 盲区，此处在结果
                    # 到达后按目标键并列检测——连续失败 ≥5 次注入强制换路提醒
                    try:
                        tfail_hint = self._check_target_failure(
                            tc["name"], tc["arguments"],
                            json.dumps(result, ensure_ascii=False, default=str)[:4000])
                        if tfail_hint:
                            result = {**result, "target_fail_warning": tfail_hint} if \
                                isinstance(result, dict) else result
                            self.state.push_event({"type": "log", "data": {
                                "level": "warn", "text": "同目标失败熔断：连续失败已注入换路提醒"}})
                    except Exception:
                        pass
                    # 任意工具结果里发现小程序名/appid → 自动升级会话命名
                    # （不限于 get_app_info：抓包、HTTP 响应、反编译等途径均覆盖）
                    try:
                        self._maybe_rename_from_result(result)
                    except Exception:
                        pass
                    # 信息搜集类工具 → 画板「信息搜集」分支自动记录资产条目
                    try:
                        self._auto_board_from_tool(tc["name"], result, sid)
                    except Exception:
                        pass
                    result_str = self._trim_tool_result(
                        json.dumps(result, ensure_ascii=False, default=str),
                        tool_name=tc["name"], sid=sid)
                    # 展示层截断：普通回执 2000 防刷屏；报错类回执（验收 issues/
                    # 门禁报错/must_fix）放宽到 8000——问题清单被砍尾后人工监督
                    # 视图看不到 AI 实际收到的问题全貌，复盘对照失真（wx562 实测）
                    _disp = result_str[:2000]
                    if any(k in result_str for k in ('"error"', '"issues"',
                                                     "must_fix", "验收未通过")):
                        _disp = result_str[:8000]
                    self._record_display("tool", f"⚒ {tc['name']}\n{_disp}")
                    self.state.push_event({
                        "type": "agent_tool_result",
                        "data": {"name": tc["name"], "result": _disp, "sid": sid},
                    })
                    hist.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "name": tc["name"],
                        "content": result_str,
                    })

            # 任务收尾：追加本次任务情况总结（仅展示层，不进 AI 上下文）
            self._append_task_summary(sid, task_started, steps, task_tool_calls, task_status)
            # 检查点收尾：正常结束/手动停止/提前结束都置终态，只有异常崩溃才会
            # 留下 running 状态供重启检测（finally 在此之后仍会执行，无副作用）
            if sid in self._checkpoints:
                self._checkpoints[sid]["status"] = f"ended({task_status[:30]})"
                self._checkpoints[sid]["updated_at"] = time.strftime("%m-%d %H:%M:%S")
                self._save_json_file(self._checkpoints_path, self._checkpoints)
            # 回写会话历史
            if sess is not None:
                sess["history"] = list(hist)
            self._touch(sid)
            self._save_sessions()
            return {"ok": True, "steps": steps, "sid": sid}
        except Exception as e:
            self._record_display("error", str(e))
            self.state.push_event({"type": "agent_error", "data": {"error": str(e), "sid": sid}})
            try:
                self._append_task_summary(sid, task_started, steps, task_tool_calls, f"异常终止: {str(e)[:80]}")
            except Exception:
                pass
            # 异常时也回写
            sess = self.sessions.get(sid)
            if sess is not None:
                sess["history"] = list(hist)
            self._touch(sid)
            self._save_sessions()
            return {"ok": False, "error": str(e)}
        finally:
            self.running = False
            self.state.push_event({"type": "agent_status", "data": {"running": False, "sid": sid}})

    def _append_task_summary(self, sid: str, started: float, steps: int, tool_calls: int, status: str):
        """每次任务（一轮对话）结束后在展示层追加任务情况+耗时总结条"""
        if sid not in self.sessions:
            return
        elapsed = max(0, int(time.time() - started))
        dur = f"{elapsed // 60}分{elapsed % 60}秒" if elapsed >= 60 else f"{elapsed}秒"
        text = f"—— 本次任务{status} · 用时 {dur} · 执行 {steps} 步 · 调用工具 {tool_calls} 次 ——"
        self._record_display("summary", text)
        self.state.push_event({"type": "agent_message", "data": {"role": "summary", "content": text, "sid": sid}})

    def clear_history(self):
        self.history = []

    def stop(self):
        """请求停止当前任务循环（协作式取消：当前工具执行完即中断）"""
        if self.running:
            self._stop_requested = True
            self.state.push_event({"type": "agent_stop_requested", "data": {}})
            return True
        return False
