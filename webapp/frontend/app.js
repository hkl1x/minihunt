/* Minihunt 前端逻辑 */
"use strict";

// ══════════════════════════════
//  基础工具
// ══════════════════════════════
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

async function api(path, opts = {}) {
  const config = {
    headers: { "Content-Type": "application/json" },
    ...opts,
  };
  if (config.body && typeof config.body !== "string") {
    config.body = JSON.stringify(config.body);
  }
  const resp = await fetch(`/api${path}`, config);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || `HTTP ${resp.status}`);
  }
  return data;
}

function toast(msg, type = "info") {
  // 页面已切走等场景下的渲染报错对用户无意义，不弹卡片（后台仍留 console 便于排查）
  if (/Cannot set propert(y|ies) of (null|undefined)/i.test(String(msg))) {
    console.warn("[suppressed toast]", msg);
    return;
  }
  const wrap = $("#toast-wrap");
  if (!wrap) return;
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => { el.classList.add("hide"); setTimeout(() => el.remove(), 300); }, 3600);
}

// 自定义确认弹窗（页面居中，替代原生 confirm）
// 用法: if (await confirmDialog({ title, message, danger, okText })) { ... }
function confirmDialog({ title = "确认操作", message = "", danger = false, okText = "确认", cancelText = "取消" } = {}) {
  return new Promise((resolve) => {
    const mask = document.createElement("div");
    mask.className = "cfm-mask";
    mask.innerHTML = `
      <div class="cfm-box ${danger ? "danger" : ""}">
        <div class="cfm-icon">${danger ? "⚠" : "?"}</div>
        <div class="cfm-title">${esc(title)}</div>
        <div class="cfm-msg">${esc(message)}</div>
        <div class="cfm-btns">
          <button class="cfm-btn cancel">${esc(cancelText)}</button>
          <button class="cfm-btn ok">${esc(okText)}</button>
        </div>
      </div>`;
    const done = (val) => { mask.remove(); document.removeEventListener("keydown", onKey, true); resolve(val); };
    const onKey = (e) => {
      if (e.key === "Escape") done(false);
      if (e.key === "Enter") { e.stopPropagation(); done(true); }
    };
    mask.querySelector(".cfm-btn.cancel").onclick = () => done(false);
    mask.querySelector(".cfm-btn.ok").onclick = () => done(true);
    mask.onclick = (e) => { if (e.target === mask) done(false); };
    document.addEventListener("keydown", onKey, true);
    document.body.appendChild(mask);
    mask.querySelector(".cfm-btn.ok").focus();
  });
}

// ══════════════════════════════
//  自定义下拉面板：美化原生 select 的展开选项（保留 select 元素与取值逻辑不变）
//  用法：页面渲染后对每个 select 调用 beautifySelect(sel)
// ══════════════════════════════
let _bsActive = null; // 当前打开的面板 {sel, pop, close}
function _bsClose() {
  if (_bsActive) {
    _bsActive.pop.remove();
    _bsActive.sel.classList.remove("bs-open");
    document.removeEventListener("mousedown", _bsActive.onDoc, true);
    document.removeEventListener("scroll", _bsActive.onDoc, true);
    _bsActive = null;
  }
}
function beautifySelect(sel) {
  if (!sel || sel.dataset.bs === "1") return;
  sel.dataset.bs = "1";
  sel.classList.add("bs-select");
  sel.addEventListener("mousedown", (e) => {
    if (_bsActive && _bsActive.sel === sel) { e.preventDefault(); _bsClose(); return; }
    e.preventDefault(); // 阻止原生面板
    _bsClose();
    // 重建选项面板（实时读 select 当前 options）
    const pop = document.createElement("div");
    pop.className = "bs-pop";
    const r = sel.getBoundingClientRect();
    const opts = [...sel.options];
    opts.forEach((o, i) => {
      const item = document.createElement("div");
      item.className = "bs-item" + (i === sel.selectedIndex ? " on" : "") + (o.disabled ? " dis" : "");
      item.textContent = o.textContent;
      item.onmousedown = (ev) => {
        ev.stopPropagation();
        if (o.disabled) return;
        sel.selectedIndex = i;
        sel.dispatchEvent(new Event("change", { bubbles: true }));
        _bsClose();
      };
      pop.appendChild(item);
    });
    document.body.appendChild(pop);
    // 定位：向下展开，空间不足则向上；宽度跟随 select
    pop.style.minWidth = r.width + "px";
    pop.style.left = r.left + "px";
    const ph = pop.offsetHeight || Math.min(opts.length * 34 + 12, 260);
    if (r.bottom + ph + 8 > window.innerHeight) {
      pop.style.top = Math.max(8, r.top - ph - 6) + "px";
      pop.classList.add("up");
    } else {
      pop.style.top = r.bottom + 4 + "px";
    }
    sel.classList.add("bs-open");
    const onDoc = (ev) => { if (!pop.contains(ev.target)) _bsClose(); };
    _bsActive = { sel, pop, onDoc };
    document.addEventListener("mousedown", onDoc, true);
    document.addEventListener("scroll", onDoc, true);
  });
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

function fmtJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch (e) {
    return String(obj);
  }
}

// ══════════════════════════════
//  页面注册
// ══════════════════════════════
const PAGES = {};
function registerPage(id, title, icon, render) {
  PAGES[id] = { id, title, icon, render };
}

// 内联 SVG 图标（stroke=currentColor，自动随主题/激活态变色）
const NAV_ICONS = {
  // 前期预构：仪表盘
  control: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>`,
  // AI渗透：终端提示符
  agent: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`,
  // 渗透画板：思维导图节点
  board: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="12" r="2.2"/><circle cx="19" cy="5" r="2.2"/><circle cx="19" cy="12" r="2.2"/><circle cx="19" cy="19" r="2.2"/><path d="M7.2 11 16.8 5.6M7.2 12h9.6M7.2 13 16.8 18.4"/></svg>`,
  // 渗透报告：文档清单
  report: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>`,
  // Skill 列表：书本
  skills: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>`,
  // 模型列表：齿轮
  aiset: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
};

// ══════════════════════════════
//  导航
// ══════════════════════════════
function navigate(pageId) {
  const page = PAGES[pageId];
  if (!page) return;
  $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.page === pageId));
  $("#page-title").textContent = page.title;
  // 「启动调试」「启动代理」按钮仅在前期预构页显示
  $("#btn-engine").style.display = pageId === "control" ? "" : "none";
  $("#btn-topbar-proxy").style.display = pageId === "control" ? "" : "none";
  const c = $("#page-container");
  c.innerHTML = "";
  page.render(c);
  c.scrollTop = 0;
}

// ══════════════════════════════
//  WebSocket 实时事件
// ══════════════════════════════
let ws = null;
let wsHandlers = {};
function onWsEvent(type, fn) { (wsHandlers[type] = wsHandlers[type] || []).push(fn); }

function connectWs() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      (wsHandlers[event.type] || []).forEach((fn) => fn(event.data));
    } catch (err) {}
  };
  ws.onclose = () => setTimeout(connectWs, 3000);
  ws.onerror = () => ws.close();
}

// ══════════════════════════════
//  状态
// ══════════════════════════════
const appState = { frida: false, miniapp: false, devtools: false, agent_running: false };

function updateStatusUI() {
  const btn = $("#btn-engine");
  btn.textContent = appState.frida ? "停止调试" : "启动调试";
  btn.classList.toggle("btn-danger", appState.frida);
  btn.classList.toggle("btn-primary", !appState.frida);
  // 同步更新前期预构页的状态卡片（若存在）
  const map = { frida: "ctl-frida", miniapp: "ctl-miniapp" };
  for (const k in map) {
    const el = document.getElementById(map[k]);
    if (el) {
      el.textContent = appState[k] ? "已连接" : "未连接";
      el.className = appState[k] ? "stat-value accent-text" : "stat-value muted";
    }
  }
  // 小程序版本 · 偏移量卡：版本在 Frida 注入过程中随进程检测一并得出（注入失败也会先上报版本）
  // offset_ready: true=绿就绪 / false=黄缺失 / null=灰尚未注入
  const off = document.getElementById("ctl-offset");
  if (off) {
    const v = appState.wmpf_version;
    const ready = appState.offset_ready;
    if (v == null) {
      off.textContent = "未注入";
      off.className = "stat-value muted";
    } else if (ready === true) {
      off.textContent = `WMPF ${v} · 偏移就绪`;
      off.className = "stat-value accent-text";
    } else if (ready === false) {
      off.textContent = `WMPF ${v} · 缺偏移量`;
      off.className = "stat-value warn-text";
    } else {
      off.textContent = `WMPF ${v}`;
      off.className = "stat-value muted";
    }
  }
}

// ws 状态事件：合并进 appState 后统一刷新（注入过程中引擎多次上报，卡片实时跟随）
onWsEvent("status", (data) => { Object.assign(appState, data); updateStatusUI(); });

// 顶栏代理按钮文案/样式（运行中变「停止代理」红色）
function updateTopbarProxy() {
  const b = $("#btn-topbar-proxy");
  if (!b) return;
  b.textContent = appState.proxy_running ? "停止代理" : "启动代理";
  b.classList.toggle("btn-danger", !!appState.proxy_running);
}

async function refreshStatus() {
  try {
    Object.assign(appState, await api("/status"));
    try {
      const ps = await api("/proxy/status");
      appState.proxy_running = !!ps.running;
    } catch (e) { appState.proxy_running = false; }
    updateStatusUI();
    updateTopbarProxy();
  } catch (e) {}
}

// ══════════════════════════════
//  页面: 前期预构
// ══════════════════════════════
registerPage("control", "前期预构", "◉", (c) => {
  c.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">捕获代理</div>
        <div class="stat-value muted" id="ctl-proxy">未启动</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">小程序版本 · 偏移量</div>
        <div class="stat-value muted" id="ctl-offset">未注入</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Frida 注入</div>
        <div class="stat-value" id="ctl-frida">未连接</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">小程序</div>
        <div class="stat-value" id="ctl-miniapp">未连接</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">代理证书安装</div>
      <div class="muted" style="font-size:12px;line-height:1.8">
        HTTPS 解密需安装 mitmproxy CA 证书（只需一次）：双击本地证书文件
        <span style="user-select:all">%USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.cer</span>
        → 安装到「受信任的根证书颁发机构」。
      </div>
    </div>
    <div class="card">
      <div class="card-title">小程序包路径</div>
      <div class="muted" id="pkg-info" style="font-size:12px"></div>
    </div>
    <div class="card">
      <div class="card-title">运行日志</div>
      <div class="log-box" id="log-box"></div>
    </div>
  `;
  // 小程序包路径（只读显示，路径在 minihunt_config.json 的 packages_dir 配置）
  const loadPkgDir = async () => {
    const box = $("#pkg-info");
    if (!box) return;
    try {
      const d = await api("/config/packages_dir");
      box.textContent = d.configured
        ? `当前路径: ${d.configured}`
        : `当前路径: ${d.detected[0] || "未检测到"}（自动检测，共 ${d.detected.length} 个账号目录）`;
    } catch (e) {
      box.textContent = "检测失败: " + e.message;
    }
  };
  loadPkgDir();
  // HTTP 捕获代理
  const renderProxyStatus = (s) => {
    const el = $("#ctl-proxy");
    if (!el) return;
    if (s.running) {
      el.textContent = `运行中 · ${s.capture_count} 条${s.mode === "local" ? " · 进程拦截" : ""}`;
      el.className = "stat-value accent-text";
    } else {
      el.textContent = "未启动";
      el.className = "stat-value muted";
    }
  };
  const loadProxyStatus = async () => {
    try {
      renderProxyStatus(await api("/proxy/status"));
    } catch (e) { /* 忽略 */ }
  };
  loadProxyStatus();
  setInterval(loadProxyStatus, 5000);
  // 状态渲染：直接复用全局 updateStatusUI（含偏移量卡逻辑，避免两处渲染不一致）
  const render = () => updateStatusUI();
  render();
  onWsEvent("status", render);
  // 日志追加
  onWsEvent("log", (data) => {
    const box = $("#log-box");
    if (!box) return;
    const line = document.createElement("div");
    line.className = `log-line log-${data.level}`;
    const t = new Date(data.ts).toLocaleTimeString();
    line.textContent = `[${t}] ${data.text}`;
    box.appendChild(line);
    while (box.children.length > 500) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  });
});

// ══════════════════════════════
//  页面: 模型列表
// ══════════════════════════════
registerPage("aiset", "模型列表", "⚙", (c) => {
  c.innerHTML = `
    <div class="card">
      <div class="card-title">接入新模型</div>
      <div class="form-grid" style="max-width:560px">
        <label>Provider</label>
        <select id="ai-provider">
          <option value="openai">OpenAI 兼容 (DeepSeek/Qwen/Kimi/GLM...)</option>
          <option value="anthropic">Anthropic (Claude)</option>
          <option value="ollama">Ollama 本地</option>
        </select>
      </div>
      <div id="ai-openai-form" style="margin-top:14px">
        <div class="form-grid" style="max-width:560px">
          <label>Base URL</label><input type="text" id="ai-oai-url">
          <label>API Key</label><input type="password" id="ai-oai-key">
          <label>模型</label><input type="text" id="ai-oai-model">
        </div>
      </div>
      <div id="ai-anthropic-form" style="margin-top:14px;display:none">
        <div class="form-grid" style="max-width:560px">
          <label>Base URL</label><input type="text" id="ai-ant-url">
          <label>API Key</label><input type="password" id="ai-ant-key">
          <label>模型</label><input type="text" id="ai-ant-model">
        </div>
      </div>
      <div id="ai-ollama-form" style="margin-top:14px;display:none">
        <div class="form-grid" style="max-width:560px">
          <label>Base URL</label><input type="text" id="ai-ol-url">
          <label>模型</label><input type="text" id="ai-ol-model">
        </div>
      </div>
      <div class="row" style="margin-top:16px">
        <button class="btn" id="ai-test">测试连接</button>
        <button class="btn btn-primary" id="ai-add-model">加入模型</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title">已接入模型</div>
      <div id="model-list" class="model-list"></div>
    </div>
  `;
  const providerSel = $("#ai-provider");
  beautifySelect(providerSel);
  const toggleForms = () => {
    $("#ai-openai-form").style.display = providerSel.value === "openai" ? "block" : "none";
    $("#ai-anthropic-form").style.display = providerSel.value === "anthropic" ? "block" : "none";
    $("#ai-ollama-form").style.display = providerSel.value === "ollama" ? "block" : "none";
  };
  providerSel.onchange = toggleForms;
  api("/ai/config").then((cfg) => {
    providerSel.value = cfg.provider || "openai";
    toggleForms();
  });
  const collectConfig = () => {
    // 所有输入框默认空白；留空的字段不提交，后端保留原值
    const c = { provider: providerSel.value };
    const val = (sel) => $(sel).value.trim();
    if (val("#ai-oai-url")) c.openai_base_url = val("#ai-oai-url");
    if (val("#ai-oai-key")) c.openai_api_key = val("#ai-oai-key");
    if (val("#ai-oai-model")) c.openai_model = val("#ai-oai-model");
    if (val("#ai-ant-url")) c.anthropic_base_url = val("#ai-ant-url");
    if (val("#ai-ant-key")) c.anthropic_api_key = val("#ai-ant-key");
    if (val("#ai-ant-model")) c.anthropic_model = val("#ai-ant-model");
    if (val("#ai-ol-url")) c.ollama_base_url = val("#ai-ol-url");
    if (val("#ai-ol-model")) c.ollama_model = val("#ai-ol-model");
    return c;
  };
  $("#ai-test").onclick = async () => {
    const btn = $("#ai-test");
    toast("正在测试连接...", "info");
    btn.disabled = true;
    try {
      // 先把表单凭据提交到后端（key 留空 = 保留原值），再发起真实测试
      const cfg = collectConfig();
      await api("/ai/config", { method: "POST", body: cfg });
      const model = cfg.openai_model || cfg.anthropic_model || cfg.ollama_model;
      if (!model) return toast("请先填写模型名称", "warning");
      const d = await api("/ai/test", { method: "POST", body: { provider: cfg.provider, model } });
      toast(`连接成功 — ${d.reply}`, "success");
    } catch (e) {
      toast(e.message, "error");
    } finally {
      btn.disabled = false;
    }
  };
  // ── 已接入模型列表 ──
  const renderModels = (models) => {
    const wrap = $("#model-list");
    if (!models.length) {
      wrap.innerHTML = `<div class="muted">暂未接入模型，请在上方填写后点击「加入模型」</div>`;
      return;
    }
    wrap.innerHTML = models.map((m, i) => {
      const label = m.provider === "anthropic" ? "Anthropic" : m.provider === "ollama" ? "Ollama" : "OpenAI";
      return `<div class="model-item">
        <div class="model-info">
          <div class="model-name">${esc(m.label || m.model)}</div>
          <div class="muted model-sub">${label} · ${esc(m.model)}</div>
        </div>
        <div class="row">
          <button class="icon-btn" data-del="${i}" title="移除">✕</button>
        </div>
      </div>`;
    }).join("");
    wrap.querySelectorAll("[data-del]").forEach((el) => {
      el.onclick = async () => {
        const m = models[el.dataset.del];
        if (!(await confirmDialog({ title: "移除模型", message: `确认移除模型「${m?.label || m?.model || "未命名"}」？移除后需重新添加才能在任务中使用。`, danger: true, okText: "移除" }))) return;
        try {
          const d = await api(`/ai/models/${el.dataset.del}`, { method: "DELETE" });
          toast("已移除", "success");
          renderModels(d.models);
        } catch (e) { toast(e.message, "error"); }
      };
    });
  };
  const loadModels = async () => {
    try { renderModels((await api("/ai/models")).models); } catch (e) {}
  };
  loadModels();
  $("#ai-add-model").onclick = async () => {
    const cfg = collectConfig();
    const model = cfg.openai_model || cfg.anthropic_model || cfg.ollama_model;
    if (!model) return toast("请先填写模型名称", "warning");
    try {
      // 连接配置快照进模型条目：该模型自包含 base_url/api_key，删除即彻底清除
      const p = cfg.provider;
      const entry = {
        provider: p, model,
        base_url: p === "openai" ? (cfg.openai_base_url || "") : p === "anthropic" ? (cfg.anthropic_base_url || "") : (cfg.ollama_base_url || ""),
        api_key: p === "openai" ? (cfg.openai_api_key || "") : p === "anthropic" ? (cfg.anthropic_api_key || "") : "",
      };
      // 加入前先保存凭据到全局（旧版本兼容 + 连接测试用；key 留空 = 保留原值）
      await api("/ai/config", { method: "POST", body: cfg });
      const d = await api("/ai/models", { method: "POST", body: entry });
      toast("已加入模型", "success");
      renderModels(d.models);
    } catch (e) { toast(e.message, "error"); }
  };
});

// ══════════════════════════════
//  页面: AI 渗透（多会话）
// ══════════════════════════════
registerPage("agent", "AI渗透", "✦", (c) => {
  c.innerHTML = `
    <div class="agent-layout">
      <!-- 会话列表 -->
      <div class="card session-panel">
        <div class="card-title">会话列表
          <button class="btn btn-sm btn-primary" id="sess-add">+ 新建</button>
        </div>
        <div id="sess-list" class="sess-list"></div>
      </div>
      <!-- 对话区 -->
      <div class="chat-wrap card" style="margin-bottom:0;flex:1">
        <div class="chat-messages" id="chat-messages"></div>
        <!-- 跳到最新：用户上拉查看历史时出现，点击回到底部并恢复自动跟随 -->
        <button class="jump-latest" id="jump-latest" title="跳到最新消息" style="display:none">↓</button>
        <div class="chat-input-row">
          <textarea id="agent-input"></textarea>
          <div class="chat-input-bottom">
            <select id="agent-model" class="model-select" title="选择模型"></select>
            <button class="btn btn-primary" id="agent-send">发送</button>
          </div>
        </div>
      </div>
    </div>
    <!-- 重命名弹窗 -->
    <div class="modal-mask" id="sess-modal" style="display:none">
      <div class="modal">
        <div class="card-title">重命名会话</div>
        <div class="form-grid" style="margin-top:12px">
          <label>名称</label>
          <input type="text" id="sess-f-title" placeholder="会话名称">
        </div>
        <div class="row" style="margin-top:14px;justify-content:flex-end">
          <button class="btn" id="sess-cancel">取消</button>
          <button class="btn btn-primary" id="sess-save">保存</button>
        </div>
      </div>
    </div>
  `;
  let curSid = null;      // 当前查看的会话
  let sessMeta = {};      // sid -> 摘要
  let runningSid = null;  // 正在执行任务的会话 id（agent_status 维护）
  // 当前查看的会话是否正在执行任务（按钮态/消息删除按会话判断；
  // 全局 agent_running 只约束「同一时刻仅一个任务」，不再锁整个界面）
  const isCurRunning = () => !!(runningSid && runningSid === curSid);
  const box = $("#chat-messages");
  beautifySelect($("#agent-model"));

  // ── 滚动跟随：用户上拉看历史时冻结自动滚动，出现「↓ 跳到最新」按钮 ──
  // 距底部 >60px 视为「在翻历史」：新消息只追加不再滚动，按钮亮出；
  // 点按钮（或自己滚回底部附近）→ 恢复跟随。
  const jumpBtn = $("#jump-latest");
  let stickBottom = true; // 是否自动跟随到底
  const isNearBottom = () => box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const scrollBottom = () => { box.scrollTop = box.scrollHeight; };
  box.addEventListener("scroll", () => {
    stickBottom = isNearBottom();
    jumpBtn.style.display = stickBottom ? "none" : "flex";
  });
  jumpBtn.onclick = () => { stickBottom = true; jumpBtn.style.display = "none"; scrollBottom(); };
  // appendMsg/appendTool 里的自动滚动统一走这里：仅跟随态才滚
  const autoScroll = () => { if (stickBottom) scrollBottom(); };
  // 全量重渲染（切会话/删消息）后默认回到最新
  const resetFollow = () => { stickBottom = true; jumpBtn.style.display = "none"; scrollBottom(); };
  const WELCOME = `<div class="msg assistant"><div class="msg-bubble">
          <b>Minihunt Agent</b><br>
          我是 AI 小程序渗透测试助手-Minihunt。请先在「前期预构」页启动调试并打开目标小程序，然后进行测试。<br>
          <span style="font-size:12px;opacity:.7">发送「完整测试」进入全流程渗透；直接描述具体目标（如「只测登录页」）则为单独操作。</span>
        </div></div>`;

  const appendMsg = (role, content, idx = null) => {
    const div = document.createElement("div");
    if (role === "step") {
      closeToolGroup();
      div.className = "muted";
      div.style.cssText = "text-align:center;margin:8px 0;font-size:12px";
      div.textContent = `── 第 ${content} 步 ──`;
    } else if (role === "summary") {
      closeToolGroup();
      // 任务收尾总结（后端追加，仅展示层）
      div.className = "msg-summary";
      div.textContent = content;
    } else {
      closeToolGroup();
      div.className = `msg ${role}`;
      div.innerHTML = `<div class="msg-bubble">${esc(content)}</div>`;
      if (idx !== null) {
        div.dataset.idx = idx;
        bindCtxMenu(div, idx);
        div.onclick = () => { if (selMode) toggleRound(roundStartOf(idx)); };
      }
    }
    box.appendChild(div);
    autoScroll();
  };

  // ── 思考中指示器：贯穿任务执行期 ──
  // 非流式接口拿不到思维链，用持续可见的「思考中」气泡提示 AI 正在工作：
  // 每条消息/工具事件后重新挂到消息流底部，任务结束（agent_status running=false）才消失
  const removeThinking = () => { $("#thinking-indicator")?.remove(); };
  const showThinking = () => {
    // 只在执行任务的会话视图里显示；切到别的会话不显示
    if (runningSid && curSid && runningSid !== curSid) return;
    removeThinking();
    const div = document.createElement("div");
    div.className = "msg-thinking";
    div.id = "thinking-indicator";
    div.innerHTML = '<span class="tdot"></span><span class="tdot"></span><span class="tdot"></span><span class="tlabel">思考中…</span>';
    box.appendChild(div);
    autoScroll();
  };

  // ── 工具调用折叠组：连续工具收进一个可展开的折叠条 ──
  let toolGroup = null;   // 当前未收尾的折叠组 {el, listEl, count, pending}
  const closeToolGroup = () => { toolGroup = null; };
  const appendTool = (name, result, idx = null) => {
    const isRunning = result === "执行中...";
    // 结果到达时优先补进已有折叠组（agent_tool 与 agent_tool_result 成对到达）
    if (!isRunning && toolGroup) {
      const item = toolGroup.listEl.querySelector(`[data-tid="${CSS.escape(name)}"]:not(.done)`);
      if (item) {
        item.classList.add("done");
        item.classList.remove("pending");
        item.querySelector(".tool-result").textContent = result;
        if (idx !== null) item.dataset.idx = idx;
        toolGroup.pending--;
        if (toolGroup.pending <= 0) {
          // 全部工具执行完：头部从「正在调用」恢复为计数
          toolGroup.el.classList.remove("running");
          toolGroup.el.querySelector(".tg-label").textContent = `${toolGroup.count} 次工具调用`;
        }
        return;
      }
    }
    // 新工具开始：无折叠组则先建组（「N 次工具调用」标题行，点击展开/收起）
    if (!toolGroup) {
      const wrap = document.createElement("div");
      wrap.className = "tool-group collapsed";
      const head = document.createElement("div");
      head.className = "tool-group-head";
      head.innerHTML = `<span class="tg-arrow">▸</span><span class="tg-label">1 次工具调用</span>`;
      const list = document.createElement("div");
      list.className = "tool-group-list";
      wrap.appendChild(head); wrap.appendChild(list);
      head.onclick = () => {
        const c = wrap.classList.toggle("collapsed");
        wrap.querySelector(".tg-arrow").textContent = c ? "▸" : "▾";
      };
      box.appendChild(wrap);
      toolGroup = { el: wrap, listEl: list, count: 0, pending: 0 };
    }
    toolGroup.count++;
    const label = toolGroup.el.querySelector(".tg-label");
    if (isRunning) {
      // 调用中：头部与条目都给「正在调用」进行时状态，结果到达后由上方恢复
      toolGroup.pending++;
      toolGroup.el.classList.add("running");
      label.textContent = `正在调用 ${name}…`;
    } else {
      label.textContent = `${toolGroup.count} 次工具调用`;
    }
    const div = document.createElement("div");
    div.className = "msg-tool" + (isRunning ? " pending" : "");
    div.dataset.tid = name;
    div.innerHTML = `⚒ ${esc(name)}<div class="tool-result">${isRunning ? "正在调用…" : esc(result)}</div>`;
    if (idx !== null) {
      div.dataset.idx = idx;
      bindCtxMenu(div, idx);
      div.onclick = () => { if (selMode) toggleRound(roundStartOf(idx)); };
    }
    toolGroup.listEl.appendChild(div);
    autoScroll();
  };

  // ── 消息右键菜单 / 多选删除 ──
  let selMode = false;        // 多选模式
  let selRounds = new Set();  // 已选轮次起始下标
  let curDisplay = [];        // 当前会话 display（供轮次计算）

  const hideCtxMenu = () => {
    const m = $("#msg-ctx-menu");
    if (m) m.remove();
  };
  document.addEventListener("click", hideCtxMenu);
  window.addEventListener("blur", hideCtxMenu);

  const roundStartOf = (idx) => {
    let s = idx;
    while (s > 0 && curDisplay[s]?.role !== "user") s--;
    return s;
  };

  const bindCtxMenu = (el, idx) => {
    el.oncontextmenu = (e) => {
      e.preventDefault();
      if (isCurRunning()) return toast("当前会话执行中，无法删除消息", "warning");
      hideCtxMenu();
      const menu = document.createElement("div");
      menu.id = "msg-ctx-menu";
      menu.innerHTML = `
        <div class="ctx-item" data-act="select">选中（多选删除）</div>
        <div class="ctx-item ctx-danger" data-act="delete">删除（删除该轮对话）</div>`;
      menu.style.left = Math.min(e.clientX, window.innerWidth - 180) + "px";
      menu.style.top = Math.min(e.clientY, window.innerHeight - 90) + "px";
      document.body.appendChild(menu);
      menu.querySelector('[data-act="select"]').onclick = (ev) => {
        ev.stopPropagation();
        hideCtxMenu();
        enterSelMode();
        toggleRound(roundStartOf(idx));
      };
      menu.querySelector('[data-act="delete"]').onclick = async (ev) => {
        ev.stopPropagation();
        hideCtxMenu();
        const rs = roundStartOf(idx);
        if (!(await confirmDialog({ title: "删除该轮对话", message: "将删除该轮对话及其所有工具调用记录，AI 上下文会同步回退。", danger: true, okText: "删除" }))) return;
        try {
          const d = await api(`/agent/sessions/${curSid}/messages/${idx}`, { method: "DELETE" });
          toast("已删除");
          renderMsgs(d.display);
        } catch (err) { toast(err.message, "error"); }
      };
    };
  };

  const enterSelMode = () => {
    selMode = true;
    selRounds.clear();
    box.classList.add("sel-mode");
    showSelBar();
    toast("多选模式：点击消息选中/取消整轮对话", "info");
  };
  const exitSelMode = () => {
    selMode = false;
    selRounds.clear();
    box.classList.remove("sel-mode");
    box.querySelectorAll(".msg, .msg-tool").forEach((el) => el.classList.remove("sel"));
    $("#sel-bar")?.remove();
  };

  const toggleRound = (start) => {
    if (selRounds.has(start)) selRounds.delete(start);
    else selRounds.add(start);
    const [s, e] = roundRange(start);
    box.querySelectorAll(".msg, .msg-tool").forEach((el) => {
      const idx = Number(el.dataset.idx);
      if (!Number.isNaN(idx) && idx >= s && idx <= e) el.classList.toggle("sel", selRounds.has(start));
    });
    updateSelBar();
  };

  const roundRange = (start) => {
    let e = start;
    while (e + 1 < curDisplay.length && curDisplay[e + 1]?.role !== "user") e++;
    return [start, e];
  };

  const showSelBar = () => {
    $("#sel-bar")?.remove();
    const bar = document.createElement("div");
    bar.id = "sel-bar";
    bar.innerHTML = `
      <span id="sel-count">已选 0 轮</span>
      <button class="btn btn-sm" id="sel-cancel">取消</button>
      <button class="btn btn-sm btn-danger" id="sel-delete">删除所选</button>`;
    document.querySelector(".chat-wrap").appendChild(bar);
    $("#sel-cancel").onclick = exitSelMode;
    $("#sel-delete").onclick = async () => {
      if (!selRounds.size) return toast("请先选中要删除的对话", "warning");
      if (!(await confirmDialog({ title: "删除所选对话", message: `将删除选中的 ${selRounds.size} 轮对话，AI 上下文会同步回退。`, danger: true, okText: "删除" }))) return;
      try {
        const d = await api(`/agent/sessions/${curSid}/messages/delete-rounds`, {
          method: "POST",
          body: { round_starts: [...selRounds] },
        });
        toast("已删除");
        exitSelMode();
        renderMsgs(d.display);
      } catch (e) { toast(e.message, "error"); }
    };
  };
  const updateSelBar = () => {
    const el = $("#sel-count");
    if (el) el.textContent = `已选 ${selRounds.size} 轮`;
  };

  const renderMsgs = (display) => {
    exitSelMode();
    curDisplay = display || [];
    toolGroup = null;
    box.innerHTML = WELCOME;
    (display || []).forEach((m, i) => {
      if (m.role === "tool") {
        const [head, ...rest] = m.content.split("\n");
        // 连续 tool 条目自然并入同一折叠组（appendMsg 对非 tool 消息会 closeToolGroup）
        appendTool(head.replace(/^⚒\s*/, ""), rest.join("\n"), i);
      } else if (m.role === "summary") {
        appendMsg("summary", m.content);
      } else if (m.role === "step") {
        appendMsg("step", m.content);
      } else if (m.role === "error") {
        appendMsg("assistant", `⚠ ${m.content}`, i);
      } else {
        appendMsg(m.role, m.content, i);
      }
    });
    resetFollow(); // 切会话/重渲染：默认定位到最新消息
  };

  // ── 会话列表 ──
  const renderSessList = (sessions) => {
    const list = $("#sess-list");
    if (!list) return; // 页面已切走（WS 事件仍会触发刷新，摸 null 会报错）
    sessMeta = {};
    if (!sessions.length) {
      list.innerHTML = `<div class="muted" style="padding:8px">暂无会话</div>`;
      return;
    }
    list.innerHTML = sessions.map((s) => {
      sessMeta[s.id] = s;
      return `
      <div class="sess-item ${s.current ? "active" : ""}" data-sid="${s.id}">
        <div class="sess-info">
          <div class="sess-title">${esc(s.title)}</div>
          <div class="sess-sub muted">
            <span class="tok-badge" title="本会话累计 token 消耗（百万为单位）">${Number(s.tokens_m || 0).toFixed(2)}M</span>
          </div>
        </div>
        <div class="sess-ops">
          <button class="icon-btn" data-rename="${s.id}" title="重命名">✎</button>
          <button class="icon-btn" data-del="${s.id}" title="删除">✕</button>
        </div>
      </div>`;
    }).join("");
    // 切换会话（任务运行中：只允许查看其它会话，不切换后端 current_sid，
    // 防止把下一条消息发进正在跑的任务会话之外）
    list.querySelectorAll(".sess-item").forEach((el) => {
      el.onclick = async (e) => {
        if (e.target.closest("[data-rename],[data-del]")) return;
        const sid = el.dataset.sid;
        try {
          if (!appState.agent_running) {
            await api(`/agent/sessions/${sid}/switch`, { method: "POST" });
          }
          await loadSession(sid);
          renderSessList((await api("/agent/sessions")).sessions);
        } catch (err) { toast(err.message, "error"); }
      };
    });
    // 重命名
    list.querySelectorAll("[data-rename]").forEach((el) => {
      el.onclick = () => {
        const sid = el.dataset.rename;
        $("#sess-f-title").value = sessMeta[sid]?.title || "";
        $("#sess-modal").dataset.sid = sid;
        $("#sess-modal").style.display = "flex";
        $("#sess-f-title").focus();
      };
    });
    // 删除会话（正在跑任务的那个会话后端会拒绝，其余随时可删）
    list.querySelectorAll("[data-del]").forEach((el) => {
      el.onclick = async () => {
        const sid = el.dataset.del;
        const s = (appState.sessions || []).find((x) => x.id === sid);
        if (!(await confirmDialog({ title: "删除会话", message: `确认删除会话「${s?.title || "未命名"}」？对话记录将删除，已生成的报告仍保留在报告页。`, danger: true, okText: "删除" }))) return;
        try {
          const d = await api(`/agent/sessions/${sid}`, { method: "DELETE" });
          toast("会话已删除");
          await loadSession(d.current);
          renderSessList(d.sessions);
        } catch (err) { toast(err.message, "error"); }
      };
    });
  };

  const loadSessList = async () => {
    try { renderSessList((await api("/agent/sessions")).sessions); }
    catch (e) { toast(e.message, "error"); }
  };

  const loadSession = async (sid) => {
    curSid = sid;
    try {
      const d = await api(`/agent/sessions/${sid}`);
      renderMsgs(d.display);
    } catch (e) {
      box.innerHTML = WELCOME;
    }
    // 按钮态跟随当前会话（该会话在跑→「停止」，否则→「发送」）
    setSendBtnRunning(isCurRunning());
    // 该会话正在执行任务：渲染完历史消息后挂上「思考中」提示
    if (isCurRunning()) showThinking();
    else removeThinking();
  };

  // ── 新建 / 重命名 ──
  $("#sess-add").onclick = async () => {
    // 任务运行中允许新建空会话查看；新会话发消息会被后端「已有任务在运行」拦住
    try {
      const d = await api("/agent/sessions", { method: "POST", body: {} });
      toast("已创建新会话");
      curSid = d.sid;
      renderSessList(d.sessions);
      box.innerHTML = WELCOME;
      resetFollow();
    } catch (e) { toast(e.message, "error"); }
  };
  $("#sess-cancel").onclick = () => { $("#sess-modal").style.display = "none"; };
  $("#sess-modal").onclick = (e) => { if (e.target.id === "sess-modal") $("#sess-modal").style.display = "none"; };
  $("#sess-save").onclick = async () => {
    const sid = $("#sess-modal").dataset.sid;
    const title = $("#sess-f-title").value.trim();
    if (!title) return toast("请输入名称", "warning");
    try {
      const d = await api(`/agent/sessions/${sid}/rename`, { method: "POST", body: { title } });
      $("#sess-modal").style.display = "none";
      renderSessList(d.sessions);
    } catch (e) { toast(e.message, "error"); }
  };

  // ── 模型选择器 ──
  const loadModelOptions = async () => {
    const sel = $("#agent-model");
    if (!sel) return;
    try {
      const models = (await api("/ai/models")).models;
      if (!models.length) {
        sel.innerHTML = `<option value="">暂无模型，请到「模型列表」添加</option>`;
        return;
      }
      sel.innerHTML = models.map((m) => {
        const label = m.provider === "anthropic" ? "Anthropic" : m.provider === "ollama" ? "Ollama" : "OpenAI";
        return `<option value="${m.provider}::${m.model}">${esc(m.label || m.model)}（${label}）</option>`;
      }).join("");
      // 恢复上次选中的模型：切页会销毁重建 DOM，选择必须持久化，否则
      // 回到会话页就回落到列表第一项（实测：选 grok-4.7 切页后变回 glm-5.3-flash）
      const saved = localStorage.getItem("minihunt_model");
      if (saved && models.some((m) => `${m.provider}::${m.model}` === saved)) {
        sel.value = saved;
      } else if (saved) {
        localStorage.removeItem("minihunt_model"); // 上次选的模型已被移除，清掉
      }
      // 选中变化时持久化（beautifySelect 自定义面板选中时会派发 change 事件）；
      // 绑定守卫：同一次会话内重复调用只绑一次
      if (!sel.dataset.modelBound) {
        sel.dataset.modelBound = "1";
        sel.addEventListener("change", () => {
          if (sel.value) localStorage.setItem("minihunt_model", sel.value);
        });
      }
    } catch (e) {}
  };
  loadModelOptions();

  const setSendBtnRunning = (running) => {
    const sendBtn = $("#agent-send");
    if (!sendBtn) return;
    sendBtn.disabled = false;
    // 按钮只反映「当前查看的会话」是否在跑任务；其他会话在跑时这里仍是「发送」
    sendBtn.textContent = running ? "停止" : "发送";
    sendBtn.classList.toggle("btn-danger", running);
    sendBtn.classList.toggle("btn-primary", !running);
  };

  const stopAgent = async () => {
    try {
      await api("/agent/stop", { method: "POST" });
      toast("已请求停止，等待当前工具执行完...", "info");
    } catch (e) { toast(e.message, "error"); }
  };

  const send = async () => {
    const input = $("#agent-input");
    if (isCurRunning()) return stopAgent();
    if (appState.agent_running) return toast("已有任务在其他会话运行中，请先等待完成或停止", "warning");
    const msg = input.value.trim();
    if (!msg) return;
    input.value = "";
    // 不在此处本地回显：后端 run_task 会通过 WS agent_message 推送用户消息（唯一事实源），
    // 本地再画一条会导致同一消息出现两个气泡
    showThinking(); // 等待首个响应期间显示思考中动画，避免用户以为卡死
    const modelVal = ($("#agent-model")?.value || "");
    const [mProvider, mModel] = modelVal ? modelVal.split("::") : ["", ""];
    // 执行模式由后端根据消息内容自动判断，前端不再传递
    try {
      const d = await api("/agent/task", { method: "POST", body: { message: msg, provider: mProvider, model: mModel } });
      if (d.sid) curSid = d.sid; // 回填会话 id（含自动创建场景）
      if (d.ok) {
        loadSessList();
        if (curSid) await loadSession(curSid); // 拉取最终消息渲染（含任务摘要）
      } else {
        if (d.error) appendMsg("assistant", `❌ 任务失败: ${d.error}`);
        loadSessList();
        removeThinking(); // 任务未进入执行循环，摘掉指示器
      }
    } catch (e) {
      appendMsg("assistant", `❌ ${e.message}`);
      removeThinking(); // 请求本身失败（未进入任务循环）才摘指示器；任务已在后台跑则由 agent_status 收尾
    }
    // 按钮态不在此处复位：由 agent_status 事件按「任务会话 == 当前会话」统一驱动
  };
  $("#agent-send").onclick = send;
  $("#agent-input").onkeydown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  };

  // ── 实时事件流（仅显示当前查看的会话）──
  // 运行中严格按 sid 过滤（d.sid 必须等于 curSid 才显示）；
  // 空会话（首条消息自动建会话）时跟随后端事件流并回填 curSid
  const forCurSid = (d) => !curSid || !d.sid || d.sid === curSid;
  onWsEvent("agent_message", (d) => {
    if (!forCurSid(d)) return;
    removeThinking(); // 先摘掉旧的，新消息渲染后重新挂到底部
    if (d.sid && !curSid) curSid = d.sid; // 首条消息自动创建的会话，回填 curSid
    appendMsg(d.role, d.content);
    loadSessList(); // 刷新左侧列表（消息数/标题/时间）
    if (d.role !== "summary") showThinking(); // 任务仍在进行，继续给「思考中」提示
  });
  onWsEvent("agent_tool", (d) => {
    if (!forCurSid(d)) return;
    removeThinking();
    appendTool(d.name, "执行中...");
  });
  onWsEvent("agent_tool_result", (d) => { if (forCurSid(d)) { appendTool(d.name, d.result); showThinking(); } });
  onWsEvent("agent_error", (d) => { if (forCurSid(d)) { removeThinking(); closeToolGroup(); appendMsg("assistant", `⚠ ${d.error}`); } });
  // 发现漏洞不再在会话流插分隔条提醒（用户要求删除）：漏洞详情统一在渗透报告查看，
  // 后端 finding 事件保留广播但前端不渲染
  onWsEvent("agent_step", (d) => { if (forCurSid(d)) { removeThinking(); appendMsg("step", d.step); showThinking(); } });
  onWsEvent("session_cleared", (d) => { if (d.sid === curSid) { box.innerHTML = WELCOME; resetFollow(); } });
  onWsEvent("session_truncated", (d) => {
    if (d.sid === curSid && curSid) loadSession(curSid); // 其他标签页删除时同步
  });
  // 后端自动改名会话（信息搜集到手）时刷新左侧列表
  onWsEvent("sessions_changed", () => { if (curSid) loadSessList(); });
  onWsEvent("agent_status", (d) => {
    appState.agent_running = !!d.running;
    if (d.running) {
      runningSid = d.sid || curSid;
    } else if (runningSid && d.sid && runningSid !== d.sid) {
      // 结束的不是当前记录的任务会话（理论上不会发生），保持 runningSid 不变
    } else {
      runningSid = null;
    }
    // 按钮态按「任务会话是否是当前查看的会话」：别的会话在跑，当前会话按钮仍是「发送」
    setSendBtnRunning(isCurRunning());
    if (runningSid === curSid) {
      if (d.running) showThinking(); // 任务开始即给提示
      else removeThinking(); // 任务收尾：摘掉「思考中」
    }
    if (d.sid && !curSid) curSid = d.sid;
  });
  onWsEvent("report", (d) => {
    const r = d.data;
    const summary = Object.entries(r.summary || {}).filter(([k, v]) => v)
      .map(([k, v]) => `${k}: ${v}`).join(" · ");
    appendMsg("assistant", `📋 报告已生成: ${r.title}\n共 ${r.total_findings} 个发现 (${summary})\n前往「渗透报告」页面查看详情。`);
  });

  // 初始化：加载会话列表 + 当前会话（无会话则显示欢迎框，等待首次对话创建）
  box.innerHTML = WELCOME;
  (async () => {
    try {
      const sessions = (await api("/agent/sessions")).sessions;
      renderSessList(sessions);
      const cur = sessions.find((s) => s.current);
      if (cur) await loadSession(cur.id);
    } catch (e) {}
    // 页面刷新后恢复运行状态（任务可能在后台执行中；后端返回任务所属会话）
    try {
      const st = await api("/status");
      appState.agent_running = !!st.agent_running;
      runningSid = st.agent_running ? (st.agent_running_sid || curSid) : null;
      setSendBtnRunning(isCurRunning());
      if (isCurRunning()) showThinking(); // 当前会话在跑：恢复「思考中」指示
    } catch (e) {}
  })();
});

// ══════════════════════════════
//  页面: Skill 列表
// ══════════════════════════════
registerPage("skills", "Skill 列表", "◈", (c) => {
  c.innerHTML = `
    <div class="card">
      <div class="card-title">渗透测试 Skill
        <div class="row">
          <input type="file" id="skill-file" accept=".json,.txt,.md,.markdown" style="display:none">
          <button class="btn btn-sm" id="skill-import">⇪ 导入文件</button>
          <button class="btn btn-sm btn-primary" id="skill-add">+ 添加 Skill</button>
        </div>
      </div>
      <div id="skill-list"></div>
    </div>
    <div class="modal-mask" id="skill-modal" style="display:none">
      <div class="modal">
        <div class="card-title" id="skill-modal-title">添加 Skill</div>
        <div class="form-grid" style="margin-top:12px">
          <label>名称 *</label>
          <input type="text" id="skill-f-name" placeholder="如：登录接口爆破">
          <label>描述</label>
          <input type="text" id="skill-f-desc" placeholder="一句话说明该 Skill 的用途">
          <label>指令 Prompt *</label>
          <textarea id="skill-f-prompt" rows="7" placeholder="写给 Agent 的详细执行指令，如：在信息收集完成后，对登录接口进行弱口令测试..."></textarea>
        </div>
        <label class="checkbox" style="margin-top:10px">
          <input type="checkbox" id="skill-f-enabled"> 添加后立即启用
        </label>
        <div class="row" style="margin-top:14px;justify-content:flex-end">
          <button class="btn" id="skill-cancel">取消</button>
          <button class="btn btn-primary" id="skill-save">保存</button>
        </div>
      </div>
    </div>
  `;
  let editingIndex = -1; // -1 = 新增

  const renderList = async () => {
    let skills = [];
    try { skills = (await api("/skills")).skills; } catch (e) { $("#skill-list").textContent = e.message; return; }
    const box = $("#skill-list");
    if (!skills.length) {
      box.innerHTML = `<div class="muted">暂无 Skill — 点击右上角「+ 添加 Skill」创建</div>`;
      return;
    }
    box.innerHTML = skills.map((s, i) => `
      <div class="skill-item">
        <div class="skill-info">
          <div class="skill-head">
            <b>${esc(s.name)}</b>
            <span class="badge ${s.enabled ? "badge-low" : "badge-info"}">${s.enabled ? "已启用" : "已关闭"}</span>
          </div>
          ${s.description ? `<div class="muted">${esc(s.description)}</div>` : ""}
        </div>
        <div class="row">
          <label class="switch" title="${s.enabled ? "关闭" : "启用"}">
            <input type="checkbox" data-toggle="${i}" ${s.enabled ? "checked" : ""}>
            <span class="slider"></span>
          </label>
          <button class="btn btn-sm" data-edit="${i}">编辑</button>
          <button class="btn btn-sm btn-danger" data-del="${i}">删除</button>
        </div>
      </div>
    `).join("");

    box.querySelectorAll("[data-toggle]").forEach((el) => {
      el.onchange = async () => {
        try {
          const r = await api(`/skills/${el.dataset.toggle}/toggle`, { method: "POST" });
          // 用服务端返回的真实状态刷新徽章与开关，避免前后端状态不一致
          const idx = Number(el.dataset.toggle);
          if (skills[idx]) skills[idx].enabled = r.enabled;
          const badge = el.closest(".skill-item")?.querySelector(".badge");
          if (badge) {
            badge.className = `badge ${r.enabled ? "badge-low" : "badge-info"}`;
            badge.textContent = r.enabled ? "已启用" : "已关闭";
          }
      el.checked = r.enabled;
          toast(r.enabled ? "Skill 已启用 — 下次任务生效" : "Skill 已关闭");
        } catch (e) { toast(e.message, "error"); el.checked = !el.checked; }
      };
    });
    box.querySelectorAll("[data-edit]").forEach((el) => {
      el.onclick = () => openModal(skills[el.dataset.edit], Number(el.dataset.edit));
    });
    box.querySelectorAll("[data-del]").forEach((el) => {
      el.onclick = async () => {
        const s = skills[el.dataset.del];
        if (!(await confirmDialog({ title: "删除 Skill", message: `确认删除 Skill「${s?.name || "未命名"}」？删除后不可恢复。`, danger: true, okText: "删除" }))) return;
        try {
          await api(`/skills/${el.dataset.del}`, { method: "DELETE" });
          toast("已删除");
          renderList();
        } catch (e) { toast(e.message, "error"); }
      };
    });
  };

  const openModal = (skill = null, index = -1) => {
    editingIndex = index;
    $("#skill-modal-title").textContent = index >= 0 ? "编辑 Skill" : "添加 Skill";
    $("#skill-f-name").value = skill?.name || "";
    $("#skill-f-desc").value = skill?.description || "";
    $("#skill-f-prompt").value = skill?.prompt || "";
    $("#skill-f-enabled").checked = skill?.enabled || false;
    $("#skill-modal").style.display = "flex";
    $("#skill-f-name").focus();
  };
  const closeModal = () => { $("#skill-modal").style.display = "none"; };

  $("#skill-add").onclick = () => openModal();
  $("#skill-cancel").onclick = closeModal;
  // 文件导入
  $("#skill-import").onclick = () => $("#skill-file").click();
  $("#skill-file").onchange = async () => {
    const f = $("#skill-file").files[0];
    if (!f) return;
    $("#skill-file").value = "";
    const fd = new FormData();
    fd.append("file", f);
    try {
      const resp = await fetch("/api/skills/upload", { method: "POST", body: fd });
      const d = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(d.detail || `HTTP ${resp.status}`);
      const names = (d.imported || []).join("、");
      toast(`导入成功: ${names}${d.skipped?.length ? `（跳过: ${d.skipped.join("、")}）` : ""}`, "success");
      renderList();
    } catch (e) { toast(`导入失败: ${e.message}`, "error"); }
  };
  $("#skill-modal").onclick = (e) => { if (e.target.id === "skill-modal") closeModal(); };
  $("#skill-save").onclick = async () => {
    const body = {
      name: $("#skill-f-name").value,
      description: $("#skill-f-desc").value,
      prompt: $("#skill-f-prompt").value,
      enabled: $("#skill-f-enabled").checked,
    };
    if (!body.name.trim()) return toast("请填写 Skill 名称", "warning");
    if (!body.prompt.trim()) return toast("请填写指令 Prompt", "warning");
    try {
      if (editingIndex >= 0) {
        await api(`/skills/${editingIndex}`, { method: "PUT", body });
        toast("Skill 已更新");
      } else {
        await api("/skills", { method: "POST", body });
        toast(body.enabled ? "Skill 已添加并启用" : "Skill 已添加");
      }
      closeModal();
      renderList();
    } catch (e) { toast(e.message, "error"); }
  };
  renderList();
});

// ══════════════════════════════
//  页面: 渗透画板（两级视图：会话卡片列表 → 点进详情看思维导图）
// ══════════════════════════════
registerPage("board", "渗透画板", "◍", (c) => {
  c.innerHTML = `
    <div id="bd-list-view">
      <div class="card">
        <div class="card-title">渗透画板
          <button class="btn btn-sm" id="bd-refresh">刷新</button>
        </div>
        <div id="bd-list" class="muted">加载中…</div>
      </div>
    </div>
    <div id="bd-detail-view" style="display:none">
      <div class="card">
        <div class="card-title">
          <div class="row"><button class="btn btn-sm" id="bd-back">← 返回列表</button><span id="bd-detail-title"></span></div>
          <div class="row">
            <span id="bd-count" class="muted"></span>
            <button class="btn btn-sm" id="bd-refresh2">刷新</button>
            <button class="btn btn-sm btn-danger" id="bd-clear">清空</button>
          </div>
        </div>
        <div id="bd-flow" class="bd-flow">加载中...</div>
      </div>
    </div>
  `;
  let curBsid = "";   // 详情页当前会话

  const STATE_COLOR = {
    discovered: "#87867f", testing: "#b7791f", tested: "#5e5d59",
    confirmed: "#b53333", clean: "#61764b", skipped: "#87867f",
  };
  const escT = (s) => esc(String(s ?? ""));

  const showList = () => {
    $("#bd-detail-view").style.display = "none";
    $("#bd-list-view").style.display = "";
    curBsid = "";
  };

  // ── 列表视图：一行一个会话画板，点击进详情 ──
  const loadList = async () => {
    try {
      const d = await api("/board");
      const box = $("#bd-list");
      if (!box) return; // 页面已切走
      if (!d.sessions.length) {
        box.innerHTML = "暂无画板 — 发起测试后自动绘制流程地图";
        return;
      }
      box.innerHTML = d.sessions.map((s) => {
        const n2 = s.counts?.test || 0;
        const nv = s.counts?.vuln || 0;
        return `
          <div class="card bd-item ${s.has_board ? "" : "bd-item-empty"}" data-sid="${s.id}" style="cursor:pointer;margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
              <div style="font-weight:600;font-size:15px">${escT(s.title || "未命名会话")}</div>
              <div class="row" style="white-space:nowrap">
                <span class="badge" style="background:#f7ecdf;color:#9c6b2f">功能点 ${n2}</span>
                <span class="badge" style="background:${nv ? "#f9e3e3;color:#b53333" : "#eef0eb;color:#87867f"}">漏洞 ${nv}</span>
                <button class="icon-btn bd-item-del" data-sid="${s.id}" data-title="${escT(s.title || "")}" title="清空该会话画板">✕</button>
              </div>
            </div>
          </div>`;
      }).join("");
      box.querySelectorAll(".bd-item").forEach((el) => {
        el.onclick = () => { curBsid = el.dataset.sid; load(); };
      });
      box.querySelectorAll(".bd-item-del").forEach((btn) => {
        btn.onclick = async (ev) => {
          ev.stopPropagation();
          if (!(await confirmDialog({ title: "清空画板", message: `确认清空「${btn.dataset.title}」的信息搜集资产记录？功能点测试进展来自登记册不受影响。`, danger: true, okText: "清空" }))) return;
          try { await api(`/board?sid=${btn.dataset.sid}`, { method: "DELETE" }); toast("已清空"); loadList(); }
          catch (e) { toast(e.message, "error"); }
        };
      });
    } catch (e) { $("#bd-list").textContent = e.message; }
  };

  // ── 详情视图：自绘分层攻击图谱（起点→目标→尝试→漏洞/失败）──
  // 四列泳道：每个目标（功能点）纵向展开其测试动作（尝试），动作带判定出口（漏洞/失败/待定）
  // SVG 贝塞尔连线 + HTML 节点卡片；画布支持拖拽平移/滚轮缩放
  // 点击「尝试」节点 → 弹出该动作当时收发的请求/响应包（/board/evidence）

  // 图谱布局常量（四列泳道：起点 / 目标 / 尝试 / 结果，组内纵向展开）
  const BD_LAYOUT = {
    colW: [240, 230, 300, 190],   // 四列宽度：起点 / 目标 / 尝试 / 结果
    gapX: 60,                      // 列间距
    actGap: 16,                    // 动作组内纵向间距
    groupGap: 40,                  // 功能点组间纵向间距
  };

  // 构建图谱数据：把 {origin, test[]} 转为列式节点 + 边
  // 布局分两阶段：本函数只产出节点/边/列宽；y 坐标在 render() 中
  // 用真实 DOM 高度测量后回填（layoutY），标题完整显示不截断
  // 返回 {nodes:[{id,col,x,w,html,cls,dataEv}], edges:[{from,to,cls}], size:{w}}
  const buildGraph = (d) => {
    const L = BD_LAYOUT;
    const test = d.test || [];
    const o = d.origin || {};
    const originTitle = o.name ? `${o.name}渗透测试` : (o.appid ? `小程序 ${o.appid}渗透测试` : (d.root || "渗透测试"));
    const originSub = o.appid ? o.appid : "";

    // 列 x 坐标
    const colX = [];
    let acc = 30;
    for (let i = 0; i < 4; i++) { colX[i] = acc; acc += L.colW[i] + L.gapX; }

    const nodes = [], edges = [];

    nodes.push({
      id: "origin", col: 0, x: colX[0], w: L.colW[0],
      html: `<div class="bdn-title">${escT(originTitle)}</div>${originSub ? `<div class="bdn-sub">${escT(originSub)}</div>` : ""}`,
      cls: "bdn-origin",
    });

    test.forEach((f, fi) => {
      const vLabel = f.verdict === "vuln" ? "漏洞存在" : f.verdict === "safe" ? "无漏洞" : f.verdict === "unknown" && f.state === "skipped" ? "已跳过" : f.state_label || "待测试";
      nodes.push({
        id: `feat${fi}`, col: 1, x: colX[1], w: L.colW[1],
        html: `<div class="bdn-title">${escT(f.name)}</div><div class="bdn-sub"><span class="bdn-dot" style="background:${STATE_COLOR[f.verdict === "vuln" ? "confirmed" : f.verdict === "safe" ? "clean" : f.state] || "#87867f"}"></span>${escT(vLabel)}</div>`,
        cls: `bdn-feat${f.verdict === "vuln" ? " bdn-feat-vuln" : ""}`,
        feat: fi,
      });
      edges.push({ from: "origin", to: `feat${fi}`, cls: f.verdict === "vuln" ? "bd-edge-vuln" : "" });

      // skipped 功能点：做过真实测试动作的（如测了部分项后无法继续）按真实动作渲染，
      // 漏洞/失败判定照常出胶囊——口径必须与后端 vuln_count 一致（逐动作判定计数）；
      // 完全没动作的才用 skip_reason 兜底节点
      const acts = (f.actions || []).length ? f.actions
        : f.state === "skipped" && f.skip_reason
          ? [{ intent: `无法测试：${f.skip_reason}`, verdict: "unknown", has_evidence: false, tidx: -1 }]
          : [{ intent: f.state_label || "待测试", verdict: "unknown", has_evidence: false, tidx: -1 }];
      acts.forEach((a, ai) => {
        const id = `act${fi}_${ai}`;
        // 动作卡片只留标题（判定依据/result 描述不再平铺——用户反馈卡片下方
        // 小字碍眼，全部收进点击弹窗）；全部动作可点击：带证据包看数据包，
        // 无证据包也能看这条动作的判定结论（做了什么/结果如何/为何失败）
        nodes.push({
          id, col: 2, x: colX[2], w: L.colW[2],
          html: `<div class="bdn-title">${escT(a.intent)}</div>` +
            (a.has_evidence ? `<span class="bdn-ev" title="点击查看当时收发的数据包">⛨</span>` : ""),
          cls: "bdn-act",
          dataEv: a.tidx >= 0 ? `t:${f.name}:${a.tidx}` : "",  // 占位动作（skip 无 test_log）不弹窗
          dataRes: a.result || "",
          dataVerdict: a.verdict || "unknown",
          feat: fi,
        });
        edges.push({ from: `feat${fi}`, to: id, cls: "" });
        // 结果出口：与动作同一行（组内最后一个动作 / 已有明确判定 / 带证据包的动作）。
        // 带证据包（⛨）的动作必有标识——有真实发包的测试不该因 unknown 被吞掉标识，
        // 「有包无结论」会让人误以为画板漏渲染（实测现场：收货地址编辑动作带包无胶囊）
        if (ai === acts.length - 1 || a.verdict !== "unknown" || a.has_evidence) {
          // 胶囊文案与语义一一对应（AI 自定性 verdict）：
          // vuln=漏洞（证实漏洞存在）/ fail=失败（动作失败无结论：WAF拦截/未复现等）/
          // safe=无漏洞（证实防御有效——不是「失败」，失败动作有专属 fail 类别）/
          // unknown=待定（历史数据无定性的兜底）
          const vTxt = a.verdict === "vuln" ? "漏洞" : a.verdict === "safe" ? "无漏洞" : a.verdict === "fail" ? "失败" : "待定";
          nodes.push({
            id: `res${fi}_${ai}`, col: 3, x: colX[3], w: L.colW[3],
            html: vTxt, cls: `bdn-res bdn-res-${a.verdict}`,
            feat: fi, refAct: id,
          });
          edges.push({ from: id, to: `res${fi}_${ai}`, cls: a.verdict === "vuln" ? "bd-edge-vuln" : a.verdict === "safe" ? "bd-edge-safe" : "" });
        }
      });
    });

    return { nodes, edges, size: { w: acc + 30 }, groupGap: L.groupGap, actGap: L.actGap };
  };

  // 两阶段布局第二阶段：节点已渲染出真实高度，回填 y 坐标
  // 规则：动作从上往下排；功能点与其动作组垂直居中；组间留 groupGap；结果胶囊与其动作同行
  const layoutY = (g, nodeEls) => {
    const byFeat = {};   // feat 索引 → {acts:[], res:[]}
    g.nodes.forEach((n) => {
      if (n.feat === undefined) return;
      (byFeat[n.feat] ??= { acts: [], res: [] });
      (n.id.startsWith("act") ? byFeat[n.feat].acts : byFeat[n.feat].res).push(n);
    });
    const H = (n) => nodeEls[n.id].offsetHeight;
    const GAP = g.actGap;
    let y = 30;
    Object.keys(byFeat).map(Number).sort((a, b) => a - b).forEach((fi) => {
      const grp = byFeat[fi];
      const featEl = nodeEls[`feat${fi}`];
      const featH = featEl.offsetHeight;
      const actTotal = grp.acts.reduce((s, a) => s + H(a), 0) + GAP * (grp.acts.length - 1);
      const groupH = Math.max(featH, actTotal);
      // 功能点：组内垂直居中
      featEl.style.top = y + (groupH - featH) / 2 + "px";
      // 动作：组内从上往下
      let ay = y + Math.max(0, (groupH - actTotal) / 2);
      grp.acts.forEach((a) => {
        const ah = H(a);
        a.el.style.top = ay + "px";
        // 该动作对应的结果胶囊同行居中
        const res = grp.res.find((r) => r.refAct === a.id);
        if (res) res.el.style.top = ay + (ah - res.el.offsetHeight) / 2 + "px";
        ay += ah + GAP;
      });
      y += groupH + g.groupGap;
    });
    return y + 30; // 总高
  };

  // ── 溯源面板：点击信息搜集叶子 / 测试动作 → 弹窗展示证据详情 ──
  // 信息搜集：数据包来源显示当时收发的报文，反编译文件来源显示文件+行号+行原文，运行时显示原始数据
  // 漏洞测试动作：显示当时测试发送和收到的数据包
  const evPanel = (pid, actNode) => {
    const mask = document.createElement("div");
    mask.className = "ev-mask";
    mask.innerHTML = `
      <div class="ev-panel">
        <div class="ev-head">
          <span class="ev-title">溯源详情</span>
          <button class="icon-btn ev-close">✕</button>
        </div>
        <div class="ev-body"><div class="muted" style="padding:14px;text-align:center">加载中…</div></div>
      </div>`;
    const close = () => mask.remove();
    mask.onclick = (e) => { if (e.target === mask) close(); };
    mask.querySelector(".ev-close").onclick = close;
    document.body.appendChild(mask);
    const body = mask.querySelector(".ev-body");
    const escBlock = (s) => `<pre class="ev-pre">${escT(s ?? "")}</pre>`;
    // 动作节点自带的判定信息（verdict/result）先展示，数据包继续异步加载——
    // 无证据包的动作（fail/safe）点击也能看到「做了什么/结果如何」而非空弹窗
    const vMap = { vuln: "漏洞", safe: "无漏洞", fail: "失败", unknown: "待定" };
    if (actNode) {
      const vv = vMap[actNode.dataset.verdict] || actNode.dataset.verdict || "";
      let pre = "";
      if (vv) pre += `<div class="ev-sub2">判定：<b>${escT(vv)}</b></div>`;
      if (actNode.dataset.res) pre += `<div class="ev-sub2">结果：${escT(actNode.dataset.res)}</div>`;
      if (pre) body.innerHTML = pre;
    }
    api(`/board/evidence?entry_id=${encodeURIComponent(pid)}${curBsid ? `&sid=${curBsid}` : ""}`)
      .then((data) => {
        let html = "";
        const test = data.kind === "test" ? (data.log || {}) : null;
        const ev = data.kind === "recon" ? data.evidence : (test ? { kind: "packet", request: test.evidence?.request, response: test.evidence?.response, meta: test.evidence?.meta } : null);
        if (data.kind === "recon") {
          const e2 = data.entry || {};
          html += `<div class="ev-sub">信息：${escT(e2.title || "")}</div>`;
          if (e2.detail) html += `<div class="ev-sub2">${escT(e2.detail)}</div>`;
        } else if (test) {
          html += `<div class="ev-sub">功能点「${escT(data.feature || "")}」的测试动作</div>`;
          html += `<div class="ev-sub2">做了什么：${escT(test.intent || "")}</div>`;
          html += `<div class="ev-sub2">结果：${escT(test.result || "")}</div>`;
        }
        if (!ev || !ev.kind) {
          html += `<div class="muted" style="padding:10px">这条记录没有留证据快照${data.kind === "recon" ? "（来源：见来源渠道）" : ""}</div>`;
        } else if (ev.kind === "file") {
          html += `<div class="ev-sub">来源：反编译的文件</div>`;
          html += `<div class="ev-meta">${escT(ev.path || "")}${ev.line ? ` 第 ${ev.line} 行` : ""}</div>`;
          if (ev.snippet) html += escBlock(`第 ${ev.line || "?"} 行原文：\n${ev.snippet}`);
        } else if (ev.kind === "packet") {
          // 多包证据：一个测试动作发多包（payload 提交 + 回读验证）逐轮全展示，
          // 每包都是当时实际收发的原文——不再事后按接口匹配猜测
          const rounds = data.kind === "test" && Array.isArray(data.rounds) && data.rounds.length
            ? data.rounds
            : (ev.request || ev.response ? [{ request: ev.request, response: ev.response, meta: ev.meta }] : []);
          html += `<div class="ev-sub">来源：${escT(data.kind === "test" ? "测试动作当时实际收发的数据包" : "响应数据包")}${ev.url ? ` — ${escT(ev.method || "")} ${escT(ev.url)}` : ""}</div>`;
          rounds.forEach((r, i) => {
            const meta = (typeof r.meta === "string" ? { note: r.meta } : r.meta) || {};
            // 每轮的发包描述（方法+路径+关键参数值+响应状态码）：只标「第 N 轮」
            // 用户不知道这轮是干嘛的；desc 缺失时退回 url/method 拼一句
            const rdesc = meta.desc || (meta.method && meta.url ? `${meta.method} ${meta.url}` : "");
            if (rounds.length > 1) html += `<div class="ev-label">第 ${i + 1} 轮${rdesc ? ` · ${escT(rdesc)}` : ""}</div>`;
            else if (rdesc) html += `<div class="ev-label">${escT(rdesc)}</div>`;
            if (r.request) html += `<div class="ev-label">发送的请求</div>${escBlock(r.request)}`;
            if (r.response) html += `<div class="ev-label">收到的响应</div>${escBlock(r.response)}`;
            // note 是给"这批包从哪来"的说明，仅在有描述可读时展示，不再裸甩 JSON
            if (meta.note && typeof meta.note === "string" && meta.note.length < 120) html += `<div class="ev-meta">${escT(meta.note)}</div>`;
          });
        } else if (ev.kind === "runtime") {
          html += `<div class="ev-sub">来源：小程序运行时读取</div>`;
          html += escBlock(ev.raw || "");
        }
        body.innerHTML = html;
      })
      .catch((e2) => { body.innerHTML = `<div class="muted" style="padding:14px">加载失败：${escT(e2.message)}</div>`; });
  };

  const destroyMap = () => {
    const m = $("#bd-map");
    if (m) m.innerHTML = ""; // 自绘图谱无实例需销毁，清空容器即可
  };

  // 点击尝试节点 → 溯源面板（复用证据弹窗，展示当时收发的请求/响应包）。
  // 全部动作可点：带证据包的展示数据包，无证据包的展示判定结论（result 文字）
  const boardEvClick = (ev) => {
    const node = ev.target.closest?.(".bdn-act");
    if (!node || !node.dataset.ev) return;
    if (!node.dataset.res && !node.dataset.ev.startsWith("t:")) return;
    evPanel(node.dataset.ev, node);
  };

  const render = (d) => {
    const title = $("#bd-detail-title"), cnt = $("#bd-count"), flow = $("#bd-flow");
    if (!title || !cnt || !flow) return; // 页面已切走
    title.textContent = d.root || "渗透画板";
    cnt.textContent = `功能点 ${(d.test || []).length}`;
    if (!d.root && !(d.test || []).length) {
      destroyMap();
      flow.innerHTML = `<div class="muted" style="padding:30px;text-align:center">暂无画板 — 发起测试后自动绘制流程地图</div>`;
      return;
    }
    const g = buildGraph(d);
    flow.innerHTML = `
      <div id="bd-map" class="bd-map">
        <div class="bd-toolbar">
          <button class="btn btn-sm" id="bd-zoom-in">＋</button>
          <button class="btn btn-sm" id="bd-zoom-out">－</button>
          <button class="btn btn-sm" id="bd-zoom-reset">复位</button>
          <span class="bd-toolbar-hint">拖拽平移 · 滚轮缩放 · 点击动作节点查看判定与数据包</span>
          ${(function () {
            // 只数「漏洞结果胶囊」（画板节点末尾的漏洞标记），
            // 不把 bdn-feat-vuln 功能点节点算进去——否则 11(=4功能点+7结果) ≠ 红点 7
            const vulnN = g.nodes.filter((n) => n.id.startsWith("res") && n.cls.includes("vuln")).length;
            return vulnN ? `<span class="bd-vuln-legend"><i></i>漏洞 ${vulnN}</span>` : "";
          })()}
        </div>
        <div class="bd-viewport"><div class="bd-canvas"></div></div>
        <div class="bd-mini" title="小地图：点红点跳到漏洞动作">
          <div class="bd-mini-box"><div class="bd-mini-view"></div></div>
        </div>
      </div>`;
    const canvas = flow.querySelector(".bd-canvas");
    const viewport = flow.querySelector(".bd-viewport");

    // ── 节点层：先渲染测真实高度，y 坐标由 layoutY 回填 ──
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("class", "bd-svg");
    const layer = document.createElement("div");
    layer.className = "bd-nodes";
    const nodeEls = {};
    g.nodes.forEach((n) => {
      const el = document.createElement("div");
      el.className = `bdn ${n.cls}`;
      el.style.left = n.x + "px";
      el.style.width = n.w + "px";
      el.innerHTML = n.html;
      if (n.dataEv) el.dataset.ev = n.dataEv;
      if (n.dataRes) el.dataset.res = n.dataRes;
      if (n.dataVerdict) el.dataset.verdict = n.dataVerdict;
      layer.appendChild(el);
      nodeEls[n.id] = el;
      n.el = el;
    });

    // 测高布局：layer 已插入 DOM 后按真实高度排 y，再定总高
    canvas.appendChild(layer);
    const graphH = layoutY(g, nodeEls);
    const graphW = g.size.w;
    // 起点：垂直居中于整个图谱，用满左侧空间
    const originEl = nodeEls.origin;
    originEl.style.top = Math.max(30, (graphH - originEl.offsetHeight) / 2) + "px";
    layer.style.width = graphW + "px";
    layer.style.height = graphH + "px";
    svg.setAttribute("width", graphW);
    svg.setAttribute("height", graphH);

    // SVG 连线层压在节点层下面
    canvas.insertBefore(svg, layer);
    // 真实高度已就位，下一帧画贝塞尔连线（右中 → 左中）
    requestAnimationFrame(() => {
      g.edges.forEach((e) => {
        const a = nodeEls[e.from], b = nodeEls[e.to];
        if (!a || !b) return;
        // viewport 有缩放，用 offset 相对 canvas 计算（offsetLeft/Top 不含缩放）
        const ax = a.offsetLeft + a.offsetWidth, ay = a.offsetTop + a.offsetHeight / 2;
        const bx = b.offsetLeft, by = b.offsetTop + b.offsetHeight / 2;
        const mx = (ax + bx) / 2;
        const path = document.createElementNS(NS, "path");
        path.setAttribute("d", `M ${ax} ${ay} C ${mx} ${ay}, ${mx} ${by}, ${bx} ${by}`);
        path.setAttribute("class", `bd-edge ${e.cls || ""}`);
        svg.appendChild(path);
      });
    });

    // ── 画布平移/缩放 ──
    let scale = 1, tx = 0, ty = 0;
    const apply = () => {
      canvas.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
      canvas.style.transformOrigin = "0 0";
      syncMini();
    };
    const fitWidth = () => {
      // 复位：回到原始尺寸（1:1、画布归位），不做宽度自适应缩小——需要看全貌用鸟瞰图/滚轮缩放
      scale = 1; tx = 0; ty = 0; apply();
    };

    // ── 鸟瞰图：竖长条缩略导航 + 漏洞红点 + 视口矩形，点击跳转 ──
    // 竖向图谱配竖条鸟瞰：高度跟随视口（最高 380px），让红点纵向拉开不挤成一坨
    const mini = flow.querySelector(".bd-mini");
    const miniBox = mini.querySelector(".bd-mini-box");
    const miniView = mini.querySelector(".bd-mini-view");
    const MINI_W = 150;
    const MINI_H = Math.min(380, Math.max(200, Math.round((viewport.clientHeight || 500) * 0.65)));
    // 缩略比例：把整个图谱塞进鸟瞰框
    const mScale = Math.min((MINI_W - 16) / graphW, (MINI_H - 16) / graphH);
    const mW = graphW * mScale, mH = graphH * mScale;
    miniBox.style.width = mW + "px";
    miniBox.style.height = mH + "px";
    mini.style.width = (mW + 16) + "px";
    mini.style.height = (mH + 16) + "px";
    // 红点：只标「尝试」动作节点（从漏洞结果胶囊反查动作，功能点/起点不出点，避免两排）
    // 不按画板坐标映射——漏洞节点在画板上间距不均（功能点行高不同），鸟瞰图里
    // 直接按顺序等间隔排成一列，紧凑连续、阅读性强；点击仍跳回对应动作节点
    const vulnActs = [];
    const nodeById = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
    g.nodes.forEach((n) => {
      if (!n.id.startsWith("res") || !n.cls.includes("vuln")) return;
      // 优先反查动作节点（点击跳到测试动作）；动作被截断查不到时兜底跳到结果胶囊本身，
      // 保证红点数 = 漏洞节点数，不丢点
      const fallback = !nodeById[n.id.replace(/^res/, "act")];
      const target = nodeById[n.id.replace(/^res/, "act")] || n;
      // 兜底节点 html 只有「漏洞」两字，提示改用所属功能点名
      const tipSrc = fallback
        ? ((nodeById[`feat${n.id.match(/^res(\d+)/)?.[1]}`] || {}).html || n.html)
        : target.html;
      vulnActs.push({ node: target, tip: (tipSrc.replace(/<[^>]+>/g, " ").trim() || "存在漏洞").slice(0, 80) });
    });
    const dotGap = Math.min(24, Math.max(10, (mH - 16) / Math.max(vulnActs.length, 1)));
    const dotsTop = Math.max(8, (mH - dotGap * (vulnActs.length - 1)) / 2 - 4);
    vulnActs.forEach(({ node: target, tip }, i) => {
      const dot = document.createElement("div");
      dot.className = "bd-mini-dot";
      dot.style.left = (mW / 2) + "px"; // 水平居中一列
      dot.style.top = (dotsTop + i * dotGap) + "px"; // 等间隔连续一排
      dot.title = tip;
      dot.onclick = (e) => {
        e.stopPropagation();
        jumpTo(target.id);
      };
      miniBox.appendChild(dot);
    });
    // 点击缩略图空白处也跳到对应位置
    miniBox.addEventListener("click", (e) => {
      const r = miniBox.getBoundingClientRect();
      const wx = (e.clientX - r.left) / mScale, wy = (e.clientY - r.top) / mScale;
      centerOn(wx, wy);
    });
    const syncMini = () => {
      // 视口在画布坐标下的可视矩形 → 映射到小地图
      const vw = viewport.clientWidth || 1, vh = viewport.clientHeight || 1;
      const vx = -tx / scale, vy = -ty / scale;
      miniView.style.left = vx * mScale + "px";
      miniView.style.top = vy * mScale + "px";
      miniView.style.width = (vw / scale) * mScale + "px";
      miniView.style.height = (vh / scale) * mScale + "px";
    };
    const centerOn = (wx, wy) => {
      // 平移画布，使画布坐标 (wx, wy) 居中于视口
      const vw = viewport.clientWidth || 800, vh = viewport.clientHeight || 500;
      tx = vw / 2 - wx * scale;
      ty = vh / 2 - wy * scale;
      apply();
    };
    // 跳转到节点并高亮闪烁
    const jumpTo = (id) => {
      const el = nodeEls[id];
      if (!el) return;
      centerOn(el.offsetLeft + el.offsetWidth / 2, el.offsetTop + el.offsetHeight / 2);
      document.querySelectorAll(".bdn.bdn-flash").forEach((x) => x.classList.remove("bdn-flash"));
      el.classList.add("bdn-flash");
      setTimeout(() => el.classList.remove("bdn-flash"), 1800);
    };

    fitWidth();
    let drag = null;
    viewport.addEventListener("mousedown", (e) => {
      if (e.target.closest(".bdn")) return; // 节点上不启动拖拽（保留点击）
      drag = { x: e.clientX, y: e.clientY, tx, ty };
    });
    window.addEventListener("mousemove", (e) => {
      if (!drag) return;
      tx = drag.tx + (e.clientX - drag.x);
      ty = drag.ty + (e.clientY - drag.y);
      apply();
    });
    window.addEventListener("mouseup", () => { drag = null; });
    viewport.addEventListener("wheel", (e) => {
      e.preventDefault();
      const rect = viewport.getBoundingClientRect();
      const cx = e.clientX - rect.left, cy = e.clientY - rect.top;
      const ns = Math.min(2, Math.max(0.2, scale * (e.deltaY < 0 ? 1.12 : 0.89)));
      tx = cx - (cx - tx) * (ns / scale);
      ty = cy - (cy - ty) * (ns / scale);
      scale = ns; apply();
    }, { passive: false });
    flow.querySelector("#bd-zoom-in").onclick = () => { scale = Math.min(2, scale * 1.2); apply(); };
    flow.querySelector("#bd-zoom-out").onclick = () => { scale = Math.max(0.2, scale * 0.83); apply(); };
    flow.querySelector("#bd-zoom-reset").onclick = fitWidth;
    window.addEventListener("resize", syncMini);

    // 尝试节点点击溯源
    canvas.addEventListener("click", boardEvClick);
  };

  const load = async () => {
    try {
      const d = await api(`/board${curBsid ? `?sid=${curBsid}` : ""}`);
      if (!$("#bd-detail-view")) return; // 页面已切走
      $("#bd-list-view").style.display = "none";
      $("#bd-detail-view").style.display = "";
      render(d);
    } catch (e) { const f = $("#bd-flow"); if (f) f.textContent = e.message; }
  };

  $("#bd-back").onclick = () => { showList(); loadList(); };
  $("#bd-refresh").onclick = loadList;
  $("#bd-refresh2").onclick = load;
  $("#bd-clear").onclick = async () => {
    if (!(await confirmDialog({ title: "清空画板", message: "确认清空该会话的信息搜集资产记录？功能点测试进展来自登记册不受影响。", danger: true, okText: "清空" }))) return;
    try { await api(`/board${curBsid ? `?sid=${curBsid}` : ""}`, { method: "DELETE" }); toast("已清空"); load(); }
    catch (e) { toast(e.message, "error"); }
  };
  // 测试进行中实时刷新详情（仅当画板页挂载且处于详情视图时才刷，防止摸空元素）
  const bdAlive = () => PAGES.board && $("#bd-detail-view") && $("#bd-detail-view").style.display !== "none";
  onWsEvent("board_add", () => { if (bdAlive()) load(); });
  onWsEvent("board_remove", () => { if (bdAlive()) load(); });
  onWsEvent("board_clear", () => { if (bdAlive()) load(); });
  // 测试分支数据来自登记册，registry 变化也要刷新
  onWsEvent("registry_add", () => { if (bdAlive()) load(); });
  onWsEvent("registry_update", () => { if (bdAlive()) load(); });
  loadList();
});

// ══════════════════════════════
//  页面: 渗透报告
// ══════════════════════════════
registerPage("report", "渗透报告", "▤", (c) => {
  c.innerHTML = `
    <div id="rp-list-view">
      <div class="card">
        <div class="card-title">渗透测试报告
          <button class="btn btn-sm" id="rp-refresh">刷新</button>
        </div>
        <div id="rp-list" class="muted">加载中…</div>
      </div>
    </div>
    <div id="rp-detail-view" style="display:none">
      <div class="card">
        <div class="card-title">
          <div class="row"><button class="btn btn-sm" id="rp-back">← 返回列表</button><span id="rp-detail-title"></span></div>
          <div class="row">
            <button class="btn btn-sm" id="rp-md">导出 Markdown</button>
            <button class="btn btn-sm" id="rp-json">导出 JSON</button>
          </div>
        </div>
        <div id="rp-body"></div>
      </div>
    </div>
  `;
  const SEV_CN = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
  let curSid = "";   // 详情页当前会话
  const showList = () => {
    $("#rp-detail-view").style.display = "none";
    $("#rp-list-view").style.display = "";
    curSid = "";
  };
  // ── 列表视图：一行一个会话报告，点击进详情 ──
  const loadList = async () => {
    try {
      const d = await api("/reports");
      const box = $("#rp-list");
      if (!box) return; // 页面已切走
      if (!d.reports.length) {
        box.innerHTML = "暂无报告 — 运行 AI 自动化渗透后自动生成";
        return;
      }
      box.innerHTML = d.reports.map((r) => {
        const badges = Object.entries(r.summary || {}).filter(([k, v]) => v)
          .map(([k, v]) => `<span class="badge badge-${k}">${SEV_CN[k] || k} ${v}</span>`).join(" ");
        return `
          <div class="card rp-item" data-sid="${r.sid}" style="cursor:pointer;margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
              <div style="font-weight:600;font-size:15px">${esc(r.report_title || r.title)}</div>
              <div class="row" style="white-space:nowrap">
                <span class="muted" style="font-size:12px">${esc(r.generated_at)}</span>
                <button class="icon-btn rp-del" data-sid="${r.sid}" data-title="${esc(r.report_title || r.title)}" title="删除报告">✕</button>
              </div>
            </div>
            <div class="row" style="margin:8px 0 0">
              ${r.session_exists === false ? `<span class="badge badge-medium">会话已删除</span>` : ""}
              <span class="badge">共 ${r.total_findings} 个发现</span>
              ${badges}
            </div>
          </div>`;
      }).join("");
      box.querySelectorAll(".rp-item").forEach((el) => {
        el.onclick = (ev) => {
          if (ev.target.closest(".rp-del")) return;   // 点删除按钮不进详情
          openDetail(el.dataset.sid);
        };
      });
      box.querySelectorAll(".rp-del").forEach((el) => {
        el.onclick = async (ev) => {
          ev.stopPropagation();
          const sid = el.dataset.sid;
          if (!(await confirmDialog({ title: "删除报告", message: `确认删除报告「${el.dataset.title}」？删除后不可恢复。`, danger: true, okText: "删除" }))) return;
          try {
            await api(`/report/session/${sid}`, { method: "DELETE" });
            toast("报告已删除");
            loadList();
          } catch (e) { toast(e.message, "error"); }
        };
      });
    } catch (e) { $("#rp-list").textContent = e.message; }
  };
  // ── 详情视图 ──
  const openDetail = async (sid) => {
    try {
      curSid = sid;
      const d = await api(`/report/session/${sid}`);
      const r = d.report;
      const sevBadge = (s) => `<span class="badge badge-${s}">${SEV_CN[s] || s}</span>`;
      // 数据包折叠块：一组 = 该接口一轮请求+响应（标题只写「请求包/响应包」，
      // 用户反馈长参数串太啰嗦——接口身份在复现步骤文字里已写明）
      const packetBlock = (g, gi, n) => {
        const r = g && g.round ? g.round : g;
        if (!r || typeof r !== "object") return "";
        let h = "";
        if (r.tampered) h += `
          <details style="margin:6px 0">
            <summary style="cursor:pointer;font-weight:600">请求包 <span class="muted" style="font-weight:400">— 实施攻击发出的请求报文</span></summary>
            <pre class="code" style="margin:6px 0 0;max-height:340px;overflow:auto">${esc(String(r.tampered).slice(0, 6000))}</pre>
          </details>`;
        if (r.response) h += `
          <details style="margin:6px 0">
            <summary style="cursor:pointer;font-weight:600">响应包 <span class="muted" style="font-weight:400">— 请求包对应的服务端响应（漏洞证据）</span></summary>
            <pre class="code" style="margin:6px 0 0;max-height:340px;overflow:auto">${esc(String(r.response).slice(0, 6000))}</pre>
          </details>`;
        return h;
      };
      // 静态证据列表（反编译敏感信息类漏洞）：文件路径 + 敏感内容 + 行号，
      // 证据不叠框不折叠，一眼看清「什么东西在哪个文件里」
      const staticEvHtml = (f) => {
        const ev = Array.isArray(f.evidence) ? f.evidence : [];
        if (!ev.length) return "";
        return `<div style="margin:8px 0 0"><b>敏感信息位置</b> <span class="muted">（反编译包内文件）</span></div>
          <table class="tbl" style="margin:6px 0 0;width:100%">
            <thead><tr><th style="width:38%">所在文件</th><th>敏感内容</th></tr></thead>
            <tbody>${ev.map((e) => `
              <tr>
                <td style="word-break:break-all">${esc(e.path || e.file || "-")}${e.line ? `<span class="muted"> :${e.line}</span>` : ""}</td>
                <td style="word-break:break-all"><code style="font-size:12px">${esc(String(e.content || "").slice(0, 400))}</code></td>
              </tr>`).join("")}</tbody>
          </table>`;
      };
      // 漏洞复现：一步描述紧跟该步对应接口的请求/响应包（无包步骤纯文字，不硬凑）
      const reproHtml = (f) => {
        const steps = Array.isArray(f.repro_steps) ? f.repro_steps : null;
        if (!steps || !steps.length) {
          // 旧结构兜底：整段文字 + 数据包平铺在后
          const pk = f.packets;
          let groups = pk && Array.isArray(pk.groups) ? pk.groups
            : pk && Array.isArray(pk.rounds) ? pk.rounds.map((r) => ({ api: "", round: r }))
            : (pk && (pk.tampered || pk.response)) ? [pk] : [];
          return `<div style="margin:4px 0;white-space:pre-wrap">${esc(f.reproduction) || "-"}</div>${groups.map((g, i) => packetBlock(g, i + 1, groups.length)).join("")}`;
        }
        return steps.map((s) => `
          <div style="margin:6px 0;white-space:pre-wrap">${esc(s.text)}</div>
          ${(s.packets || []).map((g, i) => packetBlock(g, i + 1, s.packets.length)).join("")}
        `).join("");
      };
      $("#rp-body").innerHTML = `
        <h2 style="margin-bottom:8px">${esc(r.title)}</h2>
        <div class="muted">目标: ${esc(r.app_info?.name || "")} (${esc(r.app_info?.appid || "")}) · ${esc(r.generated_at)}</div>
        <div class="row" style="margin:14px 0">
          ${Object.entries(r.summary).filter(([k, v]) => v).map(([k, v]) => `${sevBadge(k)} <b>${v}</b>`).join("")}
          <span class="muted">共 ${r.total_findings} 个发现</span>
        </div>
        ${(r.findings || []).map((f, i) => `
          <div class="card" style="border-left:3px solid var(--${f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "border2"})">
            <div style="font-weight:600">${sevBadge(f.severity)} ${i + 1}. ${esc(f.title)}</div>
            <div style="margin:10px 0 0"><b>漏洞描述</b></div>
            <div style="margin:4px 0">${esc(f.description) || "-"}</div>
            <div style="margin:10px 0 0"><b>${f.evidence_only ? "证据定位" : "漏洞复现"}</b> <span class="muted">（${f.evidence_only ? "反编译包内文件" : "步骤 + 真实数据包支撑"}）</span></div>
            ${f.evidence_only && !(f.reproduction || f.repro_steps?.length) ? "" : reproHtml(f)}
            ${staticEvHtml(f)}
            <div style="margin:10px 0 0"><b>漏洞危害</b></div>
            <div style="margin:4px 0">${esc(f.impact) || "-"}</div>
            <div style="margin:10px 0 0"><b>修复建议</b></div>
            <div style="margin:4px 0">${esc(f.recommendation) || "-"}</div>
          </div>`).join("")}
      `;
      $("#rp-list-view").style.display = "none";
      $("#rp-detail-view").style.display = "";
    } catch (e) {
      if (String(e.message).includes("404")) toast("该会话暂无报告", "error");
      else toast(e.message, "error");
    }
  };
  $("#rp-back").onclick = () => { showList(); loadList(); };   // 切回列表视图并刷新（新报告可见）
  $("#rp-refresh").onclick = loadList;
  $("#rp-md").onclick = async () => {
    try {
      const d = await api(`/report/save?fmt=md${curSid ? `&sid=${curSid}` : ""}`, { method: "POST" });
      toast(`已导出: ${d.path}`);
    } catch (e) { toast(e.message, "error"); }
  };
  $("#rp-json").onclick = async () => {
    try {
      const d = await api(`/report/save?fmt=json${curSid ? `&sid=${curSid}` : ""}`, { method: "POST" });
      toast(`已导出: ${d.path}`);
    } catch (e) { toast(e.message, "error"); }
  };
  onWsEvent("report", () => { if (!curSid) loadList(); });   // 详情页中不被新报告打断
  loadList();
});

// ══════════════════════════════
//  初始化
// ══════════════════════════════
function init() {
  // 构建侧边栏（图标用内联 SVG）
  const nav = $("#nav");
  const order = ["control", "agent", "board", "report", "skills", "aiset"];
  order.forEach((id) => {
    const p = PAGES[id];
    if (!p) return;
    const item = document.createElement("div");
    item.className = "nav-item";
    item.dataset.page = id;
    item.innerHTML = `<span class="icon">${NAV_ICONS[id] || ""}</span>${p.title}`;
    item.onclick = () => navigate(id);
    nav.appendChild(item);
  });

  // 引擎启停按钮
  $("#btn-engine").onclick = async () => {
    try {
      if (appState.frida) {
        await api("/engine/stop", { method: "POST" });
        toast("已停止");
      } else {
        toast("正在注入微信...");
        await api("/engine/start", { method: "POST" });
        toast("Frida 注入成功，请打开目标小程序");
      }
      await refreshStatus();
    } catch (e) {
      toast(e.message, "error");
      await refreshStatus();
    }
  };

  // 顶栏「启动代理」：点击切换启停，文案随状态变化
  $("#btn-topbar-proxy").onclick = async () => {
    try {
      if (appState.proxy_running) {
        await api("/proxy/stop", { method: "POST" });
        toast("代理已停止");
      } else {
        const r = await api("/proxy/start", { method: "POST", body: {} });
        if (r.ok === false) {
          toast(r.error || "代理启动失败", "error");
        } else {
          toast(r.message || "代理已启动");
        }
      }
      await refreshStatus();
    } catch (e) {
      toast(e.message, "error");
    }
  };
  updateTopbarProxy();

  navigate("control");
  connectWs();
  refreshStatus();
  setInterval(refreshStatus, 5000);
}

document.addEventListener("DOMContentLoaded", init);
