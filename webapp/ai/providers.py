"""
AI Provider 适配层 — OpenAI 兼容 / Anthropic / Ollama 三协议
统一 message / tool_call 格式，供 Agent 使用
"""
import json
import re
import asyncio
import random
from typing import List, Dict, Optional

import httpx


# 可重试的瞬时错误关键词（中转站/网关抖动：502 503 504 429 连接重置等）
_TRANSIENT_HINTS = ("502", "503", "504", "429", "bad gateway", "service unavailable",
                    "gateway timeout", "connection reset", "connection aborted",
                    "timed out", "timeout", "eof", "server disconnected", "overloaded")


def _is_transient(e: Exception) -> bool:
    """判断是否为可自动重试的瞬时错误（中转站抖动/限流/超时）"""
    if isinstance(e, (httpx.TimeoutException, httpx.TransportError,
                      httpx.RemoteProtocolError)):
        return True
    s = str(e).lower()
    return any(h in s for h in _TRANSIENT_HINTS)


class AIConfig:
    """AI 配置（持久化到 webapp_config.json）"""
    PROVIDER_OPENAI = "openai"
    PROVIDER_ANTHROPIC = "anthropic"
    PROVIDER_OLLAMA = "ollama"

    def __init__(self):
        self.provider = self.PROVIDER_OPENAI
        # OpenAI 兼容
        self.openai_base_url = "https://api.deepseek.com/v1"
        self.openai_api_key = ""
        self.openai_model = "deepseek-chat"
        # Anthropic
        self.anthropic_base_url = "https://api.anthropic.com"
        self.anthropic_api_key = ""
        self.anthropic_model = "claude-sonnet-4-20250514"
        # Ollama
        self.ollama_base_url = "http://127.0.0.1:11434"
        self.ollama_model = "qwen2.5:14b"

    def to_dict(self):
        return {
            "provider": self.provider,
            "openai_base_url": self.openai_base_url,
            "openai_api_key": self.openai_api_key,
            "openai_model": self.openai_model,
            "anthropic_base_url": self.anthropic_base_url,
            "anthropic_api_key": self.anthropic_api_key,
            "anthropic_model": self.anthropic_model,
            "ollama_base_url": self.ollama_base_url,
            "ollama_model": self.ollama_model,
        }

    def update(self, data: dict):
        for k, v in data.items():
            if hasattr(self, k) and v is not None:
                # API Key 掩码值（GET 配置时返回）不回写，避免破坏真实 key
                if k.endswith("api_key") and isinstance(v, str) and "*" in v:
                    continue
                setattr(self, k, v)


class AIProviderManager:
    """统一 Provider 调用入口"""

    def __init__(self):
        self.config = AIConfig()

    async def chat(self, messages: List[dict], tools: Optional[List[dict]] = None,
                   max_tokens: int = 8192, provider: str = "", model: str = "",
                   override: Optional[dict] = None) -> dict:
        """
        发起对话，返回统一格式:
        {
          "content": str,          # 文本回复
          "tool_calls": [ {id, name, arguments(dict)} ],
          "raw": 原始响应
        }
        provider/model 传入时临时覆盖本次调用的配置（用于多模型切换）
        override 传入模型条目自带的连接配置（base_url/api_key），
        使模型条目自包含——删除该模型即彻底清除其凭据，不残留全局配置
        """
        saved_provider, saved_model = self.config.provider, ""
        # 记录当前协议对应模型，便于恢复
        model_key = {AIConfig.PROVIDER_OPENAI: "openai_model",
                     AIConfig.PROVIDER_ANTHROPIC: "anthropic_model",
                     AIConfig.PROVIDER_OLLAMA: "ollama_model"}.get(self.config.provider)
        if model_key:
            saved_model = getattr(self.config, model_key)
        # 记录被 override 的连接字段，结束后恢复
        override_fields = {}
        try:
            if provider and provider in (AIConfig.PROVIDER_OPENAI, AIConfig.PROVIDER_ANTHROPIC, AIConfig.PROVIDER_OLLAMA):
                self.config.provider = provider
            if model and model_key:
                setattr(self.config, model_key, model)
            # 模型条目自带连接配置：base_url/api_key 以条目为准（不覆盖 model 名）
            if override:
                for k in ("openai_base_url", "openai_api_key",
                          "anthropic_base_url", "anthropic_api_key",
                          "ollama_base_url"):
                    v = (override.get(k) or "").strip()
                    if v and hasattr(self.config, k):
                        override_fields[k] = getattr(self.config, k)
                        setattr(self.config, k, v)
            model_key = {AIConfig.PROVIDER_OPENAI: "openai_model",
                         AIConfig.PROVIDER_ANTHROPIC: "anthropic_model",
                         AIConfig.PROVIDER_OLLAMA: "ollama_model"}.get(self.config.provider)
            # 前置校验，避免 httpx Illegal header value 这类模糊报错
            if self.config.provider == AIConfig.PROVIDER_OPENAI and not self.config.openai_api_key.strip():
                raise ValueError("API Key 未配置 — 请在「模型列表」页填写并保存")
            if self.config.provider == AIConfig.PROVIDER_ANTHROPIC and not self.config.anthropic_api_key.strip():
                raise ValueError("Anthropic API Key 未配置 — 请在「模型列表」页填写并保存")
            if self.config.provider == AIConfig.PROVIDER_ANTHROPIC:
                return await self._chat_with_retry(
                    self._chat_anthropic, self._normalize(messages), tools, max_tokens)
            elif self.config.provider == AIConfig.PROVIDER_OLLAMA:
                return await self._chat_with_retry(
                    self._chat_ollama, self._normalize(messages), tools, max_tokens)
            else:
                return await self._chat_with_retry(
                    self._chat_openai, self._normalize(messages), tools, max_tokens)
        finally:
            self.config.provider = saved_provider
            if model_key and saved_model:
                setattr(self.config, model_key, saved_model)
            # 恢复被 override 的连接字段
            for k, v in override_fields.items():
                setattr(self.config, k, v)

    async def _chat_with_retry(self, fn, *args, retries: int = 4):
        """瞬时错误自动重试（指数退避 + 抖动）。

        中转站/网关的 502/503/429/超时多为秒级抖动，重试即可恢复；
        其他 Agent 平台同模型不出错正是因为内置了这层。非瞬时错误立即抛出。
        """
        last = None
        for attempt in range(retries + 1):
            try:
                return await fn(*args)
            except Exception as e:
                last = e
                if attempt >= retries or not _is_transient(e):
                    raise
                delay = min(2 ** attempt * 1.5, 12.0) + random.uniform(0, 1.0)
                await asyncio.sleep(delay)
        raise last

    @staticmethod
    def _normalize(messages: List[dict]) -> List[dict]:
        """
        把 Agent 内部 history 统一转换为 OpenAI 标准格式:
        - assistant.tool_calls 自定义结构 → 标准 tool_calls[{id,type,function:{name,arguments}}]
        - tool 消息去掉 name 字段（部分兼容端点不支持）
        """
        out = []
        for m in messages:
            role = m.get("role")
            if role == "assistant" and m.get("tool_calls"):
                oai_calls = []
                for tc in m["tool_calls"]:
                    oai_calls.append({
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc["arguments"], ensure_ascii=False),
                        },
                    })
                out.append({
                    "role": "assistant",
                    "content": m.get("content") or None,
                    "tool_calls": oai_calls,
                })
            elif role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": m.get("tool_call_id", ""),
                    "content": m.get("content", ""),
                })
            else:
                out.append({"role": role, "content": m.get("content", "")})
        return out

    # ── OpenAI 兼容 (含 DeepSeek/Qwen/Kimi/GLM) ──

    async def _chat_openai(self, messages, tools, max_tokens):
        base = self.config.openai_base_url.rstrip("/")
        url = f"{base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.config.openai_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in tools
            ]
        # 连接 30s / 读取 600s：非流式大响应（长文本+多工具调用）在中转站上偶发慢回复
        timeout = httpx.Timeout(connect=30.0, read=600.0, write=60.0, pool=30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]["message"]
        tool_calls = []
        args_broken = False  # finish_reason=length 时 arguments JSON 被截断的调用
        for tc in choice.get("tool_calls") or []:
            fn = tc.get("function", {})
            raw_args = fn.get("arguments", "{}")
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except (json.JSONDecodeError, TypeError):
                    # JSON 截断（max_tokens 掐在 arguments 中间）/非 JSON 文本：
                    # 置空让上层校验拒收。必须无条件标记 args_broken——中转站/网关
                    # 常把截断误报为 stop，只信 finish_reason==length 会漏标，空参
                    # 调用被执行后 AI 收到误导性报错原样重发 → 卡死循环（实测 25 分钟）
                    args = {}
                    args_broken = True
            elif raw_args is None:
                # 网关聚合可能整个丢掉 arguments 字段；仅 finish_reason=length 时
                # 标记（模型合法调用零参工具也会是 None，不能一律当截断）
                args = {}
                if data["choices"][0].get("finish_reason") == "length":
                    args_broken = True
            else:
                args = raw_args or {}
            tool_calls.append({
                "id": tc.get("id", ""),
                "name": fn.get("name", ""),
                "arguments": args,
            })
        # content 为空但 reasoning_content 有值（GLM/DeepSeek-R1 等思考模型把
        # token 全花在推理上）时，回落用推理文本——否则 agent 层会误判「空回复」
        content = choice.get("content") or ""
        if not content and not tool_calls:
            content = (choice.get("reasoning_content")
                       or choice.get("reasoning") or "").strip()
        return {
            "content": content,
            "tool_calls": tool_calls,
            "role": "assistant",
            "args_broken": args_broken,
            # finish_reason=length 表示输出被 max_tokens 掐断（截图现场：
            # 输出 8.2K 顶格、content 落空 → agent 误判为空回复提前收尾）
            "finish_reason": data["choices"][0].get("finish_reason", ""),
            "usage": data.get("usage") or {},
        }

    # ── Anthropic ──

    async def _chat_anthropic(self, messages, tools, max_tokens):
        base = self.config.anthropic_base_url.rstrip("/")
        url = f"{base}/v1/messages"
        headers = {
            "x-api-key": self.config.anthropic_api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        # 消息格式转换: system 单独; tool 消息格式适配
        system_text = ""
        conv = []
        for m in messages:
            role = m.get("role")
            if role == "system":
                system_text = m.get("content", "")
                continue
            if role == "tool":
                # tool result → user 消息
                conv.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.get("tool_call_id", ""),
                        "content": m.get("content", ""),
                    }],
                })
            elif role == "assistant" and m.get("tool_calls"):
                content = []
                if m.get("content"):
                    content.append({"type": "text", "text": m["content"]})
                for tc in m["tool_calls"]:
                    content.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["arguments"],
                    })
                conv.append({"role": "assistant", "content": content})
            else:
                conv.append({"role": role, "content": m.get("content", "")})

        payload = {
            "model": self.config.anthropic_model,
            "max_tokens": max_tokens,
            "messages": conv,
        }
        if system_text:
            payload["system"] = system_text
        if tools:
            payload["tools"] = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["input_schema"],
                }
                for t in tools
            ]
        timeout = httpx.Timeout(connect=30.0, read=600.0, write=60.0, pool=30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        content_text = ""
        tool_calls = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content_text += block.get("text", "")
            elif block.get("type") == "tool_use":
                tool_calls.append({
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "arguments": block.get("input", {}),
                })
        return {"content": content_text, "tool_calls": tool_calls, "role": "assistant",
                # usage 归一化到 OpenAI 字段（anthropic 返回 input_tokens/output_tokens）
                "usage": {
                    "prompt_tokens": (data.get("usage") or {}).get("input_tokens", 0),
                    "completion_tokens": (data.get("usage") or {}).get("output_tokens", 0),
                }}

    # ── Ollama (OpenAI 兼容端点) ──

    async def _chat_ollama(self, messages, tools, max_tokens):
        base = self.config.ollama_base_url.rstrip("/")
        url = f"{base}/v1/chat/completions"
        payload = {
            "model": self.config.ollama_model,
            "messages": messages,
            # Ollama 不支持 max_tokens，用 num_predict；options 方式最稳
            "options": {"num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in tools
            ]
        async with httpx.AsyncClient(timeout=600) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]["message"]
        tool_calls = []
        args_broken = False  # arguments JSON 解析失败 = 截断/残缺，同 OpenAI 路径标记
        for tc in choice.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                    args_broken = True
            elif args is None:
                args = {}
                if data["choices"][0].get("finish_reason") == "length":
                    args_broken = True
            tool_calls.append({
                "id": tc.get("id", f"ollama_{len(tool_calls)}"),
                "name": fn.get("name", ""),
                "arguments": args,
            })
        return {
            "content": choice.get("content") or "",
            "tool_calls": tool_calls,
            "role": "assistant",
            "args_broken": args_broken,
            # Ollama /v1/chat/completions 返回 OpenAI 风格 usage（prompt_eval_count/eval_count）
            "usage": {
                "prompt_tokens": (data.get("usage") or {}).get("prompt_tokens",
                                  (data.get("prompt_eval_count") or 0)),
                "completion_tokens": (data.get("usage") or {}).get("completion_tokens",
                                     (data.get("eval_count") or 0)),
            },
        }

    def update_config(self, data: dict):
        self.config.update(data)

    def get_config(self):
        # 隐藏 key 中间部分
        cfg = self.config.to_dict()
        for k in ("openai_api_key", "anthropic_api_key"):
            v = cfg.get(k, "")
            if v and len(v) > 8:
                cfg[k] = v[:4] + "*" * (len(v) - 8) + v[-4:]
        return cfg
