"""
WebSocket — 实时日志 / 事件 / AI 消息推送
"""
import asyncio
import json

from fastapi import WebSocket, WebSocketDisconnect


async def websocket_endpoint(websocket: WebSocket, state):
    await websocket.accept()
    state.ws_clients.add(websocket)
    try:
        # 连接后立即推送当前状态
        engine = state.engine
        if engine:
            await websocket.send_text(json.dumps({
                "type": "status",
                "data": dict(engine.status),
            }, ensure_ascii=False))
        while True:
            # 客户端可能发 ping
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                try:
                    await websocket.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        state.ws_clients.discard(websocket)
