"""toolkit 执行 API：供 FusionWeb worker 远程执行工具（HTTP + JSON）。

端点：
  GET  /healthz            健康检查
  GET  /tools              白名单工具列表
  POST /exec               执行一次工具调用
       body: {tool, args[], workspace?, timeout?, stdin?}
       header: X-Toolkit-Token: <TOOLKIT_TOKEN>（设置了 TOOLKIT_TOKEN 时必填）

只监听容器网络；默认端口 7001。
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runner import ToolError, list_tools, run_tool

TOKEN = os.environ.get("TOOLKIT_TOKEN", "").strip()
PORT = int(os.environ.get("TOOLKIT_EXEC_PORT", "7001"))
MAX_BODY = int(os.environ.get("TOOLKIT_MAX_BODY", str(2 * 1024 * 1024)))


class Handler(BaseHTTPRequestHandler):
    server_version = "fusionweb-toolkit/1.0"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not TOKEN:
            return True
        return self.headers.get("X-Toolkit-Token", "") == TOKEN

    def log_message(self, fmt: str, *args) -> None:  # 收敛访问日志
        print(f"[exec] {self.address_string()} {fmt % args}", flush=True)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/healthz"):
            self._send(200, {"ok": True, "tools": len(list_tools())})
            return
        if self.path.startswith("/tools"):
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"tools": list_tools()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/exec"):
            self._send(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(400, {"error": "invalid content length"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as err:  # noqa: BLE001
            self._send(400, {"error": f"invalid json: {err}"})
            return

        tool = str(payload.get("tool") or "").strip()
        if not tool:
            self._send(400, {"error": "缺少 tool"})
            return

        try:
            result = run_tool(
                tool,
                args=payload.get("args"),
                workspace=payload.get("workspace"),
                timeout=payload.get("timeout"),
                stdin=payload.get("stdin"),
            )
        except ToolError as err:
            self._send(400, {"error": str(err)})
            return
        except Exception as err:  # noqa: BLE001
            self._send(500, {"error": f"执行失败: {err}"})
            return
        self._send(200, result)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[exec] toolkit 执行 API 已监听 0.0.0.0:{PORT}（鉴权：{'开启' if TOKEN else '关闭'}）", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
