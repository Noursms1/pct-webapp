# -*- coding: utf-8 -*-
"""REA MCP client with sidecar support and audited direct MCP fallback."""
import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    ClientSession = StdioServerParameters = stdio_client = None

logger = logging.getLogger("pct.rea")
if not logger.handlers:
    handler = logging.FileHandler(Path(__file__).with_name("rea_calls.log"), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

REA_TOOLS = {
    "annotate_native_function": "تحليل وتوثيق الدوال",
    "inspect_native_load_image": "فحص الصور المحملة والتحقق من DOS MZ / COM",
    "inspect_native_data_type": "فحص أنواع البيانات والـ structs",
    "inspect_native_instruction": "تفكيك وتحليل الأوامر",
    "resolve_native_call_targets": "تتبع نداءات الدوال",
}
MUTATING_TOOLS = {"annotate_native_function"}
server_params = (
    StdioServerParameters(
        command=os.getenv("REA_COMMAND", "npx"),
        args=os.getenv("REA_ARGS", "-y rea-agents mcp").split(),
    ) if StdioServerParameters else None
)


class REAClient:
    def __init__(self, port: int | None = None, timeout: float = 300):
        self.port = port or int(os.getenv("REA_BRIDGE_PORT", "7801"))
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.timeout = timeout

    def _request(self, payload: dict[str, Any]) -> Any:
        request = urllib.request.Request(self.base_url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"REA sidecar unavailable: {exc.reason}") from exc
        if not body.get("ok"):
            raise RuntimeError(body.get("error", "REA request failed"))
        return body.get("result")

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._request({"method": "list_tools"})
        return result.get("tools", []) if isinstance(result, dict) else []

    def call_tool(self, name: str, arguments: dict[str, Any], confirmed: bool = False) -> Any:
        if name in MUTATING_TOOLS and not confirmed:
            raise PermissionError("explicit confirmation is required for annotation tools")
        logger.info("REA call tool=%s confirmed=%s arguments=%s", name, confirmed, json.dumps(arguments, default=str))
        return self._request({"method": "call_tool", "params": {"name": name, "arguments": arguments}})


async def call_rea_tool(tool_name: str, arguments: dict[str, Any], *, confirmed: bool = False):
    if stdio_client is None:
        raise RuntimeError("Python package 'mcp' is not installed")
    if tool_name in MUTATING_TOOLS and not confirmed:
        raise PermissionError("explicit confirmation is required for annotation tools")
    logger.info("REA direct call tool=%s confirmed=%s arguments=%s", tool_name, confirmed, json.dumps(arguments, default=str))
    if stdio_client is None:
        raise RuntimeError("Python package 'mcp' is not installed")
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            logger.info("REA direct result tool=%s status=success", tool_name)
            return result


async def list_rea_tools():
    if stdio_client is None:
        raise RuntimeError("Python package 'mcp' is not installed")
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.list_tools()
