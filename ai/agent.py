from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .agent_system_prompt import SYSTEM_PROMPT
from .rea_client import REA_TOOLS, call_rea_tool


class PCTReverseEngineeringAgent:
    """Agent coordinator for PCT analysis and read-only REA workflows."""

    system_prompt = SYSTEM_PROMPT

    def __init__(self):
        self.knowledge_base: dict[str, Any] = {}

    async def analyze_with_rea(
        self,
        path: str,
        *,
        tools: list[str] | None = None,
        confirmed_authorized: bool = False,
        allow_annotation: bool = False,
        extra_arguments: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not confirmed_authorized:
            raise PermissionError("authorization is required before analyzing an executable")
        file_path = Path(path).expanduser().resolve()
        if not file_path.is_file():
            raise FileNotFoundError(file_path)

        selected = tools or ["inspect_native_load_image"]
        unknown = [name for name in selected if name not in REA_TOOLS]
        if unknown:
            raise ValueError(f"unsupported REA tools: {', '.join(unknown)}")

        report = {
            "target": str(file_path),
            "tools": [],
            "results": [],
            "limitations": ["REA analysis is read-only unless annotation is explicitly approved."],
        }
        for tool_name in selected:
            if tool_name == "annotate_native_function" and not allow_annotation:
                raise PermissionError("explicit annotation approval is required")
            arguments = {"path": str(file_path)}
            arguments.update((extra_arguments or {}).get(tool_name, {}))
            result = await call_rea_tool(
                tool_name,
                arguments,
                confirmed=allow_annotation and tool_name == "annotate_native_function",
            )
            report["tools"].append({"name": tool_name, "purpose": REA_TOOLS[tool_name]})
            report["results"].append({"tool": tool_name, "result": result})

        self.knowledge_base["last_rea_report"] = report
        return report

    def analyze_with_rea_sync(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return asyncio.run(self.analyze_with_rea(path, **kwargs))
