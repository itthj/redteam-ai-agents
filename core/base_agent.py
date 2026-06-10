"""
core/base_agent.py
───────────────────
BaseAgent — the foundation every specialized agent inherits from.

State-of-the-art Claude integration:
  • Model            — Claude Opus 4.7 (configurable per agent)
  • Adaptive thinking — Claude decides reasoning depth; summaries captured
  • Effort           — `xhigh` for the orchestrator, `high` for sub-agents
  • Streaming        — every turn streamed; avoids HTTP timeouts on long output
  • Prompt caching   — frozen system+tools prefix cached across every call;
                       a moving breakpoint caches the growing conversation.
                       The volatile knowledge base is kept OUT of the system
                       prompt (it would invalidate the cache every call) and
                       injected into the first user message instead.
  • Telemetry        — token usage + cost recorded for every API call
  • Guardrails       — every tool input screened for destructive actions
  • MCP              — external MCP-server tools merged into the tool surface

The agentic loop:
  1. Stream a request to Claude (system + tools + conversation).
  2. If Claude returns tool_use blocks → execute them (native or MCP),
     append results, repeat.
  3. If Claude returns end_turn → return the final text.
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any, Optional

import anthropic

from config.authorization import OperationType, scope
from config.settings import settings
from core.evidence_store import evidence
from core.guardrails import GuardrailViolation, guardrails
from core.knowledge_base import kb
from core.model_router import router
from core.telemetry import telemetry
from core.tracing import span
from mcp_layer.mcp_bridge import bridge

log = logging.getLogger(__name__)

_CACHE = {"type": "ephemeral"}

# Tool results larger than this (chars) become candidates for fast-model
# compression when settings.compress_tool_output is enabled (5A). nmap / NSE /
# linpeas dumps routinely exceed this; smaller results pass through untouched.
_COMPRESS_THRESHOLD = 6000


class BaseAgent:
    """
    Base class for all red-team agents.

    Sub-classes define:
        NAME, DESCRIPTION, SYSTEM_PROMPT, TOOLS
        _tool_map()  →  {tool_name: callable}
    and may override:
        MODEL, EFFORT, MAX_TOKENS, MAX_ITERATIONS, USE_MCP
    """

    NAME: str = "base"
    DESCRIPTION: str = "Base agent"
    SYSTEM_PROMPT: str = "You are a cybersecurity AI agent."
    TOOLS: list[dict] = []

    MODEL: Optional[str] = None          # None → settings.claude_model
    EFFORT: Optional[str] = None         # None → settings.agent_effort
    MAX_TOKENS: int = 16000
    MAX_ITERATIONS: int = 25
    USE_MCP: bool = True                 # merge MCP-server tools into the surface

    def __init__(self) -> None:
        # Async client — SDK auto-retries 429/5xx with exponential backoff
        self._client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            max_retries=4,
        )
        self._model = self.MODEL or settings.claude_model
        self._effort = self.EFFORT or settings.agent_effort
        self._downgraded = False             # budget governor (5A) — one-way latch
        self._system_block = self._build_system_block()
        log.info("[%s] Agent ready — model=%s effort=%s", self.NAME.upper(),
                 self._model, self._effort)

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, task: str, context: Optional[dict] = None,
                  resume_messages: Optional[list] = None, checkpoint_cb=None) -> str:
        """Run the agent on a task. Returns the agent's final text response.

        resume_messages (5B): rehydrate a prior conversation instead of starting
        fresh. checkpoint_cb(messages): called after each tool round so a caller
        can persist resumable state.
        """
        log.info("[%s] Task: %s", self.NAME.upper(), task[:140])

        # Stable system+tools prefix → cached. Volatile KB → first user message.
        system = [{"type": "text", "text": self._system_block, "cache_control": _CACHE}]
        tools = self._build_tools()
        # Resume from a checkpoint's conversation if provided (5B); else start fresh.
        messages = resume_messages or [
            {"role": "user", "content": self._build_first_message(task, context)}
        ]

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            # ── Budget governor (5A) — checked before each turn ──────────────
            # No-op unless engagement_budget_usd is set and already exceeded.
            if telemetry.over_budget():
                if settings.on_budget_exceeded == "halt":
                    log.warning("[%s] Engagement budget exceeded — halting (mode=halt)",
                                self.NAME.upper())
                    evidence.log(self.NAME, "budget",
                                 "Engagement budget exceeded — run halted",
                                 severity="medium")
                    return (f"[{self.NAME} halted — engagement budget exceeded. "
                            f"Partial findings are saved in the knowledge base.]")
                if not self._downgraded:
                    log.warning("[%s] Engagement budget exceeded — downgrading to %s "
                                "for the rest of the run (mode=downgrade)",
                                self.NAME.upper(), settings.claude_fast_model)
                    evidence.log(self.NAME, "budget",
                                 f"Engagement budget exceeded — downgraded to "
                                 f"{settings.claude_fast_model}", severity="info")
                    self._model = settings.claude_fast_model
                    self._effort = "low"
                    self._downgraded = True

            self._apply_cache_breakpoint(messages)

            try:
                response = await self._stream_turn(system, tools, messages)
            except anthropic.APIError as e:
                status = getattr(e, "status_code", "connection")
                log.error("[%s] API error (%s): %s", self.NAME.upper(), status, e)
                return f"[{self.NAME} aborted — API error ({status}): {e}]"

            telemetry.record(self.NAME, self._model, response.usage)
            messages.append({"role": "assistant", "content": response.content})

            stop = response.stop_reason

            if stop == "tool_use":
                tool_results = await self._run_tool_calls(response.content)
                messages.append({"role": "user", "content": tool_results})
                if checkpoint_cb is not None:
                    checkpoint_cb(messages)        # 5B: flush a checkpoint per round
                continue

            if stop == "pause_turn":
                # Server-side tool loop paused — resend to resume
                continue

            if stop == "refusal":
                log.warning("[%s] Model refused on safety grounds", self.NAME.upper())
                evidence.log(self.NAME, "refusal", "Model declined the task",
                             severity="medium")
                return f"[{self.NAME} declined this task on safety grounds. " \
                       f"Confirm the operation is in scope and rephrase.]"

            # end_turn / stop_sequence / max_tokens
            text = self._extract_text(response.content)
            log.info("[%s] Complete in %d iteration(s)", self.NAME.upper(), iteration)
            return text

        log.warning("[%s] Hit iteration limit (%d)", self.NAME.upper(), self.MAX_ITERATIONS)
        return f"[{self.NAME} reached the {self.MAX_ITERATIONS}-iteration limit. " \
               f"Partial findings are saved in the knowledge base.]"

    def run_sync(self, task: str, context: Optional[dict] = None) -> str:
        """Synchronous wrapper around run()."""
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.run(task, context))
        # Already inside a loop — run in a worker thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, self.run(task, context)).result()

    # ── Request construction ──────────────────────────────────────────────────

    async def _stream_turn(self, system, tools, messages):
        """Stream one turn and return the final assembled Message."""
        kwargs: dict[str, Any] = dict(
            model=self._model,
            max_tokens=self.MAX_TOKENS,
            thinking={"type": "adaptive", "display": "summarized"},
            output_config={"effort": self._effort},
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        with span("agent.turn", agent=self.NAME, model=self._model, effort=self._effort) as s:
            async with self._client.messages.stream(**kwargs) as stream:
                message = await stream.get_final_message()
            usage = getattr(message, "usage", None)
            if s is not None and usage is not None:
                s.set_attribute("input_tokens", getattr(usage, "input_tokens", 0) or 0)
                s.set_attribute("output_tokens", getattr(usage, "output_tokens", 0) or 0)
            return message

    def _build_system_block(self) -> str:
        """Frozen system prompt — role + engagement rules of engagement."""
        s = scope.summary()
        roe = (
            "\n\n--- RULES OF ENGAGEMENT (immutable) ---\n"
            f"Engagement : {s['engagement_id']} — {s['engagement_name']}\n"
            f"Operator   : {s['operator']}\n"
            f"Authorized : {', '.join(s['authorized_targets']) or 'NONE SET'}\n"
            f"Expiry     : {s['expiry']}\n"
            "You may ONLY act against authorized targets. Every tool call is "
            "authorization-checked and logged to a tamper-evident evidence store. "
            "Destructive actions (wipers, ransomware, DoS, mass deletion) are "
            "forbidden and will be blocked. Operate as a professional red-teamer: "
            "methodical, evidence-driven, and within scope."
        )
        return self.SYSTEM_PROMPT + roe

    def _build_first_message(self, task: str, context: Optional[dict]) -> str:
        """First user message — carries the task + volatile knowledge base."""
        kb_snapshot = json.dumps(kb.snapshot(), indent=2, default=str)
        parts = [
            f"# Task\n{task}",
            f"# Current Knowledge Base\n```json\n{kb_snapshot}\n```",
        ]
        if context:
            parts.append(f"# Additional Context\n```json\n"
                         f"{json.dumps(context, indent=2, default=str)}\n```")
        return "\n\n".join(parts)

    def _build_tools(self) -> list[dict]:
        """Native tools + (optionally) MCP-server tools, in a deterministic order."""
        tools = list(self.TOOLS)
        if self.USE_MCP:
            tools += bridge.get_anthropic_tools()
        return tools

    @staticmethod
    def _apply_cache_breakpoint(messages: list[dict]) -> None:
        """
        Move the conversation cache breakpoint to the last block of the last
        message. Clears prior message-level breakpoints so we never exceed the
        4-breakpoint limit (system holds one; this is the second).
        """
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        block.pop("cache_control", None)

        last = messages[-1]
        content = last["content"]
        if isinstance(content, str):
            last["content"] = [{"type": "text", "text": content, "cache_control": _CACHE}]
        elif isinstance(content, list) and content and isinstance(content[-1], dict):
            content[-1]["cache_control"] = _CACHE

    # ── Tool execution ────────────────────────────────────────────────────────

    async def _run_tool_calls(self, content: list) -> list[dict]:
        """Execute every tool_use block and return tool_result blocks."""
        results = []
        for block in content:
            if getattr(block, "type", None) != "tool_use":
                continue
            inputs = dict(block.input)
            with span("agent.tool", agent=self.NAME, tool=block.name,
                      target=inputs.get("target") or inputs.get("ip")):
                text, is_error = await self._execute_tool(block.name, inputs)
                # Cost control (5A): shrink oversized tool dumps via the fast model
                # before they enter (and grow) the expensive cached context. Opt-in;
                # errors and small results are passed through untouched.
                if (not is_error
                        and settings.compress_tool_output
                        and len(text) > _COMPRESS_THRESHOLD):
                    text = await self._compress_tool_output(text)
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": text,
                "is_error": is_error,
            })
        return results

    async def _compress_tool_output(self, text: str) -> str:
        """
        Compress a large tool result down to its security-relevant facts with a
        one-shot fast-model (Haiku) call, before it enters the main Opus context
        (5A cost control).

        Degrades gracefully like the MCP layer: on ANY error, or an empty
        summary, the original text is returned unchanged — compression must
        never lose a finding or break the agentic loop.
        """
        model = router.pick("summarize")[0]
        try:
            response = await self._client.messages.create(
                model=model,
                max_tokens=1024,
                system=(
                    "You compress security-tool output for a red-team engagement. "
                    "Extract ONLY the security-relevant facts: hosts, ports, "
                    "services and versions, vulnerabilities/CVEs, credentials, "
                    "interesting files/paths, and errors. Be terse and lossless on "
                    "facts; drop banners, ASCII art, progress bars, and noise."
                ),
                messages=[{
                    "role": "user",
                    "content": f"Compress this tool output:\n\n{text}",
                }],
            )
        except Exception as e:  # noqa: BLE001 — graceful degradation
            log.warning("[%s] tool-output compression failed (%s) — using raw output",
                        self.NAME.upper(), e)
            return text

        telemetry.record(self.NAME, model, response.usage)
        compressed = self._extract_text(response.content)
        if not compressed:
            return text
        return (f"[compressed {len(text)}→{len(compressed)} chars via {model}]\n"
                f"{compressed}")

    async def _execute_tool(self, name: str, inputs: dict) -> tuple[str, bool]:
        """Run one tool (native or MCP). Returns (result_text, is_error)."""
        log.info("[%s] tool → %s(%s)", self.NAME.upper(), name, list(inputs))

        # 1. Guardrail pre-flight — block destructive inputs
        try:
            guardrails.check_tool_input(name, inputs)
        except GuardrailViolation as e:
            evidence.log(self.NAME, name, f"BLOCKED by guardrail: {e}",
                         target=inputs.get("target") or inputs.get("ip"),
                         severity="high")
            return f"GUARDRAIL BLOCK: {e}", True

        # 2. MCP-routed tool
        if bridge.owns_tool(name):
            result = await bridge.call_tool(name, inputs)
            evidence.log(self.NAME, name, f"MCP tool: {name}",
                         target=inputs.get("target") or inputs.get("ip"),
                         result={"mcp": True}, severity="info")
            return result.get("content", ""), bool(result.get("is_error"))

        # 3. Native tool
        fn = self._tool_map().get(name)
        if fn is None:
            return f"Unknown tool: {name}", True

        try:
            if inspect.iscoroutinefunction(fn):
                result = await fn(**inputs)
            else:
                result = fn(**inputs)
        except Exception as e:
            log.error("[%s] tool %s raised: %s", self.NAME.upper(), name, e)
            return f"Tool error: {e}", True

        is_error = isinstance(result, dict) and ("error" in result or result.get("blocked"))
        evidence.log(
            self.NAME, name, f"Tool call: {name}",
            target=inputs.get("target") or inputs.get("ip") or inputs.get("host"),
            result=result,
            severity="info" if not is_error else "low",
        )
        return json.dumps(result, default=str), bool(is_error)

    def _tool_map(self) -> dict[str, Any]:
        """Override in sub-classes: returns {tool_name: callable}."""
        return {}

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_text(content: list) -> str:
        return "\n".join(
            b.text for b in content if getattr(b, "type", None) == "text"
        ).strip()

    def _authorize(self, target: str, operation: OperationType) -> None:
        """Sub-classes call this inside tools that touch a target."""
        scope.authorize(target, operation, agent_name=self.NAME)
