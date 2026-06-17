import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    import anthropic
    from openai import OpenAI

from src.infra.infra_vault import get_secret

logger = structlog.get_logger(__name__)

_GROQ_BASE_URL   = 'https://api.groq.com/openai/v1'
_GROQ_MODEL      = 'llama-3.3-70b-versatile'
_GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/openai/'
_GEMINI_MODEL    = 'gemini-2.0-flash'


@dataclass
class ToolCall:
    id:   str
    name: str
    args: dict


@dataclass
class ChatResponse:
    stop_reason: str
    text:        str
    tool_calls:  list[ToolCall] = field(default_factory=list)


class AnthropicLLM:
    """Thin wrapper around the Anthropic Messages API."""

    def __init__(self, model: str = 'claude-sonnet-4-6'):
        self.model   = model
        self._client: "anthropic.Anthropic | None" = None

    def _get(self) -> "anthropic.Anthropic":
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=get_secret('claude_api_key'))
        return self._client

    def chat(self, system: str, messages: list, tools: list, max_tokens: int) -> ChatResponse:
        resp  = self._get().messages.create(
            model      = self.model,
            max_tokens = max_tokens,
            system     = system,
            tools      = tools or [],
            messages   = messages,
        )
        text  = ''
        calls = []
        for block in resp.content:
            if hasattr(block, 'text'):
                text = block.text
            elif block.type == 'tool_use':
                calls.append(ToolCall(id=block.id, name=block.name, args=block.input))
        return ChatResponse(
            stop_reason = 'tool_use' if calls else 'end_turn',
            text        = text,
            tool_calls  = calls,
        )

    def append_assistant(self, messages: list, response: ChatResponse) -> None:
        content = []
        if response.text:
            content.append({'type': 'text', 'text': response.text})
        for tc in response.tool_calls:
            content.append({'type': 'tool_use', 'id': tc.id, 'name': tc.name, 'input': tc.args})
        messages.append({'role': 'assistant', 'content': content})

    def append_tool_results(self, messages: list, results: list[dict]) -> None:
        content = [
            {'type': 'tool_result', 'tool_use_id': r['tool_call_id'], 'content': r['content']}
            for r in results
        ]
        messages.append({'role': 'user', 'content': content})


class GroqLLM:
    """Thin wrapper around the Groq OpenAI-compatible API."""

    def __init__(self, model: str = _GROQ_MODEL):
        self.model   = model
        self._client: "OpenAI | None" = None

    def _get(self) -> "OpenAI":
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                api_key  = get_secret('groq_api_key', env_fallback='GROQ_API_KEY'),
                base_url = _GROQ_BASE_URL,
            )
        return self._client

    @staticmethod
    def _convert_tools(anthropic_tools: list) -> list:
        """Convert Anthropic tool definitions to OpenAI function-calling format."""
        return [
            {
                'type': 'function',
                'function': {
                    'name':        t['name'],
                    'description': t.get('description', ''),
                    'parameters':  t.get('input_schema', {'type': 'object', 'properties': {}}),
                },
            }
            for t in anthropic_tools
        ]

    def chat(self, system: str, messages: list, tools: list, max_tokens: int) -> ChatResponse:
        full_messages = [{'role': 'system', 'content': system}] + messages
        kwargs: dict  = dict(model=self.model, max_tokens=max_tokens, messages=full_messages)
        if tools:
            kwargs['tools'] = self._convert_tools(tools)

        resp    = self._get().chat.completions.create(**kwargs)
        message = resp.choices[0].message
        text    = message.content or ''
        calls   = [
            ToolCall(
                id   = tc.id,
                name = tc.function.name,
                args = json.loads(tc.function.arguments),
            )
            for tc in (message.tool_calls or [])
        ]
        return ChatResponse(
            stop_reason = 'tool_use' if calls else 'end_turn',
            text        = text,
            tool_calls  = calls,
        )

    def append_assistant(self, messages: list, response: ChatResponse) -> None:
        msg: dict = {'role': 'assistant', 'content': response.text or None}
        if response.tool_calls:
            msg['tool_calls'] = [
                {
                    'id':       tc.id,
                    'type':     'function',
                    'function': {'name': tc.name, 'arguments': json.dumps(tc.args)},
                }
                for tc in response.tool_calls
            ]
        messages.append(msg)

    def append_tool_results(self, messages: list, results: list[dict]) -> None:
        for r in results:
            messages.append({
                'role':         'tool',
                'tool_call_id': r['tool_call_id'],
                'content':      r['content'],
            })


class GeminiLLM:
    """Thin wrapper around the Gemini OpenAI-compatible API."""

    def __init__(self, model: str = _GEMINI_MODEL):
        self.model   = model
        self._client: "OpenAI | None" = None

    def _get(self) -> "OpenAI":
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                api_key  = get_secret('gemini_api_key', env_fallback='GEMINI_API_KEY'),
                base_url = _GEMINI_BASE_URL,
            )
        return self._client

    @staticmethod
    def _convert_tools(anthropic_tools: list) -> list:
        return [
            {
                'type': 'function',
                'function': {
                    'name':        t['name'],
                    'description': t.get('description', ''),
                    'parameters':  t.get('input_schema', {'type': 'object', 'properties': {}}),
                },
            }
            for t in anthropic_tools
        ]

    def chat(self, system: str, messages: list, tools: list, max_tokens: int) -> ChatResponse:
        full_messages = [{'role': 'system', 'content': system}] + messages
        kwargs: dict  = dict(model=self.model, max_tokens=max_tokens, messages=full_messages)
        if tools:
            kwargs['tools'] = self._convert_tools(tools)

        resp    = self._get().chat.completions.create(**kwargs)
        message = resp.choices[0].message
        text    = message.content or ''
        calls   = [
            ToolCall(
                id   = tc.id,
                name = tc.function.name,
                args = json.loads(tc.function.arguments),
            )
            for tc in (message.tool_calls or [])
        ]
        return ChatResponse(
            stop_reason = 'tool_use' if calls else 'end_turn',
            text        = text,
            tool_calls  = calls,
        )

    def append_assistant(self, messages: list, response: ChatResponse) -> None:
        msg: dict = {'role': 'assistant', 'content': response.text or None}
        if response.tool_calls:
            msg['tool_calls'] = [
                {
                    'id':       tc.id,
                    'type':     'function',
                    'function': {'name': tc.name, 'arguments': json.dumps(tc.args)},
                }
                for tc in response.tool_calls
            ]
        messages.append(msg)

    def append_tool_results(self, messages: list, results: list[dict]) -> None:
        for r in results:
            messages.append({
                'role':         'tool',
                'tool_call_id': r['tool_call_id'],
                'content':      r['content'],
            })


_anthropic_llm: AnthropicLLM | None = None
_groq_llm:      GroqLLM      | None = None
_gemini_llm:    GeminiLLM    | None = None


def get_anthropic_llm() -> AnthropicLLM:
    global _anthropic_llm
    if _anthropic_llm is None:
        _anthropic_llm = AnthropicLLM()
    return _anthropic_llm


def get_groq_llm() -> GroqLLM:
    global _groq_llm
    if _groq_llm is None:
        _groq_llm = GroqLLM()
    return _groq_llm


def get_gemini_llm() -> GeminiLLM:
    global _gemini_llm
    if _gemini_llm is None:
        _gemini_llm = GeminiLLM()
    return _gemini_llm


def is_credits_error(exc: Exception) -> bool:
    """True when Anthropic rejects the call due to insufficient credits."""
    import anthropic
    if isinstance(exc, anthropic.PermissionDeniedError):
        return True
    if isinstance(exc, anthropic.APIStatusError):
        if exc.status_code == 403:
            return True
        # Anthropic returns HTTP 400 with invalid_request_error when credit balance is zero
        if exc.status_code == 400 and 'credit balance' in str(exc).lower():
            return True
    return False


def is_groq_rate_limit(exc: Exception) -> bool:
    """True when Groq returns a 429 token-per-day rate limit error."""
    from openai import RateLimitError as OpenAIRateLimitError
    return isinstance(exc, OpenAIRateLimitError)
