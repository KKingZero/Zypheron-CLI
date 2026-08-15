from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from contracts.runtime import PolicyMode
from core.mcp_client_config import load_selected_mcp_servers, unsupported_mcp_client_message
from core.query_engine import QueryEngine, QueryRequest
from providers.base import AIMessage, AIResponse
from providers.claude import ClaudeProvider
from providers.openai_provider import OpenAIProvider
from tasks.store import TaskStore


def test_openai_image_message_conversion():
    provider = OpenAIProvider(api_key="test")
    message = AIMessage(
        role="user",
        content="What is shown?",
        metadata={"images": [{"mime_type": "image/png", "data_base64": "abcd"}]},
    )

    formatted = provider._format_message(message)

    assert formatted["content"][0] == {"type": "text", "text": "What is shown?"}
    assert formatted["content"][1]["image_url"]["url"] == "data:image/png;base64,abcd"


def test_claude_image_message_conversion():
    provider = ClaudeProvider(api_key="test")
    message = AIMessage(
        role="user",
        content="What is shown?",
        metadata={"images": [{"url": "https://example.com/a.png"}]},
    )

    content = provider._format_content(message)

    assert content[0] == {"type": "text", "text": "What is shown?"}
    assert content[1] == {
        "type": "image",
        "source": {"type": "url", "url": "https://example.com/a.png"},
    }


@pytest.mark.asyncio
async def test_openai_effort_payload_mapping():
    provider = OpenAIProvider(api_key="test")
    provider.client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(
                    return_value=SimpleNamespace(
                        choices=[SimpleNamespace(message=SimpleNamespace(content="ok"), finish_reason="stop")],
                        usage=SimpleNamespace(total_tokens=3, prompt_tokens=1, completion_tokens=2),
                    )
                )
            )
        )
    )

    await provider.chat([AIMessage(role="user", content="hi")], effort="low")

    kwargs = provider.client.chat.completions.create.await_args.kwargs
    assert kwargs["reasoning_effort"] == "low"


@pytest.mark.asyncio
async def test_openai_uses_responses_api_for_images_when_available():
    provider = OpenAIProvider(api_key="test")
    provider.client = SimpleNamespace(
        responses=SimpleNamespace(
            create=AsyncMock(
                return_value=SimpleNamespace(
                    output_text="ok",
                    usage=SimpleNamespace(input_tokens=1, output_tokens=2, total_tokens=3),
                    status="completed",
                )
            )
        )
    )
    messages = [
        AIMessage(
            role="user",
            content="What is shown?",
            metadata={"images": [{"url": "https://example.com/a.png"}]},
        )
    ]

    response = await provider.chat(messages, effort="high")

    kwargs = provider.client.responses.create.await_args.kwargs
    assert kwargs["reasoning"] == {"effort": "high"}
    assert kwargs["input"][0]["content"][1] == {
        "type": "input_image",
        "image_url": "https://example.com/a.png",
    }
    assert response.metadata["api"] == "responses"


@pytest.mark.asyncio
async def test_claude_effort_payload_mapping():
    provider = ClaudeProvider(api_key="test")
    provider.client = SimpleNamespace(
        messages=SimpleNamespace(
            create=AsyncMock(
                return_value=SimpleNamespace(
                    content=[SimpleNamespace(text="ok")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=2),
                    stop_reason="end_turn",
                )
            )
        )
    )

    await provider.chat([AIMessage(role="user", content="hi")], effort="medium")

    kwargs = provider.client.messages.create.await_args.kwargs
    assert kwargs["output_config"] == {"effort": "medium"}


def test_mcp_config_loading(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "local-test": {
              "command": "python",
              "args": ["server.py"],
              "env": {"A": "B"},
              "allowed_tools": ["read"],
              "approval": "readonly"
            }
          }
        }
        """
    )

    servers = load_selected_mcp_servers(str(config), [{"label": "local-test"}])

    assert servers[0].label == "local-test"
    assert servers[0].command == "python"
    assert servers[0].allowed_tools == ["read"]


def test_mcp_unsupported_message_distinguishes_remote_and_stdio(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "local-test": {"command": "python"},
            "remote-test": {"server_url": "https://example.com/sse"}
          }
        }
        """
    )

    servers = load_selected_mcp_servers(str(config), [{"label": "local-test"}, {"label": "remote-test"}])
    message = unsupported_mcp_client_message(servers)

    assert "stdio server(s): local-test" in message
    assert "remote HTTP/SSE server(s): remote-test" in message


def test_mcp_config_invalid_errors(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": []}')

    with pytest.raises(ValueError, match="mcpServers"):
        load_selected_mcp_servers(str(config), [{"label": "local-test"}])


@pytest.mark.asyncio
async def test_query_engine_rejects_selected_mcp_before_provider_call(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"local-test": {"command": "python"}}}')
    engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
    request = QueryRequest(
        messages=[AIMessage(role="user", content="use a tool")],
        mcp_config=str(config),
        mcp=[{"label": "local-test"}],
        policy_mode=PolicyMode.INTERACTIVE_SAFE,
    )

    with pytest.raises(NotImplementedError, match="chat-time MCP tool execution is experimental"):
        await engine.execute(request)


@pytest.mark.asyncio
async def test_query_engine_passes_effort_to_supported_provider(tmp_path):
    engine = QueryEngine(task_store=TaskStore(str(tmp_path / "runtime.db")))
    request = QueryRequest(
        messages=[AIMessage(role="user", content="Explain SQL injection.")],
        provider="openai",
        effort="minimal",
    )
    mock_response = AIResponse(content="ok", provider="openai", model="gpt-test", tokens_used=2)

    with patch("core.query_engine.ai_manager.chat", new=AsyncMock(return_value=mock_response)) as mock_chat:
        await engine.execute(request)

    assert mock_chat.await_args.kwargs["effort"] == "minimal"
