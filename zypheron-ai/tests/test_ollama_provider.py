"""Tests for Ollama model fallback selection."""

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
PROVIDERS_DIR = ROOT / "providers"

providers_pkg = types.ModuleType("providers")
providers_pkg.__path__ = [str(PROVIDERS_DIR)]
sys.modules.setdefault("providers", providers_pkg)

logger = SimpleNamespace(
    info=lambda *args, **kwargs: None,
    debug=lambda *args, **kwargs: None,
    warning=lambda *args, **kwargs: None,
)
sys.modules.setdefault("loguru", SimpleNamespace(logger=logger))

core_pkg = types.ModuleType("core")
core_pkg.__path__ = [str(ROOT / "core")]
sys.modules.setdefault("core", core_pkg)
sys.modules.setdefault(
    "core.config",
    SimpleNamespace(
        config=SimpleNamespace(
            OLLAMA_HOST="http://localhost:11434",
            OLLAMA_MODEL="llama3.2",
        )
    ),
)

base_spec = importlib.util.spec_from_file_location("providers.base", PROVIDERS_DIR / "base.py")
base_module = importlib.util.module_from_spec(base_spec)
sys.modules["providers.base"] = base_module
base_spec.loader.exec_module(base_module)

ollama_spec = importlib.util.spec_from_file_location("providers.ollama", PROVIDERS_DIR / "ollama.py")
ollama_module = importlib.util.module_from_spec(ollama_spec)
sys.modules["providers.ollama"] = ollama_module
ollama_spec.loader.exec_module(ollama_module)

DEFAULT_OLLAMA_MODEL = ollama_module.DEFAULT_OLLAMA_MODEL
OllamaProvider = ollama_module.OllamaProvider
normalize_ollama_host = ollama_module.normalize_ollama_host
select_ollama_model = ollama_module.select_ollama_model


def test_normalize_ollama_host():
    assert normalize_ollama_host("") == "http://localhost:11434"
    assert normalize_ollama_host("localhost:11434/") == "http://localhost:11434"
    assert normalize_ollama_host(" https://ollama.example.com/// ") == "https://ollama.example.com"


def test_select_ollama_model_exact_match():
    assert (
        select_ollama_model("llama3.2", ["mistral:latest", "llama3.2"])
        == "llama3.2"
    )


def test_select_ollama_model_tag_match():
    assert (
        select_ollama_model("llama3.2", ["mistral:latest", "llama3.2:latest"])
        == "llama3.2:latest"
    )


def test_select_ollama_model_skips_embedding_models():
    assert (
        select_ollama_model("llama3.2", ["nomic-embed-text:latest", "mistral:latest"])
        == "mistral:latest"
    )


def test_select_ollama_model_empty_list_keeps_preferred():
    assert select_ollama_model("llama3.3:70b", []) == "llama3.3:70b"


def test_select_ollama_model_empty_list_falls_back_default():
    assert select_ollama_model("", []) == DEFAULT_OLLAMA_MODEL


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return self.payload


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def get(self, url, timeout=None):
        self.urls.append(url)
        key = url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1]
        status, payload = self.routes[key]
        return FakeResponse(status, payload)


def test_list_models_uses_native_tags_first():
    async def run():
        provider = OllamaProvider(host="http://ollama.test", model="llama3.2")
        session = FakeSession(
            {
                "api/tags": (
                    200,
                    {"models": [{"name": " llama3.2:latest "}, {"name": ""}]},
                ),
            }
        )

        models = await provider._list_models(session)

        assert models == ["llama3.2:latest"]
        assert session.urls == ["http://ollama.test/api/tags"]

    asyncio.run(run())


def test_list_models_falls_back_to_openai_compatible_models():
    async def run():
        provider = OllamaProvider(host="http://ollama.test", model="llama3.2")
        session = FakeSession(
            {
                "api/tags": (404, {"error": "missing"}),
                "v1/models": (
                    200,
                    {"data": [{"id": " qwen2.5-coder:latest "}, {"id": ""}]},
                ),
            }
        )

        models = await provider._list_models(session)

        assert models == ["qwen2.5-coder:latest"]
        assert session.urls == [
            "http://ollama.test/api/tags",
            "http://ollama.test/v1/models",
        ]

    asyncio.run(run())
