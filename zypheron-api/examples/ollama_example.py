"""Example usage of Ollama provider with Zypheron API.

This script demonstrates how to use the Ollama provider for local LLM inference.

Prerequisites:
1. Ollama installed and running: https://ollama.ai/download
2. At least one model downloaded: ollama pull llama3
3. Zypheron API running: uvicorn app.main:app --reload

Usage:
    python examples/ollama_example.py
"""

import asyncio
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.ai_providers import OllamaProvider
from app.services.ai_providers.ollama_client import OllamaConnectionError


async def check_ollama_server():
    """Check if Ollama server is running and accessible."""
    print("Checking Ollama server status...")

    provider = OllamaProvider()

    try:
        is_running = await provider.health_check()
        if is_running:
            print("✓ Ollama server is running")
            return True
        else:
            print("✗ Ollama server responded but is not healthy")
            return False
    except OllamaConnectionError as e:
        print(f"✗ Ollama server not accessible: {e}")
        print("\nTo start Ollama:")
        print("  1. Install: https://ollama.ai/download")
        print("  2. Run: ollama serve")
        return False
    finally:
        await provider.close()


async def list_available_models():
    """List models available on the Ollama server."""
    print("\nListing available models...")

    provider = OllamaProvider()

    try:
        models = await provider.list_models()

        if models:
            print(f"✓ Found {len(models)} model(s):")
            for model in models:
                print(f"  - {model}")
            return models
        else:
            print("✗ No models found")
            print("\nTo download models:")
            print("  ollama pull llama3")
            print("  ollama pull codellama")
            print("  ollama pull mistral")
            return []
    except OllamaConnectionError as e:
        print(f"✗ Failed to list models: {e}")
        return []
    finally:
        await provider.close()


async def simple_chat_example(model: str = "llama3"):
    """Simple non-streaming chat example."""
    print(f"\n{'='*60}")
    print(f"Example 1: Simple Chat (model: {model})")
    print(f"{'='*60}\n")

    provider = OllamaProvider(timeout=60)

    messages = [
        {"role": "user", "content": "What is Python? Answer in one sentence."}
    ]

    try:
        print("Sending request...")
        response = await provider.chat_completion(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=100,
            stream=False,
        )

        print(f"\nResponse: {response.content}")
        print(f"\nMetadata:")
        print(f"  Model: {response.model}")
        print(f"  Tokens: {response.total_tokens} (prompt: {response.prompt_tokens}, completion: {response.completion_tokens})")
        print(f"  Latency: {response.latency_ms}ms")

    except OllamaConnectionError as e:
        print(f"✗ Error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    finally:
        await provider.close()


async def streaming_chat_example(model: str = "llama3"):
    """Streaming chat example."""
    print(f"\n{'='*60}")
    print(f"Example 2: Streaming Chat (model: {model})")
    print(f"{'='*60}\n")

    provider = OllamaProvider(timeout=60)

    messages = [
        {"role": "user", "content": "Write a haiku about coding."}
    ]

    try:
        print("Streaming response:\n")

        stream = await provider.chat_completion(
            messages=messages,
            model=model,
            temperature=0.8,
            max_tokens=100,
            stream=True,
        )

        full_content = ""
        async for chunk in stream:
            if chunk.type == "content":
                print(chunk.content, end="", flush=True)
                full_content += chunk.content
            elif chunk.type == "done":
                print("\n\nStream complete!")
                print(f"\nMetadata:")
                print(f"  Tokens: {chunk.metadata.get('total_tokens', 0)}")
                print(f"  Finish reason: {chunk.metadata.get('finish_reason', 'unknown')}")
            elif chunk.type == "error":
                print(f"\n✗ Error: {chunk.error}")

    except OllamaConnectionError as e:
        print(f"✗ Error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    finally:
        await provider.close()


async def code_generation_example(model: str = "codellama"):
    """Code generation example using CodeLlama."""
    print(f"\n{'='*60}")
    print(f"Example 3: Code Generation (model: {model})")
    print(f"{'='*60}\n")

    provider = OllamaProvider(timeout=90)  # Longer timeout for code generation

    messages = [
        {
            "role": "user",
            "content": "Write a Python function to calculate fibonacci numbers recursively. Include docstring."
        }
    ]

    try:
        print("Generating code...")

        response = await provider.chat_completion(
            messages=messages,
            model=model,
            temperature=0.3,  # Lower temperature for code
            max_tokens=500,
            stream=False,
        )

        print(f"\nGenerated Code:\n")
        print(response.content)

    except OllamaConnectionError as e:
        print(f"✗ Error: {e}")
        if "not found" in str(e):
            print(f"\nTo install {model}:")
            print(f"  ollama pull {model}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    finally:
        await provider.close()


async def multi_turn_conversation_example(model: str = "llama3"):
    """Multi-turn conversation example."""
    print(f"\n{'='*60}")
    print(f"Example 4: Multi-turn Conversation (model: {model})")
    print(f"{'='*60}\n")

    provider = OllamaProvider(timeout=60)

    # Build conversation history
    messages = [
        {"role": "user", "content": "What is machine learning?"},
    ]

    try:
        # First turn
        print("User: What is machine learning?\n")
        response1 = await provider.chat_completion(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=200,
            stream=False,
        )
        print(f"Assistant: {response1.content}\n")

        # Add assistant response to history
        messages.append({"role": "assistant", "content": response1.content})

        # Second turn
        messages.append({"role": "user", "content": "Can you give me a simple example?"})
        print("User: Can you give me a simple example?\n")

        response2 = await provider.chat_completion(
            messages=messages,
            model=model,
            temperature=0.7,
            max_tokens=300,
            stream=False,
        )
        print(f"Assistant: {response2.content}\n")

    except OllamaConnectionError as e:
        print(f"✗ Error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
    finally:
        await provider.close()


async def main():
    """Run all examples."""
    print("="*60)
    print("Ollama Provider Examples for Zypheron AI Proxy")
    print("="*60)

    # Check if Ollama is running
    if not await check_ollama_server():
        print("\nPlease start Ollama and try again.")
        return

    # List available models
    models = await list_available_models()

    if not models:
        print("\nPlease install at least one model and try again.")
        return

    # Determine which model to use
    preferred_models = ["llama3", "mistral", "phi"]
    selected_model = None
    for model in preferred_models:
        if any(model in m for m in models):
            selected_model = next(m for m in models if model in m)
            break

    if not selected_model:
        selected_model = models[0]  # Use first available model

    print(f"\nUsing model: {selected_model}")

    # Run examples
    await simple_chat_example(selected_model)
    await streaming_chat_example(selected_model)

    # Try code generation if codellama is available
    if any("codellama" in m for m in models):
        codellama_model = next(m for m in models if "codellama" in m)
        await code_generation_example(codellama_model)
    else:
        print("\n(Skipping code generation example - codellama not installed)")

    await multi_turn_conversation_example(selected_model)

    print("\n" + "="*60)
    print("Examples completed!")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
