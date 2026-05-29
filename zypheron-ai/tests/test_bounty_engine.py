"""Tests for bounty runtime convergence."""

from unittest.mock import AsyncMock, patch

import pytest

from bounty.engine import BountyEngine


class TestBountyEngine:
    @pytest.mark.asyncio
    async def test_run_generates_submission_only_from_validated_runtime_findings(self, tmp_path):
        engine = BountyEngine(
            session_id="bounty-session",
            targets=["https://example.com"],
            platform="hackerone",
            program="Example",
        )
        engine.loot.base_dir = tmp_path

        runtime_result = {
            "content": "runtime completed",
            "provider": "zypheron-query-engine",
            "model": "runtime-bounty",
            "tool_results": [
                {
                    "tool_name": "nuclei_scan",
                    "success": True,
                    "content": "[high] exposed panel",
                    "data": {
                        "evidence": {
                            "target": "https://example.com",
                            "summary": "[high] exposed panel",
                            "findings": [
                                {
                                    "title": "[high] exposed panel",
                                    "severity": "high",
                                    "evidence": "GET /admin returned 200",
                                }
                            ],
                        }
                    },
                }
            ],
        }

        with patch("bounty.engine.query_engine.execute", new=AsyncMock(return_value=type("Response", (), {"to_result": lambda self: runtime_result})())):
            result = await engine.run()

        assert len(engine.findings) == 1
        assert len(result["submissions"]) == 1
        assert result["submissions"][0]["severity"] == "high"
