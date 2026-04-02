"""
IPC Server for Go <-> Python Communication
Uses Unix domain sockets for fast, efficient communication
"""

import asyncio
import json
import os
import secrets
from pathlib import Path
from typing import Dict, Any, Optional
import sys
import httpx
from loguru import logger

# Ensure project root is on sys.path when executed as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from providers.manager import ai_manager
from providers.base import AIMessage
from analysis.vulnerability_analyzer import VulnerabilityAnalyzer
from ml.vulnerability_predictor import MLVulnerabilityPredictor
from agents.autonomous_agent import AutonomousAgent, AgentTask, AgentOrchestrator
from core.config import config
from core.query_engine import QueryRequest, query_engine
from contracts.runtime import PolicyMode
from tools.registry import tool_registry


async def validate_api_key_with_provider(provider: str, api_key: str) -> tuple[bool, str]:
    """Validate a provider API key with a minimal network request."""
    provider = (provider or "").strip().lower()
    if not provider or not api_key:
        return False, "Both provider and API key are required"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if provider == "anthropic":
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": config.CLAUDE_MODEL_FAST,
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                )
                if response.status_code == 200:
                    return True, "Anthropic API key validated successfully"
                if response.status_code in (401, 403):
                    return False, "Invalid Claude API key"
                return False, f"Anthropic API returned status {response.status_code}"

            if provider == "openai":
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "OpenAI API key validated successfully"
                if response.status_code in (401, 403):
                    return False, "Invalid OpenAI API key"
                return False, f"OpenAI API returned status {response.status_code}"

            if provider == "google":
                response = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
                )
                if response.status_code == 200:
                    return True, "Gemini API key validated successfully"
                if response.status_code in (400, 401, 403):
                    return False, "Invalid Gemini API key"
                return False, f"Gemini API returned status {response.status_code}"

            if provider == "deepseek":
                response = await client.get(
                    "https://api.deepseek.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "DeepSeek API key validated successfully"
                if response.status_code in (401, 403):
                    return False, "Invalid DeepSeek API key"
                return False, f"DeepSeek API returned status {response.status_code}"

            if provider == "grok":
                response = await client.get(
                    "https://api.x.ai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "Grok API key validated successfully"
                if response.status_code in (401, 403):
                    return False, "Invalid Grok API key"
                return False, f"Grok API returned status {response.status_code}"

            if provider == "kimi":
                response = await client.get(
                    "https://api.moonshot.cn/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if response.status_code == 200:
                    return True, "Kimi API key validated successfully"
                if response.status_code in (401, 403):
                    return False, "Invalid Kimi API key"
                return False, f"Kimi API returned status {response.status_code}"

            if provider == "nvd":
                return True, "NVD API key accepted"

            return False, f"Unknown provider: {provider}"
    except httpx.TimeoutException:
        return False, f"Timed out validating {provider} API key"
    except httpx.RequestError as exc:
        return False, f"Network error validating {provider} API key: {exc}"
    except Exception as exc:
        return False, f"Unexpected error validating {provider} API key: {exc}"


class IPCServer:
    """IPC Server for handling requests from Go CLI"""
    
    def __init__(self, socket_path: str = None):
        self.socket_path = socket_path or config.IPC_SOCKET_PATH
        self.transport = "unix"
        self.endpoint = self.socket_path
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.ml_predictor = MLVulnerabilityPredictor()
        self.agent_orchestrator = AgentOrchestrator()
        self.query_engine = query_engine
        self.server = None
        
        # Generate or load authentication token
        self.auth_token = self._init_auth_token()

    def _endpoint_file(self) -> Path:
        return Path.home() / ".zypheron" / "ipc.endpoint.json"

    def _write_endpoint_file(self) -> None:
        endpoint_file = self._endpoint_file()
        endpoint_file.parent.mkdir(mode=0o700, exist_ok=True)
        payload = {
            "transport": self.transport,
            "endpoint": self.endpoint,
        }
        endpoint_file.write_text(json.dumps(payload), encoding="utf-8")
        endpoint_file.chmod(0o600)

    async def _serve_stdio(self):
        """Serve IPC over stdio (line-delimited JSON)."""
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break

            response = None
            try:
                request = json.loads(line.decode("utf-8"))
                provided_token = request.get("auth_token")
                if provided_token != self.auth_token:
                    response = {
                        "success": False,
                        "error": "Authentication failed: invalid token",
                    }
                else:
                    response = await self.handle_request(request)
            except Exception as e:
                response = {
                    "success": False,
                    "error": str(e),
                }

            out = (json.dumps(response) + "\n").encode("utf-8")
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()
    
    def _init_auth_token(self) -> str:
        """Initialize or load authentication token"""
        token_dir = Path.home() / ".zypheron"
        token_file = token_dir / "ipc.token"
        
        # Create directory if it doesn't exist
        token_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Load existing token or generate new one
        if token_file.exists():
            try:
                token = token_file.read_text().strip()
                logger.debug("Loaded existing auth token")
                return token
            except Exception as e:
                logger.warning(f"Failed to load token, generating new one: {e}")
        
        # Generate new token
        token = secrets.token_hex(32)
        try:
            token_file.write_text(token)
            token_file.chmod(0o600)  # Only owner can read/write
            logger.info(f"Generated new auth token: {token_file}")
        except Exception as e:
            logger.error(f"Failed to save auth token: {e}")
            raise
        
        return token
    
    async def start(self):
        """Start the IPC server"""
        transport = (config.IPC_TRANSPORT or "auto").strip().lower()
        if transport == "stdio":
            self.transport = "stdio"
            self.endpoint = "stdio"
            self._write_endpoint_file()
            logger.info("🚀 Zypheron AI Engine started on stdio")
            logger.info(f"   Available AI providers: {', '.join(ai_manager.list_available_providers())}")
            await self._serve_stdio()
            return

        use_unix = transport in ("auto", "unix")
        use_tcp = transport in ("auto", "tcp")

        last_err = None

        if use_unix:
            try:
                # Ensure socket directory exists
                Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)

                # Remove existing socket file
                if os.path.exists(self.socket_path):
                    os.unlink(self.socket_path)

                self.server = await asyncio.start_unix_server(
                    self.handle_client,
                    path=self.socket_path,
                    limit=config.IPC_MAX_REQUEST_BYTES,
                )

                # Set socket permissions - only owner can read/write
                os.chmod(self.socket_path, 0o600)
                self.transport = "unix"
                self.endpoint = self.socket_path
            except Exception as e:
                last_err = e
                if transport == "unix":
                    raise
                logger.warning(f"Unix IPC unavailable, falling back to TCP localhost: {e}")

        if self.server is None and use_tcp:
            self.server = await asyncio.start_server(
                self.handle_client,
                host=config.IPC_TCP_HOST,
                port=config.IPC_TCP_PORT,
                limit=config.IPC_MAX_REQUEST_BYTES,
            )
            sock = self.server.sockets[0]
            host, port = sock.getsockname()[:2]
            self.transport = "tcp"
            self.endpoint = f"{host}:{port}"

        if self.server is None:
            raise RuntimeError(f"Failed to start IPC server: {last_err}")

        self._write_endpoint_file()

        logger.info(f"🚀 Zypheron AI Engine started on {self.transport}:{self.endpoint}")
        logger.info(f"   Available AI providers: {', '.join(ai_manager.list_available_providers())}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        try:
            # Read request
            request = await self._read_request(reader)
            logger.debug(f"Received request: {request.get('method', 'unknown')}")
            
            # Verify authentication token
            provided_token = request.get('auth_token')
            if provided_token != self.auth_token:
                logger.warning("Authentication failed: invalid token")
                error_response = {
                    'success': False,
                    'error': 'Authentication failed: invalid token'
                }
                writer.write(json.dumps(error_response).encode('utf-8'))
                await writer.drain()
                return
            
            # Route request to appropriate handler
            response = await self.handle_request(request)
            
            # Send response
            response_data = json.dumps(response).encode('utf-8')
            writer.write(response_data)
            await writer.drain()
        
        except Exception as e:
            logger.error(f"Error handling client: {e}")
            error_response = {
                'success': False,
                'error': str(e)
            }
            writer.write(json.dumps(error_response).encode('utf-8'))
            await writer.drain()
        
        finally:
            writer.close()
            await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> Dict[str, Any]:
        """Read a single JSON request delimited by newline."""
        buffer = bytearray()
        max_size = config.IPC_MAX_REQUEST_BYTES

        while True:
            chunk = await reader.read(config.IPC_BUFFER_SIZE)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > max_size:
                raise ValueError(
                    f"Request too large ({len(buffer)} bytes). "
                    f"Max {max_size} bytes. Reduce context or increase IPC_MAX_REQUEST_BYTES."
                )
            if b"\n" in chunk:
                break

        if not buffer:
            raise ValueError("Empty request")

        data = bytes(buffer)
        if b"\n" in data:
            data = data.split(b"\n", 1)[0]

        return json.loads(data.decode("utf-8"))
    
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Route request to appropriate handler"""
        method = request.get('method')
        params = request.get('params', {})
        
        handlers = {
            'chat': self.handle_chat,
            'analyze_scan': self.handle_analyze_scan,
            'predict_vulnerabilities': self.handle_predict_vulnerabilities,
            'create_agent': self.handle_create_agent,
            'agent_status': self.handle_agent_status,
            'list_providers': self.handle_list_providers,
            'health': self.handle_health,
            'stream_chat': self.handle_stream_chat,
            'validate_api_key': self.handle_validate_api_key,
            'store_api_key': self.handle_store_api_key,
            'get_configured_providers': self.handle_get_configured_providers,
            'ad_attack': self.handle_ad_attack,
            'cloud_scan': self.handle_cloud_scan,
            'bounty_analyze': self.handle_bounty_analyze,
            'mitre_attack': self.handle_mitre_attack,
            'task_list': self.handle_task_list,
            'task_get': self.handle_task_get,
            'task_events': self.handle_task_events,
            'task_approve': self.handle_task_approve,
        }
        
        handler = handlers.get(method)
        if not handler:
            return {
                'success': False,
                'error': f'Unknown method: {method}'
            }
        
        try:
            result = await handler(params)
            return {
                'success': True,
                'result': result
            }
        except Exception as e:
            logger.error(f"Handler error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def handle_chat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle chat request"""
        messages_data = params.get('messages', [])
        messages = [
            AIMessage(
                role=msg['role'],
                content=msg['content'],
                metadata=msg.get('metadata'),
            )
            for msg in messages_data
        ]

        policy_mode_value = str(params.get('policy_mode', PolicyMode.INTERACTIVE_SAFE.value)).strip().lower()
        try:
            policy_mode = PolicyMode(policy_mode_value)
        except ValueError:
            policy_mode = PolicyMode.INTERACTIVE_SAFE
        response = await self.query_engine.execute(
            QueryRequest(
                messages=messages,
                provider=params.get('provider'),
                model=params.get('model'),
                temperature=params.get('temperature', 0.7),
                max_tokens=params.get('max_tokens', 4096),
                session_id=params.get('session_id'),
                task_id=params.get('task_id'),
                policy_mode=policy_mode,
            )
        )
        return response.to_result()
    
    async def handle_stream_chat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle streaming chat request.
        
        NOTE: True streaming requires a different protocol (e.g., SSE/WebSockets or NDJSON over this socket).
        For now, this falls back to standard request/response to prevent client errors.
        """
        logger.debug("Stream chat requested - falling back to standard chat (streaming protocol not implemented)")
        return await self.handle_chat(params)
    
    async def handle_analyze_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan analysis request"""
        scan_output = params.get('scan_output', '')
        tool = params.get('tool', '')
        target = params.get('target', '')
        use_ai = params.get('use_ai', True)
        
        # Analyze the scan
        vulns = await self.vuln_analyzer.analyze_scan_output(
            scan_output=scan_output,
            tool=tool,
            target=target,
            use_ai=use_ai
        )
        
        # Generate report
        report = await self.vuln_analyzer.generate_report(vulns, format='markdown')
        
        return {
            'vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'description': v.description,
                    'severity': v.severity,
                    'cvss_score': v.cvss_score,
                    'cve_id': v.cve_id,
                    'port': v.port,
                    'host': v.host,
                    'remediation': v.remediation,
                    'exploit_available': v.exploit_available,
                    'references': v.references,
                }
                for v in vulns
            ],
            'report': report,
            'summary': {
                'total': len(vulns),
                'critical': sum(1 for v in vulns if v.severity == 'critical'),
                'high': sum(1 for v in vulns if v.severity == 'high'),
                'medium': sum(1 for v in vulns if v.severity == 'medium'),
                'low': sum(1 for v in vulns if v.severity == 'low'),
            }
        }
    
    async def handle_predict_vulnerabilities(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ML vulnerability prediction"""
        scan_data = params.get('scan_data', {})
        use_ai = params.get('use_ai', True)
        
        # Run ML prediction
        predictions = await self.ml_predictor.predict_vulnerabilities(
            scan_data=scan_data,
            use_ai=use_ai
        )
        
        return {
            'predictions': [
                {
                    'vulnerability_type': p.vulnerability_type,
                    'confidence': p.confidence,
                    'severity': p.severity,
                    'reasoning': p.reasoning,
                    'affected_components': p.affected_components,
                    'recommended_tests': p.recommended_tests,
                }
                for p in predictions
            ]
        }
    
    async def handle_create_agent(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle autonomous agent creation"""
        task = AgentTask(
            task_id=params.get('task_id', f"agent-{len(self.agent_orchestrator.agents)}"),
            objective=params.get('objective', ''),
            target=params.get('target', ''),
            scope=params.get('scope', []),
            constraints=params.get('constraints', []),
            max_duration=params.get('max_duration', 3600),
            ai_provider=params.get('ai_provider', 'claude'),
        )
        
        task_id = await self.agent_orchestrator.create_agent(task)
        
        return {
            'task_id': task_id,
            'status': 'created'
        }
    
    async def handle_agent_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent status request"""
        task_id = params.get('task_id')
        
        if not task_id:
            # Return all agents
            return {
                'agents': self.agent_orchestrator.list_agents()
            }
        
        status = self.agent_orchestrator.get_agent_status(task_id)
        
        if not status:
            raise ValueError(f"Agent not found: {task_id}")
        
        return status
    
    async def handle_list_providers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list providers request"""
        providers = ai_manager.list_available_providers()
        
        return {
            'providers': providers,
            'default': config.DEFAULT_PROVIDER
        }
    
    async def handle_health(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle health check request"""
        return {
            'status': 'healthy',
            'version': '2.0.0',
            'providers': ai_manager.list_available_providers(),
            'socket': self.socket_path,
            'transport': self.transport,
            'endpoint': self.endpoint,
            'shared_tool_count': len(tool_registry.specs()),
        }

    async def handle_task_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List recent runtime tasks."""
        limit = int(params.get('limit', 50))
        session_id = params.get('session_id') or None
        task_id = params.get('task_id') or None
        tasks = [
            task.to_dict()
            for task in self.query_engine.task_store.list_tasks(
                limit=limit,
                session_id=session_id,
                task_id=task_id,
            )
        ]
        return {'tasks': tasks}

    async def handle_task_get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch a single task by id."""
        task_id = params.get('task_id')
        if not task_id:
            raise ValueError("task_id is required")
        task = self.query_engine.task_store.get_task(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        return task.to_dict()

    async def handle_task_events(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch audit events for a task."""
        task_id = params.get('task_id')
        if not task_id:
            raise ValueError("task_id is required")
        task = self.query_engine.task_store.get_task(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        return {'events': self.query_engine.task_store.list_events(task_id)}

    async def handle_task_approve(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Apply an approval decision to a waiting task."""
        task_id = params.get('task_id')
        request_id = params.get('request_id')
        decision = params.get('decision')
        if not task_id:
            raise ValueError("task_id is required")
        if not request_id:
            raise ValueError("request_id is required")
        if not decision:
            raise ValueError("decision is required")
        task = self.query_engine.task_store.get_task(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        if task.kind == "autopent":
            self.query_engine.task_store.set_approval_response(
                task_id=task_id,
                request_id=request_id,
                decision=decision,
            )
            return {
                'content': f'Queued approval decision `{decision}` for autopent task {task_id}.',
                'session_id': task.session_id,
                'task_id': task.task_id,
                'task_status': task.status.value,
                'progress_events': [],
                'approval_request': None,
            }
        response = await self.query_engine.submit_approval(
            task_id=task_id,
            request_id=request_id,
            decision=decision,
        )
        return response.to_result()
    
    async def handle_store_api_key(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle API key storage request"""
        from core.secure_config import store_api_key

        provider = params.get('provider', '')
        api_key = params.get('api_key', '')

        if not provider or not api_key:
            raise ValueError("Both provider and api_key are required")

        is_valid, message = await validate_api_key_with_provider(provider, api_key)
        if not is_valid:
            return {
                'success': False,
                'provider': provider,
                'message': message,
            }

        success = store_api_key(provider, api_key)
        if success:
            config.reload_api_keys()
            ai_manager.reload()

        return {
            'success': success,
            'provider': provider,
            'message': "API key stored successfully" if success else "Failed to store API key",
        }

    async def handle_validate_api_key(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle API key validation request."""
        provider = params.get('provider', '')
        api_key = params.get('api_key', '')

        is_valid, message = await validate_api_key_with_provider(provider, api_key)
        return {
            'success': is_valid,
            'provider': provider,
            'message': message,
        }
    
    async def handle_get_configured_providers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get configured providers request"""
        from core.secure_config import list_configured_providers
        
        providers = list_configured_providers()
        
        return {
            'providers': providers,
        }

    async def handle_ad_attack(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Active Directory attack orchestration"""
        from ad.engine import ADEngine

        engine = ADEngine(
            session_id=params.get('session_id', ''),
            target=params.get('target', ''),
            domain=params.get('domain', ''),
            mode=params.get('mode', 'full'),
            user=params.get('user', ''),
            password=params.get('password', ''),
            ntlm_hash=params.get('hash', ''),
            available_tools=params.get('available_tools', []),
            ai_provider=ai_manager,
        )
        return await engine.run()

    async def handle_cloud_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle cloud security scanning"""
        from cloud.engine import CloudEngine

        engine = CloudEngine(
            session_id=params.get('session_id', ''),
            provider=params.get('provider', 'aws'),
            target=params.get('target', ''),
            mode=params.get('mode', 'audit'),
            profile=params.get('profile', ''),
            available_tools=params.get('available_tools', []),
            ai_provider=ai_manager,
        )
        return await engine.run()

    async def handle_bounty_analyze(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle bug bounty analysis"""
        from bounty.engine import BountyEngine

        engine = BountyEngine(
            session_id=params.get('session_id', ''),
            targets=params.get('targets', []),
            out_of_scope=params.get('out_of_scope', []),
            platform=params.get('platform', 'hackerone'),
            program=params.get('program', ''),
            ai_provider=ai_manager,
        )
        return await engine.run()

    async def handle_mitre_attack(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MITRE ATT&CK objective-driven attack"""
        from mitre.engine import MitreEngine

        engine = MitreEngine(ai_provider=ai_manager)

        method = params.get('method', 'run_objective')

        if method == 'list_tactics':
            return {'tactics': engine.list_tactics()}
        elif method == 'get_technique':
            technique = engine.get_technique(params.get('technique_id', ''))
            return {'technique': technique}
        elif method == 'update_data':
            return await engine.update_data()
        elif method == 'heatmap':
            return engine.generate_heatmap_data(params.get('techniques', []))
        else:
            # Default: run_objective
            return await engine.run_objective(
                objective=params.get('objective', ''),
                target=params.get('target', ''),
                session_id=params.get('session_id', ''),
            )


async def main():
    """Main entry point"""
    from loguru import logger
    import sys
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        level=config.LOG_LEVEL
    )
    logger.add(
        config.LOG_FILE,
        rotation="10 MB",
        retention="7 days",
        level="DEBUG"
    )
    
    # Start server
    server = IPCServer()
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == '__main__':
    asyncio.run(main())
