"""
IPC Server for Go <-> Python Communication
Uses Unix domain sockets for fast, efficient communication
"""

import sys
import os
from pathlib import Path

# Add parent directory to Python path for imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

import asyncio
import json
from typing import Dict, Any, Optional
from loguru import logger

# Import Python's built-in secrets module (do this BEFORE any local modules that might conflict)
from secrets import token_hex

from providers.manager import ai_manager
from providers.base import AIMessage
from analysis.vulnerability_analyzer import VulnerabilityAnalyzer
from ml.vulnerability_predictor import MLVulnerabilityPredictor
from agents.autonomous_agent import AutonomousAgent, AgentTask, AgentOrchestrator
from core.config import config
from core.secure_socket import SecureSocketManager, SocketSecurityError


class IPCServer:
    """IPC Server for handling requests from Go CLI"""
    
    def __init__(self, socket_path: str = None):
        # Use secure socket manager
        self.socket_manager = SecureSocketManager(socket_name="ai")
        self.socket_path = socket_path or str(self.socket_manager.socket_path)
        
        self.vuln_analyzer = VulnerabilityAnalyzer()
        self.ml_predictor = MLVulnerabilityPredictor()
        self.agent_orchestrator = AgentOrchestrator()
        self.server = None
        
        # Generate or load authentication token
        self.auth_token = self._init_auth_token()
    
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
        token = token_hex(32)
        try:
            token_file.write_text(token)
            token_file.chmod(0o600)  # Only owner can read/write
            logger.info(f"Generated new auth token: {token_file}")
        except Exception as e:
            logger.error(f"Failed to save auth token: {e}")
            raise
        
        return token
    
    async def start(self):
        """Start the IPC server with secure socket"""
        try:
            # Create secure socket
            self.socket_path = self.socket_manager.create_socket()
            
            # Start Unix socket server
            self.server = await asyncio.start_unix_server(
                self.handle_client,
                path=self.socket_path
            )
            
            logger.info(f"🚀 Zypheron AI Engine started on {self.socket_path}")
            logger.info(f"   Available AI providers: {', '.join(ai_manager.list_available_providers())}")
            logger.info(f"   PID: {self.socket_manager.pid}")
            
            async with self.server:
                await self.server.serve_forever()
                
        except SocketSecurityError as e:
            logger.error(f"Socket security error: {e}")
            raise
        finally:
            # Clean up socket on exit
            self.socket_manager.cleanup()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        try:
            # Read request
            data = await reader.read(config.IPC_BUFFER_SIZE)
            if not data:
                return
            
            request = json.loads(data.decode('utf-8'))
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
            'store_api_key': self.handle_store_api_key,
            'get_configured_providers': self.handle_get_configured_providers,
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
        provider = params.get('provider')
        temperature = params.get('temperature', 0.7)
        max_tokens = params.get('max_tokens', 4096)
        
        # Convert to AIMessage objects
        messages = [
            AIMessage(role=msg['role'], content=msg['content'])
            for msg in messages_data
        ]
        
        # Get AI response
        response = await ai_manager.chat(
            messages=messages,
            provider=provider,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return {
            'content': response.content,
            'provider': response.provider,
            'model': response.model,
            'tokens_used': response.tokens_used,
        }
    
    async def handle_stream_chat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle streaming chat request (note: real streaming needs different protocol)"""
        # For now, return full response
        # In production, implement WebSocket or SSE for true streaming
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
        report = await self.vuln_analyzer.generate_report(vulns, format='text')
        
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
            'version': '1.0.0',
            'providers': ai_manager.list_available_providers(),
            'socket': self.socket_path,
        }
    
    async def handle_store_api_key(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle API key storage request"""
        from core.secure_config import store_api_key
        
        provider = params.get('provider', '')
        api_key = params.get('api_key', '')
        
        if not provider or not api_key:
            raise ValueError("Both provider and api_key are required")
        
        success = store_api_key(provider, api_key)
        
        return {
            'success': success,
            'provider': provider,
        }
    
    async def handle_get_configured_providers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get configured providers request"""
        from core.secure_config import list_configured_providers
        
        providers = list_configured_providers()
        
        return {
            'providers': providers,
        }


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

