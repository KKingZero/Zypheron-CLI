"""
Network Manager - Handle communication between coordinator and agents
"""

import logging
import asyncio
import json
from typing import Dict, Optional, Any, Callable
from datetime import datetime
import websockets

logger = logging.getLogger(__name__)


class AgentConnection:
    """Represents a connection to a scan agent"""
    
    def __init__(self, websocket, agent_id: str):
        self.websocket = websocket
        self.agent_id = agent_id
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
    
    async def send(self, message: Dict[str, Any]):
        """Send message to agent"""
        try:
            await self.websocket.send(json.dumps(message))
            self.last_activity = datetime.now()
        except Exception as e:
            logger.error(f"Failed to send to agent {self.agent_id}: {e}")
            raise
    
    async def receive(self) -> Dict[str, Any]:
        """Receive message from agent"""
        try:
            data = await self.websocket.recv()
            self.last_activity = datetime.now()
            return json.loads(data)
        except Exception as e:
            logger.error(f"Failed to receive from agent {self.agent_id}: {e}")
            raise
    
    async def close(self):
        """Close connection"""
        try:
            await self.websocket.close()
        except:
            pass


class NetworkManager:
    """
    Manage network communication for distributed scanning
    
    Features:
    - WebSocket server for coordinator
    - WebSocket client for agents
    - Message routing
    - Connection management
    """
    
    def __init__(self, mode: str = 'coordinator'):
        """
        Initialize network manager
        
        Args:
            mode: 'coordinator' or 'agent'
        """
        self.mode = mode
        self.connections: Dict[str, AgentConnection] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self.server = None
        self.running = False
    
    async def start_coordinator(self, host: str = '0.0.0.0', port: int = 8765):
        """Start coordinator server"""
        if self.mode != 'coordinator':
            raise ValueError("Not in coordinator mode")
        
        logger.info(f"Starting coordinator server on {host}:{port}")
        
        self.running = True
        self.server = await websockets.serve(
            self._handle_agent_connection,
            host,
            port
        )
        
        logger.info(f"Coordinator server listening on ws://{host}:{port}")
    
    async def start_agent(self, coordinator_host: str, coordinator_port: int = 8765):
        """Start agent client"""
        if self.mode != 'agent':
            raise ValueError("Not in agent mode")
        
        logger.info(f"Connecting to coordinator at {coordinator_host}:{coordinator_port}")
        
        uri = f"ws://{coordinator_host}:{coordinator_port}"
        
        while self.running:
            try:
                async with websockets.connect(uri) as websocket:
                    logger.info("Connected to coordinator")
                    
                    # Handle messages
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            await self._handle_message(data, websocket)
                        except Exception as e:
                            logger.error(f"Message handling error: {e}")
                    
            except Exception as e:
                logger.error(f"Connection error: {e}")
                if self.running:
                    logger.info("Reconnecting in 5 seconds...")
                    await asyncio.sleep(5)
                else:
                    break
    
    async def stop(self):
        """Stop network manager"""
        logger.info("Stopping network manager")
        self.running = False
        
        # Close all connections
        for agent_id, conn in self.connections.items():
            try:
                await conn.close()
            except:
                pass
        
        self.connections.clear()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
    
    async def _handle_agent_connection(self, websocket, path):
        """Handle incoming agent connection (coordinator mode)"""
        agent_id = None
        
        try:
            # Wait for registration message
            message = await asyncio.wait_for(
                websocket.recv(),
                timeout=30.0
            )
            
            data = json.loads(message)
            
            if data.get('type') == 'register':
                agent_id = data.get('agent_id')
                
                # Create connection
                connection = AgentConnection(websocket, agent_id)
                self.connections[agent_id] = connection
                
                logger.info(f"Agent {agent_id} connected")
                
                # Send acknowledgment
                await connection.send({
                    'type': 'registered',
                    'agent_id': agent_id,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Handle messages from this agent
                async for msg in websocket:
                    try:
                        msg_data = json.loads(msg)
                        await self._handle_message(msg_data, websocket)
                    except Exception as e:
                        logger.error(f"Error handling message from {agent_id}: {e}")
            else:
                logger.warning("First message must be registration")
                await websocket.close()
                
        except asyncio.TimeoutError:
            logger.warning("Agent registration timeout")
        except Exception as e:
            logger.error(f"Agent connection error: {e}")
        finally:
            if agent_id and agent_id in self.connections:
                del self.connections[agent_id]
                logger.info(f"Agent {agent_id} disconnected")
    
    async def _handle_message(self, data: Dict[str, Any], websocket):
        """Handle incoming message"""
        msg_type = data.get('type')
        
        if msg_type in self.message_handlers:
            handler = self.message_handlers[msg_type]
            try:
                await handler(data, websocket)
            except Exception as e:
                logger.error(f"Handler error for {msg_type}: {e}")
        else:
            logger.warning(f"No handler for message type: {msg_type}")
    
    def register_handler(self, msg_type: str, handler: Callable):
        """Register message handler"""
        self.message_handlers[msg_type] = handler
        logger.info(f"Registered handler for {msg_type}")
    
    async def send_to_agent(self, agent_id: str, message: Dict[str, Any]) -> bool:
        """Send message to specific agent"""
        if agent_id not in self.connections:
            logger.error(f"Agent {agent_id} not connected")
            return False
        
        try:
            connection = self.connections[agent_id]
            await connection.send(message)
            return True
        except Exception as e:
            logger.error(f"Failed to send to agent {agent_id}: {e}")
            return False
    
    async def broadcast(self, message: Dict[str, Any], exclude: Optional[str] = None):
        """Broadcast message to all connected agents"""
        for agent_id, connection in self.connections.items():
            if agent_id == exclude:
                continue
            
            try:
                await connection.send(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to agent {agent_id}: {e}")
    
    def get_connected_agents(self) -> list:
        """Get list of connected agent IDs"""
        return list(self.connections.keys())
    
    def is_agent_connected(self, agent_id: str) -> bool:
        """Check if agent is connected"""
        return agent_id in self.connections

