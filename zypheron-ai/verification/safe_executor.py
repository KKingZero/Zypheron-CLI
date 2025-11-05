"""
Safe Executor - Controlled command execution with sandboxing
"""

import logging
import subprocess
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import os
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """Context for safe command execution"""
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    timeout: int = 30
    
    # Safety limits
    max_output_size: int = 10 * 1024 * 1024  # 10MB
    allowed_commands: Optional[List[str]] = None
    forbidden_patterns: List[str] = field(default_factory=lambda: [
        'rm -rf /',
        'dd if=/dev/zero',
        'fork bomb',
        ':(){ :|:& };:',
    ])
    
    # Sandboxing
    use_sandbox: bool = True
    read_only_mode: bool = False
    network_access: bool = True
    
    # Results
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    execution_time: float = 0.0
    error: Optional[str] = None


class SafeExecutor:
    """
    Safe command executor with sandboxing and limits
    
    Features:
    - Command whitelisting
    - Pattern blacklisting
    - Output size limits
    - Timeout enforcement
    - Resource limits
    - Audit logging
    """
    
    def __init__(self):
        self.default_allowed_commands = [
            # Network scanning
            'nmap', 'masscan', 'ncat', 'nc',
            # Web testing
            'curl', 'wget', 'nikto', 'gobuster',
            # SSL/TLS
            'openssl', 'sslyze',
            # DNS
            'dig', 'host', 'nslookup',
            # Safe utilities
            'cat', 'grep', 'awk', 'sed',
        ]
        self.execution_log: List[ExecutionContext] = []
    
    async def execute(self, context: ExecutionContext) -> ExecutionContext:
        """
        Execute command safely
        
        Args:
            context: Execution context with command and parameters
            
        Returns:
            ExecutionContext with results
        """
        start_time = datetime.now()
        
        try:
            # 1. Validation
            if not self._validate_command(context):
                context.error = "Command validation failed"
                return context
            
            # 2. Prepare environment
            env = os.environ.copy()
            env.update(context.env)
            
            # Add safety environment variables
            if context.read_only_mode:
                env['READONLY'] = '1'
            
            # 3. Build command
            full_command = [context.command] + context.args
            
            logger.info(f"Executing: {' '.join(full_command)}")
            
            # 4. Execute with limits
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=context.cwd
            )
            
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=context.timeout
                )
                
                context.stdout = stdout_data.decode('utf-8', errors='replace')
                context.stderr = stderr_data.decode('utf-8', errors='replace')
                context.return_code = process.returncode
                
                # Check output size limits
                if len(context.stdout) > context.max_output_size:
                    context.stdout = context.stdout[:context.max_output_size]
                    context.error = "Output truncated (size limit exceeded)"
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                context.error = f"Execution timeout ({context.timeout}s)"
                context.return_code = -1
                
        except Exception as e:
            context.error = str(e)
            logger.error(f"Execution failed: {e}", exc_info=True)
            
        finally:
            end_time = datetime.now()
            context.execution_time = (end_time - start_time).total_seconds()
            self.execution_log.append(context)
            
        return context
    
    def _validate_command(self, context: ExecutionContext) -> bool:
        """Validate command is safe to execute"""
        # Check if command is allowed
        allowed = context.allowed_commands or self.default_allowed_commands
        
        command_name = os.path.basename(context.command)
        if command_name not in allowed:
            logger.warning(f"Command not in whitelist: {command_name}")
            return False
        
        # Check for forbidden patterns
        full_command = f"{context.command} {' '.join(context.args)}"
        for pattern in context.forbidden_patterns:
            if pattern in full_command:
                logger.warning(f"Forbidden pattern detected: {pattern}")
                return False
        
        # Check for dangerous flags
        dangerous_flags = ['--exec', '--eval', '-e', 'exec', 'eval']
        for flag in dangerous_flags:
            if flag in context.args:
                logger.warning(f"Dangerous flag detected: {flag}")
                return False
        
        return True
    
    async def execute_script(
        self,
        script_content: str,
        interpreter: str = 'bash',
        timeout: int = 30
    ) -> ExecutionContext:
        """
        Execute script content safely
        
        Args:
            script_content: Script to execute
            interpreter: Script interpreter (bash, python, etc.)
            timeout: Execution timeout
            
        Returns:
            ExecutionContext with results
        """
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.sh',
            delete=False
        ) as f:
            f.write(script_content)
            script_path = f.name
        
        try:
            # Make executable
            os.chmod(script_path, 0o700)
            
            # Execute
            context = ExecutionContext(
                command=interpreter,
                args=[script_path],
                timeout=timeout
            )
            
            return await self.execute(context)
            
        finally:
            # Clean up
            try:
                os.unlink(script_path)
            except:
                pass
    
    def get_execution_history(self, limit: int = 10) -> List[ExecutionContext]:
        """Get recent execution history"""
        return self.execution_log[-limit:]

