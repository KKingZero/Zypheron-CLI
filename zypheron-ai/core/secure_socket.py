"""
Secure Unix Domain Socket Management

Prevents socket squatting, race conditions, and privilege escalation attacks.
"""

import os
import stat
import fcntl
import socket
import struct
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SocketSecurityError(Exception):
    """Raised when socket security validation fails"""
    pass


class SecureSocketManager:
    """
    Secure Unix domain socket manager with ownership validation and PID tracking.
    
    Security features:
    - User-specific socket directory (~/.zypheron/sockets/)
    - PID-based socket naming to prevent collisions
    - Ownership validation before connection
    - Atomic socket creation with proper permissions (0600)
    - PID file for process tracking
    """
    
    def __init__(self, socket_name: str = "ai"):
        """
        Initialize secure socket manager.
        
        Args:
            socket_name: Base name for the socket (default: "ai")
        """
        self.socket_name = socket_name
        self.socket_dir = self._get_socket_directory()
        self.pid = os.getpid()
        self.socket_path = self.socket_dir / f"{socket_name}-{self.pid}.sock"
        self.pid_file = self.socket_dir / f"{socket_name}-{self.pid}.pid"
        
    def _get_socket_directory(self) -> Path:
        """
        Get secure socket directory in user's home.
        
        Returns:
            Path to socket directory
            
        Raises:
            SocketSecurityError: If directory cannot be created securely
        """
        home = Path.home()
        zypheron_dir = home / ".zypheron"
        socket_dir = zypheron_dir / "sockets"
        
        try:
            # Create .zypheron directory with restricted permissions
            zypheron_dir.mkdir(mode=0o700, exist_ok=True)
            
            # Verify ownership
            stat_info = zypheron_dir.stat()
            if stat_info.st_uid != os.getuid():
                raise SocketSecurityError(
                    f"Directory {zypheron_dir} owned by different user"
                )
            
            # Create sockets subdirectory
            socket_dir.mkdir(mode=0o700, exist_ok=True)
            
            # Verify ownership again
            stat_info = socket_dir.stat()
            if stat_info.st_uid != os.getuid():
                raise SocketSecurityError(
                    f"Directory {socket_dir} owned by different user"
                )
            
            # Verify permissions are restrictive
            mode = stat_info.st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.warning(f"Fixing insecure permissions on {socket_dir}")
                socket_dir.chmod(0o700)
            
            logger.debug(f"Using socket directory: {socket_dir}")
            return socket_dir
            
        except Exception as e:
            raise SocketSecurityError(
                f"Failed to create secure socket directory: {e}"
            ) from e
    
    def create_socket(self) -> str:
        """
        Create a secure Unix domain socket.
        
        Returns:
            Path to created socket
            
        Raises:
            SocketSecurityError: If socket cannot be created securely
        """
        try:
            # Remove any stale socket file
            if self.socket_path.exists():
                # Verify ownership before removing
                stat_info = self.socket_path.stat()
                if stat_info.st_uid != os.getuid():
                    raise SocketSecurityError(
                        f"Stale socket {self.socket_path} owned by different user"
                    )
                self.socket_path.unlink()
            
            # Create PID file first
            self._create_pid_file()
            
            # Create socket with restrictive permissions
            # Note: umask will be applied, but we set permissions explicitly after
            old_umask = os.umask(0o077)  # Ensure restrictive creation
            
            try:
                # Socket will be created by bind()
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.bind(str(self.socket_path))
                
                # Set permissions to owner-only (0600)
                os.chmod(self.socket_path, stat.S_IRUSR | stat.S_IWUSR)
                
                # Verify permissions were set correctly
                stat_info = self.socket_path.stat()
                mode = stat_info.st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise SocketSecurityError(
                        f"Failed to set restrictive permissions on socket"
                    )
                
                logger.info(f"Created secure socket: {self.socket_path}")
                return str(self.socket_path)
                
            finally:
                os.umask(old_umask)
            
        except Exception as e:
            # Clean up on failure
            self._cleanup()
            raise SocketSecurityError(
                f"Failed to create secure socket: {e}"
            ) from e
    
    def validate_socket_ownership(self, socket_path: str) -> bool:
        """
        Validate socket is owned by current user.
        
        Args:
            socket_path: Path to socket file
            
        Returns:
            True if socket is owned by current user
            
        Raises:
            SocketSecurityError: If ownership validation fails
        """
        try:
            path = Path(socket_path)
            
            if not path.exists():
                raise SocketSecurityError(f"Socket does not exist: {socket_path}")
            
            # Check it's a socket
            if not stat.S_ISSOCK(path.stat().st_mode):
                raise SocketSecurityError(
                    f"Path is not a socket: {socket_path}"
                )
            
            # Verify ownership
            stat_info = path.stat()
            if stat_info.st_uid != os.getuid():
                raise SocketSecurityError(
                    f"Socket owned by UID {stat_info.st_uid}, "
                    f"current UID is {os.getuid()}"
                )
            
            # Verify permissions are restrictive
            mode = stat_info.st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SocketSecurityError(
                    f"Socket has insecure permissions: {oct(mode)}"
                )
            
            logger.debug(f"Socket ownership validated: {socket_path}")
            return True
            
        except Exception as e:
            raise SocketSecurityError(
                f"Socket ownership validation failed: {e}"
            ) from e
    
    def connect_to_socket(self, socket_path: str) -> socket.socket:
        """
        Connect to a socket after validating ownership.
        
        Args:
            socket_path: Path to socket
            
        Returns:
            Connected socket
            
        Raises:
            SocketSecurityError: If validation or connection fails
        """
        # Validate ownership first
        self.validate_socket_ownership(socket_path)
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
            logger.debug(f"Connected to socket: {socket_path}")
            return sock
        except Exception as e:
            raise SocketSecurityError(
                f"Failed to connect to socket: {e}"
            ) from e
    
    def _create_pid_file(self):
        """Create PID file for process tracking"""
        try:
            with open(self.pid_file, 'w') as f:
                # Use fcntl to get exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                f.write(str(self.pid))
                f.flush()
            
            # Set restrictive permissions
            os.chmod(self.pid_file, stat.S_IRUSR | stat.S_IWUSR)
            logger.debug(f"Created PID file: {self.pid_file}")
            
        except IOError as e:
            raise SocketSecurityError(
                f"Another instance may be running: {e}"
            ) from e
    
    def find_running_socket(self) -> Optional[str]:
        """
        Find a running socket for this application.
        
        Returns:
            Path to running socket if found, None otherwise
        """
        # Look for socket files in the directory
        pattern = f"{self.socket_name}-*.sock"
        
        for socket_file in self.socket_dir.glob(pattern):
            try:
                # Extract PID from filename
                pid_str = socket_file.stem.split('-')[-1]
                pid = int(pid_str)
                
                # Check if process is still running
                if self._is_process_running(pid):
                    # Validate ownership
                    try:
                        self.validate_socket_ownership(str(socket_file))
                        logger.info(f"Found running socket: {socket_file}")
                        return str(socket_file)
                    except SocketSecurityError:
                        logger.warning(f"Socket ownership validation failed: {socket_file}")
                        continue
                else:
                    # Clean up stale socket
                    logger.info(f"Cleaning up stale socket: {socket_file}")
                    self._cleanup_socket_files(socket_file)
                    
            except (ValueError, IndexError):
                logger.warning(f"Invalid socket filename: {socket_file}")
                continue
        
        return None
    
    def _is_process_running(self, pid: int) -> bool:
        """
        Check if a process is running.
        
        Args:
            pid: Process ID to check
            
        Returns:
            True if process is running
        """
        try:
            # Send signal 0 to check if process exists
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False
    
    def _cleanup_socket_files(self, socket_path: Path):
        """Clean up socket and PID files"""
        try:
            # Get PID from socket name
            pid_str = socket_path.stem.split('-')[-1]
            pid_file = self.socket_dir / f"{self.socket_name}-{pid_str}.pid"
            
            # Remove socket file
            if socket_path.exists():
                socket_path.unlink()
            
            # Remove PID file
            if pid_file.exists():
                pid_file.unlink()
                
        except Exception as e:
            logger.warning(f"Failed to clean up socket files: {e}")
    
    def cleanup(self):
        """Clean up socket and PID files"""
        self._cleanup()
    
    def _cleanup(self):
        """Internal cleanup method"""
        try:
            if self.socket_path.exists():
                self.socket_path.unlink()
                logger.debug(f"Removed socket: {self.socket_path}")
        except Exception as e:
            logger.warning(f"Failed to remove socket: {e}")
        
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                logger.debug(f"Removed PID file: {self.pid_file}")
        except Exception as e:
            logger.warning(f"Failed to remove PID file: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        self.create_socket()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()

