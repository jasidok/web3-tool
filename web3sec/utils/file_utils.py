
"""
File utility functions for Web3Sec Framework.
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Set, Optional

from .logger import get_logger


class FileUtils:
    """
    Utility class for file operations and discovery.
    
    Provides functionality for discovering files to scan,
    checking file types, and validating external tools.
    """
    
    def __init__(self, config):
        """
        Initialize file utilities.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.logger = get_logger(__name__)
        
        # Get configuration
        self.max_file_size_mb = config.get('scanning.max_file_size_mb', 10)
        self.exclude_patterns = config.get('scanning.exclude_patterns', [])
        
        # Supported file extensions
        self.supported_extensions = {
            '.sol',     # Solidity
            '.js',      # JavaScript
            '.ts',      # TypeScript
            '.json',    # JSON
            '.yaml',    # YAML
            '.yml',     # YAML
            '.md',      # Markdown
            '.txt'      # Text
        }
    
    def discover_files(self, target_path: Path) -> List[Path]:
        """
        Discover files to scan in the target path.
        
        Args:
            target_path: Path to file or directory
            
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        
        if target_path.is_file():
            if self._should_scan_file(target_path):
                files_to_scan.append(target_path)
        elif target_path.is_dir():
            files_to_scan = self._discover_files_in_directory(target_path)
        else:
            self.logger.warning(f"Target path is neither file nor directory: {target_path}")
        
        self.logger.info(f"Discovered {len(files_to_scan)} files to scan")
        return files_to_scan
    
    def _discover_files_in_directory(self, directory: Path) -> List[Path]:
        """Discover files in directory recursively."""
        files = []
        
        try:
            for file_path in directory.rglob("*"):
                if file_path.is_file() and self._should_scan_file(file_path):
                    files.append(file_path)
        except PermissionError as e:
            self.logger.warning(f"Permission denied accessing {directory}: {e}")
        except Exception as e:
            self.logger.error(f"Error discovering files in {directory}: {e}")
        
        return files
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """
        Check if a file should be scanned.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be scanned
        """
        # Check file extension
        if not self._has_supported_extension(file_path):
            return False
        
        # Check file size
        if not self._check_file_size(file_path):
            return False
        
        # Check exclude patterns
        if self._is_excluded(file_path):
            return False
        
        # Check if file is readable
        if not self._is_readable(file_path):
            return False
        
        return True
    
    def _has_supported_extension(self, file_path: Path) -> bool:
        """Check if file has supported extension."""
        return file_path.suffix.lower() in self.supported_extensions
    
    def _check_file_size(self, file_path: Path) -> bool:
        """Check if file size is within limits."""
        try:
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                self.logger.debug(f"Skipping large file ({file_size_mb:.1f}MB): {file_path}")
                return False
            return True
        except OSError:
            return False
    
    def _is_excluded(self, file_path: Path) -> bool:
        """Check if file matches exclude patterns."""
        file_str = str(file_path)
        
        for pattern in self.exclude_patterns:
            # Simple pattern matching (could be enhanced with fnmatch)
            if pattern in file_str:
                self.logger.debug(f"Excluding file matching pattern '{pattern}': {file_path}")
                return True
            
            # Check if pattern matches filename
            if pattern in file_path.name:
                self.logger.debug(f"Excluding file matching pattern '{pattern}': {file_path}")
                return True
        
        return False
    
    def _is_readable(self, file_path: Path) -> bool:
        """Check if file is readable."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.read(1)  # Try to read first character
            return True
        except (OSError, PermissionError):
            self.logger.debug(f"Cannot read file: {file_path}")
            return False
    
    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if external tool is available on the system.
        
        Args:
            tool_name: Name or path of the tool
            
        Returns:
            True if tool is available
        """
        try:
            # Try using shutil.which first
            if shutil.which(tool_name):
                return True
            
            # Try running the tool with --version
            result = subprocess.run(
                [tool_name, '--version'],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def get_file_info(self, file_path: Path) -> dict:
        """
        Get information about a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information
        """
        try:
            stat = file_path.stat()
            
            return {
                'path': str(file_path),
                'name': file_path.name,
                'extension': file_path.suffix,
                'size_bytes': stat.st_size,
                'size_mb': stat.st_size / (1024 * 1024),
                'modified_time': stat.st_mtime,
                'is_readable': self._is_readable(file_path),
                'should_scan': self._should_scan_file(file_path)
            }
        
        except OSError as e:
            return {
                'path': str(file_path),
                'error': str(e)
            }
    
    def create_backup(self, file_path: Path, backup_dir: Optional[Path] = None) -> Optional[Path]:
        """
        Create backup of a file.
        
        Args:
            file_path: Path to the file to backup
            backup_dir: Optional backup directory
            
        Returns:
            Path to backup file or None if failed
        """
        try:
            if backup_dir is None:
                backup_dir = file_path.parent / "backups"
            
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"{file_path.name}.backup"
            
            shutil.copy2(file_path, backup_path)
            self.logger.debug(f"Created backup: {backup_path}")
            
            return backup_path
        
        except Exception as e:
            self.logger.error(f"Failed to create backup for {file_path}: {e}")
            return None
    
    def get_supported_extensions(self) -> Set[str]:
        """Get set of supported file extensions."""
        return self.supported_extensions.copy()
    
    def add_supported_extension(self, extension: str):
        """
        Add a supported file extension.
        
        Args:
            extension: File extension to add (with or without dot)
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'
        
        self.supported_extensions.add(extension.lower())
        self.logger.debug(f"Added supported extension: {extension}")
    
    def remove_supported_extension(self, extension: str):
        """
        Remove a supported file extension.
        
        Args:
            extension: File extension to remove
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'
        
        self.supported_extensions.discard(extension.lower())
        self.logger.debug(f"Removed supported extension: {extension}")
