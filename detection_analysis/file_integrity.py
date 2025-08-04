"""File System Integrity Checker

Detect unauthorized file modifications, new files, and system changes that could
indicate spyware installation or system compromise.
"""

import os
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from loguru import logger


@dataclass
class FileRecord:
    """File information record"""
    path: str
    size: int
    modified_time: float
    permissions: str
    owner: str
    hash_sha256: str
    hash_md5: str
    is_executable: bool
    is_hidden: bool
    created_time: float = 0.0
    accessed_time: float = 0.0


@dataclass
class FileChange:
    """Represents a file change event"""
    path: str
    change_type: str  # 'CREATED', 'MODIFIED', 'DELETED', 'PERMISSIONS'
    timestamp: str
    old_record: Optional[FileRecord] = None
    new_record: Optional[FileRecord] = None
    suspicious_score: float = 0.0
    reasons: List[str] = None
    
    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []


@dataclass
class IntegrityReport:
    """File integrity check report"""
    timestamp: str
    scan_duration: float
    total_files_scanned: int
    changes_detected: int
    suspicious_changes: int
    new_files: int
    modified_files: int
    deleted_files: int
    permission_changes: int
    high_risk_changes: List[FileChange]
    recommendations: List[str]


class FileIntegrityChecker:
    """File system integrity monitoring and analysis"""
    
    def __init__(self, db_path: str = "file_integrity.db"):
        self.db_path = db_path
        self.suspicious_paths = self._load_suspicious_paths()
        self.critical_system_files = self._load_critical_files()
        self.excluded_paths = self._load_excluded_paths()
        self._init_database()
        
    def _load_suspicious_paths(self) -> Set[str]:
        """Load paths that are commonly targeted by malware"""
        if os.name == 'nt':  # Windows
            return {
                'C:\\Windows\\System32\\drivers\\',
                'C:\\Windows\\System32\\',
                'C:\\Users\\*\\AppData\\Roaming\\',
                'C:\\ProgramData\\',
                'C:\\Temp\\',
                'C:\\Windows\\Temp\\'
            }
        else:  # Unix-like
            return {
                '/tmp/',
                '/var/tmp/',
                '/dev/shm/',
                '/usr/bin/',
                '/usr/sbin/',
                '/bin/',
                '/sbin/',
                '/etc/',
                '/home/*/.bashrc',
                '/home/*/.bash_profile',
                '/home/*/.ssh/',
                '/root/.ssh/',
                '/etc/crontab',
                '/var/spool/cron/'
            }
    
    def _load_critical_files(self) -> Set[str]:
        """Load critical system files that should be monitored closely"""
        if os.name == 'nt':  # Windows
            return {
                'C:\\Windows\\System32\\ntoskrnl.exe',
                'C:\\Windows\\System32\\kernel32.dll',
                'C:\\Windows\\System32\\user32.dll',
                'C:\\Windows\\System32\\advapi32.dll',
                'C:\\Windows\\System32\\wininet.dll'
            }
        else:  # Unix-like
            return {
                '/bin/bash',
                '/bin/sh',
                '/usr/bin/sudo',
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/etc/resolv.conf'
            }
    
    def _load_excluded_paths(self) -> Set[str]:
        """Load paths to exclude from monitoring (logs, caches, etc.)"""
        if os.name == 'nt':  # Windows
            return {
                'C:\\Windows\\Logs\\',
                'C:\\Windows\\SoftwareDistribution\\',
                'C:\\Users\\*\\AppData\\Local\\Temp\\'
            }
        else:  # Unix-like
            return {
                '/var/log/',
                '/var/cache/',
                '/proc/',
                '/sys/',
                '/dev/',
                '/tmp/.X11-unix/',
                '/home/*/.cache/'
            }
    
    def _init_database(self) -> None:
        """Initialize SQLite database for storing file records"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_records (
                path TEXT PRIMARY KEY,
                size INTEGER,
                modified_time REAL,
                permissions TEXT,
                owner TEXT,
                hash_sha256 TEXT,
                hash_md5 TEXT,
                is_executable BOOLEAN,
                is_hidden BOOLEAN,
                created_time REAL,
                accessed_time REAL,
                last_checked REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                change_type TEXT,
                timestamp TEXT,
                suspicious_score REAL,
                reasons TEXT,
                old_record TEXT,
                new_record TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _calculate_file_hashes(self, file_path: str) -> Tuple[str, str]:
        """Calculate SHA256 and MD5 hashes for a file"""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            return sha256_hash.hexdigest(), md5_hash.hexdigest()
        except (OSError, PermissionError):
            return "", ""
    
    def _get_file_record(self, file_path: str) -> Optional[FileRecord]:
        """Get file information and create FileRecord"""
        try:
            stat = os.stat(file_path)
            sha256_hash, md5_hash = self._calculate_file_hashes(file_path)
            
            # Get file permissions
            permissions = oct(stat.st_mode)[-3:]
            
            # Get owner (simplified)
            try:
                import pwd
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except (ImportError, KeyError):
                owner = str(stat.st_uid)
            
            return FileRecord(
                path=file_path,
                size=stat.st_size,
                modified_time=stat.st_mtime,
                permissions=permissions,
                owner=owner,
                hash_sha256=sha256_hash,
                hash_md5=md5_hash,
                is_executable=os.access(file_path, os.X_OK),
                is_hidden=os.path.basename(file_path).startswith('.'),
                created_time=stat.st_ctime,
                accessed_time=stat.st_atime
            )
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot access file {file_path}: {e}")
            return None
    
    def _is_path_excluded(self, file_path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        for excluded in self.excluded_paths:
            if '*' in excluded:
                # Simple wildcard matching
                pattern = excluded.replace('*', '')
                if pattern in file_path:
                    return True
            elif file_path.startswith(excluded):
                return True
        return False
    
    def _is_suspicious_path(self, file_path: str) -> bool:
        """Check if file path is in suspicious locations"""
        for suspicious in self.suspicious_paths:
            if '*' in suspicious:
                pattern = suspicious.replace('*', '')
                if pattern in file_path:
                    return True
            elif file_path.startswith(suspicious):
                return True
        return False
    
    def _is_critical_file(self, file_path: str) -> bool:
        """Check if file is critical system file"""
        return file_path in self.critical_system_files
    
    def _calculate_suspicion_score(self, change: FileChange) -> float:
        """Calculate suspicion score for a file change"""
        score = 0.0
        
        # Location-based scoring
        if self._is_suspicious_path(change.path):
            score += 30.0
            change.reasons.append("Located in suspicious directory")
        
        if self._is_critical_file(change.path):
            score += 40.0
            change.reasons.append("Critical system file modified")
        
        # Change type scoring
        if change.change_type == 'CREATED':
            if change.new_record and change.new_record.is_executable:
                score += 25.0
                change.reasons.append("New executable file created")
            
            if change.new_record and change.new_record.is_hidden:
                score += 20.0
                change.reasons.append("Hidden file created")
        
        elif change.change_type == 'MODIFIED':
            if change.old_record and change.new_record:
                # Hash changed
                if change.old_record.hash_sha256 != change.new_record.hash_sha256:
                    score += 20.0
                    change.reasons.append("File content modified")
                
                # Permissions changed
                if change.old_record.permissions != change.new_record.permissions:
                    score += 15.0
                    change.reasons.append("File permissions changed")
                
                # Size significantly changed
                size_diff = abs(change.new_record.size - change.old_record.size)
                if size_diff > 1024 * 1024:  # 1MB
                    score += 10.0
                    change.reasons.append("Significant size change")
        
        # Time-based scoring
        change_time = datetime.fromisoformat(change.timestamp)
        if datetime.now() - change_time < timedelta(hours=1):
            score += 10.0
            change.reasons.append("Recent change")
        
        # File extension scoring
        suspicious_extensions = ['.exe', '.dll', '.so', '.dylib', '.scr', '.bat', '.sh']
        if any(change.path.lower().endswith(ext) for ext in suspicious_extensions):
            score += 15.0
            change.reasons.append("Suspicious file extension")
        
        return min(score, 100.0)
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[FileChange]:
        """Scan directory for file changes"""
        logger.info(f"Scanning directory: {directory}")
        changes = []
        
        if not os.path.exists(directory):
            logger.warning(f"Directory does not exist: {directory}")
            return changes
        
        # Get current files
        current_files = set()
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if not self._is_path_excluded(file_path):
                        current_files.add(file_path)
        else:
            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                if os.path.isfile(file_path) and not self._is_path_excluded(file_path):
                    current_files.add(file_path)
        
        # Get stored file records
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT path FROM file_records WHERE path LIKE ?", (f"{directory}%",))
        stored_files = {row[0] for row in cursor.fetchall()}
        
        # Find new files
        new_files = current_files - stored_files
        for file_path in new_files:
            record = self._get_file_record(file_path)
            if record:
                change = FileChange(
                    path=file_path,
                    change_type='CREATED',
                    timestamp=datetime.now().isoformat(),
                    new_record=record
                )
                change.suspicious_score = self._calculate_suspicion_score(change)
                changes.append(change)
                
                # Store new record
                self._store_file_record(record)
        
        # Find deleted files
        deleted_files = stored_files - current_files
        for file_path in deleted_files:
            old_record = self._get_stored_record(file_path)
            change = FileChange(
                path=file_path,
                change_type='DELETED',
                timestamp=datetime.now().isoformat(),
                old_record=old_record
            )
            change.suspicious_score = self._calculate_suspicion_score(change)
            changes.append(change)
            
            # Remove from database
            cursor.execute("DELETE FROM file_records WHERE path = ?", (file_path,))
        
        # Check modified files
        common_files = current_files & stored_files
        for file_path in common_files:
            current_record = self._get_file_record(file_path)
            stored_record = self._get_stored_record(file_path)
            
            if current_record and stored_record:
                if self._has_file_changed(current_record, stored_record):
                    change = FileChange(
                        path=file_path,
                        change_type='MODIFIED',
                        timestamp=datetime.now().isoformat(),
                        old_record=stored_record,
                        new_record=current_record
                    )
                    change.suspicious_score = self._calculate_suspicion_score(change)
                    changes.append(change)
                    
                    # Update stored record
                    self._store_file_record(current_record)
        
        conn.commit()
        conn.close()
        
        # Store changes
        self._store_changes(changes)
        
        logger.info(f"Found {len(changes)} file changes in {directory}")
        return changes
    
    def _has_file_changed(self, current: FileRecord, stored: FileRecord) -> bool:
        """Check if file has changed significantly"""
        return (
            current.hash_sha256 != stored.hash_sha256 or
            current.size != stored.size or
            current.permissions != stored.permissions or
            abs(current.modified_time - stored.modified_time) > 1.0
        )
    
    def _store_file_record(self, record: FileRecord) -> None:
        """Store file record in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO file_records 
            (path, size, modified_time, permissions, owner, hash_sha256, hash_md5,
             is_executable, is_hidden, created_time, accessed_time, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            record.path, record.size, record.modified_time, record.permissions,
            record.owner, record.hash_sha256, record.hash_md5, record.is_executable,
            record.is_hidden, record.created_time, record.accessed_time, datetime.now().timestamp()
        ))
        
        conn.commit()
        conn.close()
    
    def _get_stored_record(self, file_path: str) -> Optional[FileRecord]:
        """Get stored file record from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM file_records WHERE path = ?", (file_path,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return FileRecord(
                path=row[0], size=row[1], modified_time=row[2], permissions=row[3],
                owner=row[4], hash_sha256=row[5], hash_md5=row[6], is_executable=row[7],
                is_hidden=row[8], created_time=row[9], accessed_time=row[10]
            )
        return None
    
    def _store_changes(self, changes: List[FileChange]) -> None:
        """Store file changes in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for change in changes:
            cursor.execute('''
                INSERT INTO file_changes 
                (path, change_type, timestamp, suspicious_score, reasons, old_record, new_record)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                change.path, change.change_type, change.timestamp, change.suspicious_score,
                json.dumps(change.reasons), 
                json.dumps(asdict(change.old_record)) if change.old_record else None,
                json.dumps(asdict(change.new_record)) if change.new_record else None
            ))
        
        conn.commit()
        conn.close()
    
    def get_recent_changes(self, hours: int = 24) -> List[FileChange]:
        """Get file changes from the last N hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        cursor.execute(
            "SELECT * FROM file_changes WHERE timestamp > ? ORDER BY timestamp DESC",
            (since_time,)
        )
        
        changes = []
        for row in cursor.fetchall():
            change = FileChange(
                path=row[1],
                change_type=row[2],
                timestamp=row[3],
                suspicious_score=row[4],
                reasons=json.loads(row[5]) if row[5] else []
            )
            
            if row[6]:  # old_record
                change.old_record = FileRecord(**json.loads(row[6]))
            if row[7]:  # new_record
                change.new_record = FileRecord(**json.loads(row[7]))
            
            changes.append(change)
        
        conn.close()
        return changes
    
    def generate_integrity_report(self, scan_paths: List[str]) -> IntegrityReport:
        """Generate comprehensive integrity report"""
        logger.info("Generating file integrity report")
        start_time = datetime.now()
        
        all_changes = []
        total_files = 0
        
        # Scan all specified paths
        for path in scan_paths:
            if os.path.exists(path):
                changes = self.scan_directory(path)
                all_changes.extend(changes)
                
                # Count files
                if os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        total_files += len(files)
                else:
                    total_files += 1
        
        # Analyze changes
        suspicious_changes = [c for c in all_changes if c.suspicious_score >= 50.0]
        high_risk_changes = [c for c in all_changes if c.suspicious_score >= 75.0]
        
        new_files = len([c for c in all_changes if c.change_type == 'CREATED'])
        modified_files = len([c for c in all_changes if c.change_type == 'MODIFIED'])
        deleted_files = len([c for c in all_changes if c.change_type == 'DELETED'])
        permission_changes = len([c for c in all_changes if 'permissions changed' in ' '.join(c.reasons)])
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_changes, suspicious_changes)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        report = IntegrityReport(
            timestamp=datetime.now().isoformat(),
            scan_duration=scan_duration,
            total_files_scanned=total_files,
            changes_detected=len(all_changes),
            suspicious_changes=len(suspicious_changes),
            new_files=new_files,
            modified_files=modified_files,
            deleted_files=deleted_files,
            permission_changes=permission_changes,
            high_risk_changes=high_risk_changes[:20],  # Top 20 high-risk changes
            recommendations=recommendations
        )
        
        logger.info(f"Integrity scan completed in {scan_duration:.2f} seconds")
        return report
    
    def _generate_recommendations(self, all_changes: List[FileChange], 
                                suspicious_changes: List[FileChange]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if suspicious_changes:
            recommendations.append("Investigate suspicious file changes immediately")
            recommendations.append("Consider running full antimalware scan")
            
        if any(c.change_type == 'CREATED' and c.new_record and c.new_record.is_executable 
               for c in suspicious_changes):
            recommendations.append("New executable files detected - verify legitimacy")
            
        if any(self._is_critical_file(c.path) for c in all_changes):
            recommendations.append("Critical system files modified - restore from backup if unauthorized")
            
        if len(all_changes) > 100:
            recommendations.append("High volume of file changes detected - investigate potential compromise")
            
        recommendations.extend([
            "Enable real-time file integrity monitoring",
            "Regularly backup critical system files",
            "Implement application whitelisting",
            "Monitor system logs for correlation with file changes",
            "Keep file integrity baseline updated"
        ])
        
        return recommendations
    
    def save_report(self, report: IntegrityReport, filename: str) -> None:
        """Save integrity report to file"""
        with open(filename, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        logger.info(f"Integrity report saved to {filename}")


if __name__ == "__main__":
    # Example usage
    checker = FileIntegrityChecker()
    
    # Define paths to monitor
    if os.name == 'nt':  # Windows
        scan_paths = ['C:\\Windows\\System32', 'C:\\Program Files']
    else:  # Unix-like
        scan_paths = ['/bin', '/usr/bin', '/etc']
    
    print("Starting file integrity scan...")
    report = checker.generate_integrity_report(scan_paths)
    
    print(f"\nScan Results:")
    print(f"Files scanned: {report.total_files_scanned}")
    print(f"Changes detected: {report.changes_detected}")
    print(f"Suspicious changes: {report.suspicious_changes}")
    print(f"High-risk changes: {len(report.high_risk_changes)}")
    
    checker.save_report(report, "file_integrity_report.json")