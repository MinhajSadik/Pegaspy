"""Mobile Device Scanner

Forensic analysis tools for iOS and Android devices to detect suspicious processes,
unauthorized modifications, and potential spyware infections.
"""

import os
import json
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

import psutil
from loguru import logger


@dataclass
class ProcessInfo:
    """Information about a running process"""
    pid: int
    name: str
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    create_time: float
    connections: List[Dict]
    suspicious_score: float = 0.0


@dataclass
class ScanResult:
    """Results from a device scan"""
    timestamp: str
    device_type: str
    total_processes: int
    suspicious_processes: List[ProcessInfo]
    network_connections: List[Dict]
    file_modifications: List[Dict]
    threat_level: str
    recommendations: List[str]


class MobileDeviceScanner:
    """Mobile device forensic scanner for spyware detection"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.baseline_processes = set()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load scanner configuration"""
        default_config = {
            "scan_interval": 60,
            "cpu_threshold": 80.0,
            "memory_threshold": 70.0,
            "network_monitoring": True,
            "file_monitoring": True,
            "log_level": "INFO"
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
                
        return default_config
    
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate suspicious behavior"""
        return {
            "process_names": [
                "keylogger", "spyware", "trojan", "backdoor",
                "pegasus", "cellebrite", "graykey", "msab"
            ],
            "network_domains": [
                "suspicious-domain.com", "malware-c2.net",
                "data-exfil.org", "spyware-command.io"
            ],
            "file_paths": [
                "/tmp/", "/var/tmp/", "/dev/shm/",
                "/.hidden", "/system/bin/su", "/system/xbin/"
            ],
            "suspicious_ports": [4444, 5555, 6666, 8080, 9999]
        }
    
    def scan_processes(self) -> List[ProcessInfo]:
        """Scan running processes for suspicious activity"""
        logger.info("Starting process scan...")
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
            try:
                proc_info = proc.info
                connections = self._get_process_connections(proc)
                
                process = ProcessInfo(
                    pid=proc_info['pid'],
                    name=proc_info['name'] or 'Unknown',
                    cmdline=proc_info['cmdline'] or [],
                    cpu_percent=proc_info['cpu_percent'] or 0.0,
                    memory_percent=proc_info['memory_percent'] or 0.0,
                    create_time=proc_info['create_time'] or 0.0,
                    connections=connections
                )
                
                # Calculate suspicion score
                process.suspicious_score = self._calculate_suspicion_score(process)
                processes.append(process)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        logger.info(f"Scanned {len(processes)} processes")
        return processes
    
    def _get_process_connections(self, proc: psutil.Process) -> List[Dict]:
        """Get network connections for a process"""
        connections = []
        try:
            for conn in proc.connections():
                connections.append({
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return connections
    
    def _calculate_suspicion_score(self, process: ProcessInfo) -> float:
        """Calculate suspicion score for a process"""
        score = 0.0
        
        # Check process name against suspicious patterns
        for pattern in self.suspicious_patterns['process_names']:
            if pattern.lower() in process.name.lower():
                score += 30.0
                
        # Check command line arguments
        cmdline_str = ' '.join(process.cmdline).lower()
        for pattern in self.suspicious_patterns['process_names']:
            if pattern in cmdline_str:
                score += 20.0
                
        # High resource usage
        if process.cpu_percent > self.config['cpu_threshold']:
            score += 15.0
        if process.memory_percent > self.config['memory_threshold']:
            score += 15.0
            
        # Suspicious network connections
        for conn in process.connections:
            if conn['raddr']:
                try:
                    port = int(conn['raddr'].split(':')[1])
                    if port in self.suspicious_patterns['suspicious_ports']:
                        score += 25.0
                except (ValueError, IndexError):
                    pass
                    
        # Recently created processes
        if datetime.now().timestamp() - process.create_time < 3600:  # Last hour
            score += 10.0
            
        return min(score, 100.0)  # Cap at 100
    
    def scan_network_connections(self) -> List[Dict]:
        """Scan network connections for suspicious activity"""
        logger.info("Scanning network connections...")
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:  # Only external connections
                connection_info = {
                    'pid': conn.pid,
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'status': conn.status,
                    'suspicious': self._is_suspicious_connection(conn)
                }
                connections.append(connection_info)
                
        logger.info(f"Found {len(connections)} network connections")
        return connections
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if a network connection is suspicious"""
        if not conn.raddr:
            return False
            
        # Check suspicious ports
        if conn.raddr.port in self.suspicious_patterns['suspicious_ports']:
            return True
            
        # Check suspicious IP ranges (example: private IPs connecting externally)
        remote_ip = conn.raddr.ip
        if remote_ip.startswith(('10.', '172.', '192.168.')):
            return False  # Internal network, likely safe
            
        return False
    
    def scan_file_integrity(self, paths: List[str]) -> List[Dict]:
        """Scan file system for unauthorized modifications"""
        logger.info("Scanning file integrity...")
        modifications = []
        
        for path in paths:
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            file_hash = self._calculate_file_hash(file_path)
                            
                            file_info = {
                                'path': file_path,
                                'size': stat.st_size,
                                'modified_time': stat.st_mtime,
                                'hash': file_hash,
                                'suspicious': self._is_suspicious_file(file_path)
                            }
                            
                            if file_info['suspicious']:
                                modifications.append(file_info)
                                
                        except (OSError, PermissionError):
                            continue
                            
        logger.info(f"Found {len(modifications)} suspicious file modifications")
        return modifications
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (OSError, PermissionError):
            return ""
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if a file path is suspicious"""
        for pattern in self.suspicious_patterns['file_paths']:
            if pattern in file_path:
                return True
        return False
    
    def perform_full_scan(self, scan_paths: Optional[List[str]] = None) -> ScanResult:
        """Perform a comprehensive device scan"""
        logger.info("Starting full device scan...")
        
        if scan_paths is None:
            scan_paths = ['/tmp', '/var/tmp', '/home'] if os.name != 'nt' else ['C:\\Temp', 'C:\\Users']
        
        # Scan processes
        processes = self.scan_processes()
        suspicious_processes = [p for p in processes if p.suspicious_score > 50.0]
        
        # Scan network connections
        network_connections = self.scan_network_connections()
        
        # Scan file integrity
        file_modifications = self.scan_file_integrity(scan_paths)
        
        # Determine threat level
        threat_level = self._determine_threat_level(
            len(suspicious_processes),
            len([c for c in network_connections if c['suspicious']]),
            len(file_modifications)
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            suspicious_processes, network_connections, file_modifications
        )
        
        result = ScanResult(
            timestamp=datetime.now().isoformat(),
            device_type="Mobile/Desktop",
            total_processes=len(processes),
            suspicious_processes=suspicious_processes,
            network_connections=network_connections,
            file_modifications=file_modifications,
            threat_level=threat_level,
            recommendations=recommendations
        )
        
        logger.info(f"Scan completed. Threat level: {threat_level}")
        return result
    
    def _determine_threat_level(self, suspicious_procs: int, suspicious_conns: int, file_mods: int) -> str:
        """Determine overall threat level"""
        total_score = suspicious_procs * 3 + suspicious_conns * 2 + file_mods
        
        if total_score >= 10:
            return "HIGH"
        elif total_score >= 5:
            return "MEDIUM"
        elif total_score >= 1:
            return "LOW"
        else:
            return "CLEAN"
    
    def _generate_recommendations(self, processes: List[ProcessInfo], 
                                connections: List[Dict], modifications: List[Dict]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        if processes:
            recommendations.append("Investigate suspicious processes and consider terminating if confirmed malicious")
            recommendations.append("Run additional malware scans with updated signatures")
            
        if any(c['suspicious'] for c in connections):
            recommendations.append("Monitor network traffic for data exfiltration")
            recommendations.append("Consider blocking suspicious network connections")
            
        if modifications:
            recommendations.append("Restore modified system files from clean backups")
            recommendations.append("Enable file integrity monitoring")
            
        if not recommendations:
            recommendations.append("System appears clean, continue regular monitoring")
            
        recommendations.extend([
            "Keep operating system and applications updated",
            "Use strong, unique passwords and enable 2FA",
            "Avoid clicking suspicious links or downloading unknown files",
            "Regular security scans and monitoring"
        ])
        
        return recommendations
    
    def save_scan_results(self, result: ScanResult, output_path: str) -> None:
        """Save scan results to file"""
        with open(output_path, 'w') as f:
            json.dump(result.__dict__, f, indent=2, default=str)
        logger.info(f"Scan results saved to {output_path}")


if __name__ == "__main__":
    # Example usage
    scanner = MobileDeviceScanner()
    result = scanner.perform_full_scan()
    
    print(f"Scan completed at {result.timestamp}")
    print(f"Threat Level: {result.threat_level}")
    print(f"Suspicious Processes: {len(result.suspicious_processes)}")
    print(f"Network Connections: {len(result.network_connections)}")
    print(f"File Modifications: {len(result.file_modifications)}")
    
    # Save results
    scanner.save_scan_results(result, "scan_results.json")