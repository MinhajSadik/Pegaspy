"""Behavioral Analysis Engine

Monitor process behaviors and patterns to detect suspicious activities that could
indicate spyware, keyloggers, or other malicious software.
"""

import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

import psutil
from loguru import logger


@dataclass
class ProcessBehavior:
    """Process behavior metrics"""
    pid: int
    name: str
    cmdline: List[str]
    start_time: float
    cpu_usage_history: List[float]
    memory_usage_history: List[float]
    network_connections: List[Dict]
    file_operations: List[Dict]
    registry_operations: List[Dict]  # Windows only
    child_processes: List[int]
    parent_pid: int
    user: str
    suspicious_score: float = 0.0
    behavioral_flags: List[str] = None
    
    def __post_init__(self):
        if self.behavioral_flags is None:
            self.behavioral_flags = []


@dataclass
class BehavioralAlert:
    """Behavioral analysis alert"""
    timestamp: str
    alert_type: str
    severity: str
    process_name: str
    pid: int
    description: str
    evidence: Dict
    confidence: float


@dataclass
class BehavioralReport:
    """Behavioral analysis report"""
    timestamp: str
    monitoring_duration: float
    processes_monitored: int
    alerts_generated: int
    high_risk_processes: List[ProcessBehavior]
    behavioral_patterns: Dict[str, int]
    recommendations: List[str]


class BehavioralAnalysisEngine:
    """Engine for analyzing process behaviors and detecting suspicious patterns"""
    
    def __init__(self, monitoring_interval: float = 5.0):
        self.monitoring_interval = monitoring_interval
        self.process_behaviors = {}
        self.alerts = []
        self.monitoring = False
        self.start_time = None
        
        # Behavioral pattern definitions
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.keylogger_indicators = self._load_keylogger_indicators()
        self.spyware_indicators = self._load_spyware_indicators()
        
        # Baseline metrics
        self.baseline_cpu_usage = 0.0
        self.baseline_memory_usage = 0.0
        self.baseline_network_activity = 0.0
        
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate suspicious behavior"""
        return {
            'process_names': [
                'keylogger', 'spyware', 'trojan', 'backdoor', 'rootkit',
                'pegasus', 'cellebrite', 'graykey', 'msab', 'oxygen'
            ],
            'suspicious_cmdline': [
                'powershell -enc', 'cmd /c echo', 'certutil -decode',
                'bitsadmin /transfer', 'regsvr32 /s /u', 'rundll32 javascript:',
                'wmic process call create', 'schtasks /create'
            ],
            'network_indicators': [
                'raw socket', 'packet capture', 'network sniffing',
                'traffic interception', 'ssl mitm'
            ],
            'file_indicators': [
                'temp file creation', 'hidden file access', 'system file modification',
                'registry modification', 'startup modification'
            ]
        }
    
    def _load_keylogger_indicators(self) -> Dict[str, any]:
        """Load indicators specific to keylogger detection"""
        return {
            'api_calls': [
                'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
                'RegisterHotKey', 'GetForegroundWindow', 'GetWindowText'
            ],
            'file_patterns': [
                'keylog', 'keystroke', 'keyboard', 'input_log',
                'keys.txt', 'log.dat', 'capture.log'
            ],
            'registry_keys': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            ],
            'behavioral_patterns': {
                'low_cpu_high_persistence': True,
                'hidden_window_operations': True,
                'frequent_keyboard_polling': True,
                'encrypted_log_files': True
            }
        }
    
    def _load_spyware_indicators(self) -> Dict[str, any]:
        """Load indicators specific to spyware detection"""
        return {
            'data_collection': [
                'screenshot capture', 'camera access', 'microphone access',
                'location tracking', 'contact extraction', 'sms reading'
            ],
            'communication_patterns': [
                'regular beaconing', 'data exfiltration', 'command reception',
                'encrypted communication', 'tor usage', 'proxy usage'
            ],
            'persistence_mechanisms': [
                'service installation', 'startup modification', 'scheduled task',
                'dll injection', 'process hollowing', 'registry persistence'
            ],
            'evasion_techniques': [
                'process name spoofing', 'digital signature bypass',
                'anti-debugging', 'vm detection', 'sandbox evasion'
            ]
        }
    
    def start_monitoring(self) -> None:
        """Start behavioral monitoring"""
        logger.info("Starting behavioral analysis monitoring")
        self.monitoring = True
        self.start_time = time.time()
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        # Establish baseline
        self._establish_baseline()
    
    def stop_monitoring(self) -> None:
        """Stop behavioral monitoring"""
        logger.info("Stopping behavioral analysis monitoring")
        self.monitoring = False
    
    def collect_process_behaviors(self) -> List[ProcessBehavior]:
        """Collect current process behaviors (public interface)"""
        self._collect_process_behaviors()
        return list(self.process_behaviors.values())
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._collect_process_behaviors()
                self._analyze_behaviors()
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)
    
    def _establish_baseline(self) -> None:
        """Establish baseline system metrics"""
        logger.info("Establishing baseline metrics")
        
        cpu_samples = []
        memory_samples = []
        network_samples = []
        
        for _ in range(10):  # Sample for 50 seconds
            cpu_samples.append(psutil.cpu_percent())
            memory_samples.append(psutil.virtual_memory().percent)
            
            # Network activity
            net_io = psutil.net_io_counters()
            network_samples.append(net_io.bytes_sent + net_io.bytes_recv)
            
            time.sleep(5)
        
        self.baseline_cpu_usage = sum(cpu_samples) / len(cpu_samples)
        self.baseline_memory_usage = sum(memory_samples) / len(memory_samples)
        
        # Calculate network baseline (bytes per second)
        if len(network_samples) > 1:
            network_diff = network_samples[-1] - network_samples[0]
            self.baseline_network_activity = network_diff / (len(network_samples) * 5)
        
        logger.info(f"Baseline established - CPU: {self.baseline_cpu_usage:.1f}%, "
                   f"Memory: {self.baseline_memory_usage:.1f}%, "
                   f"Network: {self.baseline_network_activity:.0f} bytes/s")
    
    def _collect_process_behaviors(self) -> None:
        """Collect current process behaviors"""
        current_time = time.time()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 
                                       'memory_percent', 'create_time', 'ppid', 'username']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']
                
                # Get or create process behavior record
                if pid not in self.process_behaviors:
                    self.process_behaviors[pid] = ProcessBehavior(
                        pid=pid,
                        name=proc_info['name'] or 'Unknown',
                        cmdline=proc_info['cmdline'] or [],
                        start_time=proc_info['create_time'] or current_time,
                        cpu_usage_history=[],
                        memory_usage_history=[],
                        network_connections=[],
                        file_operations=[],
                        registry_operations=[],
                        child_processes=[],
                        parent_pid=proc_info['ppid'] or 0,
                        user=proc_info['username'] or 'Unknown'
                    )
                
                behavior = self.process_behaviors[pid]
                
                # Update metrics
                behavior.cpu_usage_history.append(proc_info['cpu_percent'] or 0.0)
                behavior.memory_usage_history.append(proc_info['memory_percent'] or 0.0)
                
                # Keep only recent history (last 100 samples)
                if len(behavior.cpu_usage_history) > 100:
                    behavior.cpu_usage_history.pop(0)
                if len(behavior.memory_usage_history) > 100:
                    behavior.memory_usage_history.pop(0)
                
                # Collect network connections
                try:
                    connections = []
                    for conn in proc.connections():
                        connections.append({
                            'family': conn.family.name,
                            'type': conn.type.name,
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'status': conn.status,
                            'timestamp': current_time
                        })
                    behavior.network_connections = connections
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Collect child processes
                try:
                    children = [child.pid for child in proc.children()]
                    behavior.child_processes = children
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Remove dead processes
                if pid in self.process_behaviors:
                    del self.process_behaviors[pid]
                continue
    
    def _analyze_behaviors(self) -> None:
        """Analyze collected behaviors for suspicious patterns"""
        for pid, behavior in self.process_behaviors.items():
            # Reset flags and score for re-analysis
            behavior.behavioral_flags = []
            behavior.suspicious_score = 0.0
            
            # Analyze different behavioral aspects
            self._analyze_resource_usage(behavior)
            self._analyze_network_behavior(behavior)
            self._analyze_process_characteristics(behavior)
            self._analyze_persistence_indicators(behavior)
            self._analyze_keylogger_behavior(behavior)
            self._analyze_spyware_behavior(behavior)
            
            # Generate alerts for high-risk behaviors
            if behavior.suspicious_score >= 70.0:
                self._generate_behavioral_alert(behavior, "HIGH")
            elif behavior.suspicious_score >= 50.0:
                self._generate_behavioral_alert(behavior, "MEDIUM")
    
    def _analyze_resource_usage(self, behavior: ProcessBehavior) -> None:
        """Analyze resource usage patterns"""
        if not behavior.cpu_usage_history or not behavior.memory_usage_history:
            return
        
        avg_cpu = sum(behavior.cpu_usage_history) / len(behavior.cpu_usage_history)
        avg_memory = sum(behavior.memory_usage_history) / len(behavior.memory_usage_history)
        
        # High CPU usage
        if avg_cpu > 80.0:
            behavior.behavioral_flags.append("HIGH_CPU_USAGE")
            behavior.suspicious_score += 15.0
        
        # High memory usage
        if avg_memory > 70.0:
            behavior.behavioral_flags.append("HIGH_MEMORY_USAGE")
            behavior.suspicious_score += 15.0
        
        # Unusual resource patterns
        if len(behavior.cpu_usage_history) >= 10:
            # Check for consistent low CPU (typical of keyloggers)
            recent_cpu = behavior.cpu_usage_history[-10:]
            if all(cpu < 5.0 for cpu in recent_cpu) and avg_cpu < 2.0:
                behavior.behavioral_flags.append("PERSISTENT_LOW_CPU")
                behavior.suspicious_score += 20.0
            
            # Check for CPU spikes (potential data processing)
            max_cpu = max(behavior.cpu_usage_history)
            if max_cpu > 90.0 and avg_cpu < 20.0:
                behavior.behavioral_flags.append("CPU_SPIKES")
                behavior.suspicious_score += 10.0
    
    def _analyze_network_behavior(self, behavior: ProcessBehavior) -> None:
        """Analyze network communication patterns"""
        if not behavior.network_connections:
            return
        
        # Check for suspicious network patterns
        external_connections = [conn for conn in behavior.network_connections 
                              if conn['remote_address'] and not self._is_local_address(conn['remote_address'])]
        
        if external_connections:
            behavior.behavioral_flags.append("EXTERNAL_NETWORK_ACCESS")
            behavior.suspicious_score += 10.0
            
            # Check for multiple external connections
            if len(external_connections) > 5:
                behavior.behavioral_flags.append("MULTIPLE_EXTERNAL_CONNECTIONS")
                behavior.suspicious_score += 15.0
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 8080, 9999, 31337]
            for conn in external_connections:
                if conn['remote_address']:
                    try:
                        port = int(conn['remote_address'].split(':')[1])
                        if port in suspicious_ports:
                            behavior.behavioral_flags.append("SUSPICIOUS_PORT_USAGE")
                            behavior.suspicious_score += 25.0
                            break
                    except (ValueError, IndexError):
                        pass
    
    def _analyze_process_characteristics(self, behavior: ProcessBehavior) -> None:
        """Analyze process characteristics"""
        # Check process name against suspicious patterns
        name_lower = behavior.name.lower()
        for pattern in self.suspicious_patterns['process_names']:
            if pattern in name_lower:
                behavior.behavioral_flags.append("SUSPICIOUS_PROCESS_NAME")
                behavior.suspicious_score += 30.0
                break
        
        # Check command line arguments
        cmdline_str = ' '.join(behavior.cmdline).lower()
        for pattern in self.suspicious_patterns['suspicious_cmdline']:
            if pattern in cmdline_str:
                behavior.behavioral_flags.append("SUSPICIOUS_CMDLINE")
                behavior.suspicious_score += 25.0
                break
        
        # Check for process hiding techniques
        if behavior.name == '' or len(behavior.name) == 1:
            behavior.behavioral_flags.append("PROCESS_NAME_HIDING")
            behavior.suspicious_score += 20.0
        
        # Check for unusual parent-child relationships
        if behavior.parent_pid == 0 and behavior.pid != 1:  # Orphaned process
            behavior.behavioral_flags.append("ORPHANED_PROCESS")
            behavior.suspicious_score += 15.0
        
        # Check for many child processes (potential process injection)
        if len(behavior.child_processes) > 10:
            behavior.behavioral_flags.append("MANY_CHILD_PROCESSES")
            behavior.suspicious_score += 10.0
    
    def _analyze_persistence_indicators(self, behavior: ProcessBehavior) -> None:
        """Analyze persistence mechanisms"""
        # Check process age (very old processes might be persistent malware)
        current_time = time.time()
        process_age = current_time - behavior.start_time
        
        if process_age > 86400:  # Running for more than 24 hours
            behavior.behavioral_flags.append("LONG_RUNNING_PROCESS")
            behavior.suspicious_score += 5.0
        
        # Check for processes started at unusual times
        start_hour = datetime.fromtimestamp(behavior.start_time).hour
        if start_hour < 6 or start_hour > 22:  # Started during night hours
            behavior.behavioral_flags.append("UNUSUAL_START_TIME")
            behavior.suspicious_score += 10.0
    
    def _analyze_keylogger_behavior(self, behavior: ProcessBehavior) -> None:
        """Analyze for keylogger-specific behaviors"""
        # Check for keylogger file patterns
        for pattern in self.keylogger_indicators['file_patterns']:
            if pattern in behavior.name.lower() or any(pattern in arg.lower() for arg in behavior.cmdline):
                behavior.behavioral_flags.append("KEYLOGGER_FILE_PATTERN")
                behavior.suspicious_score += 35.0
                break
        
        # Check for low CPU with persistence (typical keylogger behavior)
        if ("PERSISTENT_LOW_CPU" in behavior.behavioral_flags and 
            "LONG_RUNNING_PROCESS" in behavior.behavioral_flags):
            behavior.behavioral_flags.append("KEYLOGGER_BEHAVIOR_PATTERN")
            behavior.suspicious_score += 25.0
    
    def _analyze_spyware_behavior(self, behavior: ProcessBehavior) -> None:
        """Analyze for spyware-specific behaviors"""
        # Check for data collection indicators
        for indicator in self.spyware_indicators['data_collection']:
            cmdline_str = ' '.join(behavior.cmdline).lower()
            if indicator in cmdline_str or indicator in behavior.name.lower():
                behavior.behavioral_flags.append("DATA_COLLECTION_INDICATOR")
                behavior.suspicious_score += 30.0
                break
        
        # Check for communication patterns
        if ("EXTERNAL_NETWORK_ACCESS" in behavior.behavioral_flags and 
            "PERSISTENT_LOW_CPU" in behavior.behavioral_flags):
            behavior.behavioral_flags.append("SPYWARE_COMMUNICATION_PATTERN")
            behavior.suspicious_score += 20.0
    
    def _is_local_address(self, address: str) -> bool:
        """Check if address is local/private"""
        if not address:
            return True
        
        ip = address.split(':')[0]
        return (ip.startswith('127.') or ip.startswith('192.168.') or 
                ip.startswith('10.') or ip.startswith('172.') or ip == 'localhost')
    
    def _generate_behavioral_alert(self, behavior: ProcessBehavior, severity: str) -> None:
        """Generate behavioral analysis alert"""
        alert_type = "SUSPICIOUS_BEHAVIOR"
        
        # Determine specific alert type based on flags
        if "KEYLOGGER_BEHAVIOR_PATTERN" in behavior.behavioral_flags:
            alert_type = "POTENTIAL_KEYLOGGER"
        elif "SPYWARE_COMMUNICATION_PATTERN" in behavior.behavioral_flags:
            alert_type = "POTENTIAL_SPYWARE"
        elif "SUSPICIOUS_PROCESS_NAME" in behavior.behavioral_flags:
            alert_type = "SUSPICIOUS_PROCESS"
        
        description = f"Suspicious behavior detected in process {behavior.name} (PID: {behavior.pid})"
        if behavior.behavioral_flags:
            description += f". Flags: {', '.join(behavior.behavioral_flags)}"
        
        alert = BehavioralAlert(
            timestamp=datetime.now().isoformat(),
            alert_type=alert_type,
            severity=severity,
            process_name=behavior.name,
            pid=behavior.pid,
            description=description,
            evidence={
                'suspicious_score': behavior.suspicious_score,
                'behavioral_flags': behavior.behavioral_flags,
                'cmdline': behavior.cmdline,
                'network_connections': len(behavior.network_connections),
                'avg_cpu': sum(behavior.cpu_usage_history) / len(behavior.cpu_usage_history) if behavior.cpu_usage_history else 0,
                'avg_memory': sum(behavior.memory_usage_history) / len(behavior.memory_usage_history) if behavior.memory_usage_history else 0
            },
            confidence=min(behavior.suspicious_score / 100.0, 1.0)
        )
        
        self.alerts.append(alert)
        logger.warning(f"BEHAVIORAL ALERT [{severity}] {alert_type}: {description}")
    
    def get_high_risk_processes(self, threshold: float = 70.0) -> List[ProcessBehavior]:
        """Get processes with high suspicious scores"""
        return [behavior for behavior in self.process_behaviors.values() 
                if behavior.suspicious_score >= threshold]
    
    def get_behavioral_patterns(self) -> Dict[str, int]:
        """Get summary of behavioral patterns detected"""
        patterns = defaultdict(int)
        
        for behavior in self.process_behaviors.values():
            for flag in behavior.behavioral_flags:
                patterns[flag] += 1
        
        return dict(patterns)
    
    def generate_behavioral_report(self) -> BehavioralReport:
        """Generate comprehensive behavioral analysis report"""
        monitoring_duration = time.time() - self.start_time if self.start_time else 0
        high_risk_processes = self.get_high_risk_processes()
        behavioral_patterns = self.get_behavioral_patterns()
        
        # Generate recommendations
        recommendations = self._generate_recommendations(high_risk_processes, behavioral_patterns)
        
        report = BehavioralReport(
            timestamp=datetime.now().isoformat(),
            monitoring_duration=monitoring_duration,
            processes_monitored=len(self.process_behaviors),
            alerts_generated=len(self.alerts),
            high_risk_processes=high_risk_processes[:20],  # Top 20 high-risk processes
            behavioral_patterns=behavioral_patterns,
            recommendations=recommendations
        )
        
        return report
    
    def _generate_recommendations(self, high_risk_processes: List[ProcessBehavior], 
                                patterns: Dict[str, int]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if high_risk_processes:
            recommendations.append("Investigate high-risk processes immediately")
            recommendations.append("Consider terminating suspicious processes after verification")
        
        if patterns.get('KEYLOGGER_BEHAVIOR_PATTERN', 0) > 0:
            recommendations.append("Potential keylogger detected - scan for credential theft")
        
        if patterns.get('SPYWARE_COMMUNICATION_PATTERN', 0) > 0:
            recommendations.append("Potential spyware detected - check for data exfiltration")
        
        if patterns.get('EXTERNAL_NETWORK_ACCESS', 0) > 10:
            recommendations.append("High external network activity - monitor for data leaks")
        
        recommendations.extend([
            "Enable real-time behavioral monitoring",
            "Implement application whitelisting",
            "Monitor network traffic for anomalies",
            "Regular behavioral baseline updates",
            "Deploy endpoint detection and response (EDR) solutions"
        ])
        
        return recommendations
    
    def save_report(self, report: BehavioralReport, filename: str) -> None:
        """Save behavioral report to file"""
        with open(filename, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        logger.info(f"Behavioral analysis report saved to {filename}")


if __name__ == "__main__":
    # Example usage
    engine = BehavioralAnalysisEngine(monitoring_interval=2.0)
    
    print("Starting behavioral analysis for 60 seconds...")
    engine.start_monitoring()
    
    # Monitor for 60 seconds
    time.sleep(60)
    engine.stop_monitoring()
    
    # Generate report
    report = engine.generate_behavioral_report()
    
    print(f"\nBehavioral Analysis Results:")
    print(f"Monitoring duration: {report.monitoring_duration:.1f} seconds")
    print(f"Processes monitored: {report.processes_monitored}")
    print(f"Alerts generated: {report.alerts_generated}")
    print(f"High-risk processes: {len(report.high_risk_processes)}")
    
    if report.behavioral_patterns:
        print(f"\nTop behavioral patterns:")
        for pattern, count in sorted(report.behavioral_patterns.items(), 
                                   key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {pattern}: {count}")
    
    engine.save_report(report, "behavioral_analysis_report.json")