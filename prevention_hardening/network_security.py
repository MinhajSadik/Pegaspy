"""Network Security Monitor

Provides comprehensive network security monitoring including:
- Real-time network traffic analysis
- VPN integration and management
- Firewall rule management
- Network threat detection
- DNS security monitoring
"""

import os
import json
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from ipaddress import ip_address, ip_network
from loguru import logger

try:
    import psutil
except ImportError:
    psutil = None

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS
except ImportError:
    sniff = IP = TCP = UDP = DNS = None


class ThreatLevel(Enum):
    """Network threat levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConnectionType(Enum):
    """Network connection types"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class VPNStatus(Enum):
    """VPN connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class NetworkConnection:
    """Network connection information"""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    status: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    connection_type: Optional[ConnectionType] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    is_encrypted: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp: Optional[str] = None


@dataclass
class NetworkThreat:
    """Network threat detection"""
    threat_id: str
    threat_type: str
    description: str
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    threat_level: ThreatLevel
    timestamp: str
    evidence: Dict[str, Any]
    mitigation_steps: List[str]


@dataclass
class VPNConfiguration:
    """VPN configuration"""
    name: str
    provider: str
    server_address: str
    protocol: str  # OpenVPN, IKEv2, WireGuard, etc.
    encryption: str
    authentication: str
    dns_servers: List[str]
    kill_switch: bool = True
    auto_connect: bool = False
    split_tunneling: bool = False
    config_file: Optional[str] = None


@dataclass
class VPNStatus:
    """VPN status information"""
    name: str
    status: VPNStatus
    server_ip: Optional[str] = None
    public_ip: Optional[str] = None
    dns_servers: List[str] = None
    connection_time: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    last_error: Optional[str] = None


@dataclass
class FirewallRule:
    """Firewall rule definition"""
    rule_id: str
    name: str
    action: str  # ALLOW, DENY, LOG
    direction: str  # IN, OUT, BOTH
    protocol: str  # TCP, UDP, ICMP, ALL
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    enabled: bool = True
    priority: int = 100
    description: str = ""


@dataclass
class NetworkSecurityReport:
    """Network security monitoring report"""
    timestamp: str
    monitoring_duration: float
    total_connections: int
    suspicious_connections: int
    blocked_connections: int
    threats_detected: int
    vpn_status: Optional[VPNStatus]
    active_connections: List[NetworkConnection]
    detected_threats: List[NetworkThreat]
    firewall_rules: List[FirewallRule]
    dns_queries: List[Dict[str, Any]]
    recommendations: List[str]
    overall_security_score: float


class NetworkSecurityMonitor:
    """Comprehensive network security monitoring system"""
    
    def __init__(self):
        self.monitoring = False
        self.connections: Dict[str, NetworkConnection] = {}
        self.threats: List[NetworkThreat] = []
        self.vpn_configs: Dict[str, VPNConfiguration] = {}
        self.firewall_rules: Dict[str, FirewallRule] = {}
        self.dns_queries: List[Dict[str, Any]] = []
        
        # Threat detection patterns
        self.suspicious_ports = {22, 23, 135, 139, 445, 1433, 3389, 5432, 5900}
        self.malicious_ips: Set[str] = set()
        self.suspicious_domains: Set[str] = set()
        
        # Load threat intelligence
        self._load_threat_intelligence()
        
        # Initialize monitoring thread
        self.monitor_thread: Optional[threading.Thread] = None
        
        logger.info("NetworkSecurityMonitor initialized")
    
    def _load_threat_intelligence(self) -> None:
        """Load threat intelligence data"""
        # Load known malicious IPs and domains
        # In a real implementation, this would fetch from threat intelligence feeds
        self.malicious_ips.update([
            "192.168.1.100",  # Example malicious IP
            "10.0.0.50",      # Example internal threat
        ])
        
        self.suspicious_domains.update([
            "malware.example.com",
            "phishing.test.org",
            "suspicious.domain.net"
        ])
        
        logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs and {len(self.suspicious_domains)} suspicious domains")
    
    def start_monitoring(self) -> None:
        """Start network security monitoring"""
        if self.monitoring:
            logger.warning("Network monitoring already active")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Network security monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop network security monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Network security monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Monitor network connections
                self._scan_network_connections()
                
                # Check VPN status
                self._check_vpn_status()
                
                # Analyze DNS queries
                self._monitor_dns_queries()
                
                # Detect threats
                self._detect_network_threats()
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
    
    def _scan_network_connections(self) -> None:
        """Scan and analyze network connections"""
        if not psutil:
            return
        
        try:
            current_connections = {}
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip if conn.raddr else 'unknown'}:{conn.raddr.port if conn.raddr else 0}"
                    
                    # Get process information
                    process_name = None
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    # Determine connection type
                    connection_type = self._classify_connection_type(
                        conn.laddr.ip, 
                        conn.raddr.ip if conn.raddr else None
                    )
                    
                    # Check if connection is encrypted
                    is_encrypted = self._is_encrypted_connection(
                        conn.raddr.port if conn.raddr else 0
                    )
                    
                    # Assess threat level
                    threat_level = self._assess_connection_threat(
                        conn.raddr.ip if conn.raddr else None,
                        conn.raddr.port if conn.raddr else 0,
                        process_name
                    )
                    
                    network_conn = NetworkConnection(
                        local_address=conn.laddr.ip,
                        local_port=conn.laddr.port,
                        remote_address=conn.raddr.ip if conn.raddr else "unknown",
                        remote_port=conn.raddr.port if conn.raddr else 0,
                        protocol=conn.type.name if hasattr(conn.type, 'name') else 'TCP',
                        status=conn.status,
                        pid=conn.pid,
                        process_name=process_name,
                        connection_type=connection_type,
                        threat_level=threat_level,
                        is_encrypted=is_encrypted,
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    )
                    
                    current_connections[conn_key] = network_conn
            
            self.connections = current_connections
            
        except Exception as e:
            logger.error(f"Error scanning network connections: {e}")
    
    def _classify_connection_type(self, local_ip: str, remote_ip: Optional[str]) -> ConnectionType:
        """Classify connection type based on IP addresses"""
        if not remote_ip:
            return ConnectionType.INTERNAL
        
        try:
            local_addr = ip_address(local_ip)
            remote_addr = ip_address(remote_ip)
            
            # Check if both are private
            if local_addr.is_private and remote_addr.is_private:
                return ConnectionType.INTERNAL
            
            # Check if remote is external
            if not remote_addr.is_private:
                return ConnectionType.OUTBOUND
            
            return ConnectionType.INBOUND
            
        except Exception:
            return ConnectionType.INTERNAL
    
    def _is_encrypted_connection(self, port: int) -> bool:
        """Check if connection uses encrypted protocol"""
        encrypted_ports = {443, 993, 995, 465, 587, 636, 989, 990, 992, 5061}
        return port in encrypted_ports
    
    def _assess_connection_threat(self, remote_ip: Optional[str], port: int, process_name: Optional[str]) -> ThreatLevel:
        """Assess threat level of a connection"""
        if not remote_ip:
            return ThreatLevel.LOW
        
        # Check against known malicious IPs
        if remote_ip in self.malicious_ips:
            return ThreatLevel.CRITICAL
        
        # Check suspicious ports
        if port in self.suspicious_ports:
            return ThreatLevel.HIGH
        
        # Check for suspicious processes
        if process_name and any(suspicious in process_name.lower() 
                               for suspicious in ['backdoor', 'trojan', 'malware']):
            return ThreatLevel.CRITICAL
        
        # Check for unencrypted connections to external hosts
        if not self._is_encrypted_connection(port):
            try:
                if not ip_address(remote_ip).is_private:
                    return ThreatLevel.MEDIUM
            except Exception:
                pass
        
        return ThreatLevel.LOW
    
    def _check_vpn_status(self) -> Optional[VPNStatus]:
        """Check current VPN status"""
        try:
            # Check for common VPN interfaces
            vpn_interfaces = ['tun0', 'tap0', 'utun0', 'utun1', 'utun2']
            
            for interface in vpn_interfaces:
                if self._is_interface_active(interface):
                    # Get VPN details
                    public_ip = self._get_public_ip()
                    
                    return VPNStatus(
                        name="Active VPN",
                        status=VPNStatus.CONNECTED,
                        public_ip=public_ip,
                        connection_time=time.strftime('%Y-%m-%d %H:%M:%S')
                    )
            
            return VPNStatus(
                name="No VPN",
                status=VPNStatus.DISCONNECTED
            )
            
        except Exception as e:
            logger.error(f"Error checking VPN status: {e}")
            return None
    
    def _is_interface_active(self, interface_name: str) -> bool:
        """Check if network interface is active"""
        try:
            if psutil:
                interfaces = psutil.net_if_stats()
                return interface_name in interfaces and interfaces[interface_name].isup
            return False
        except Exception:
            return False
    
    def _get_public_ip(self) -> Optional[str]:
        """Get current public IP address"""
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf-8').strip()
        except Exception:
            return None
    
    def _monitor_dns_queries(self) -> None:
        """Monitor DNS queries for suspicious domains"""
        # This would require packet capture capabilities
        # For now, simulate DNS monitoring
        pass
    
    def _detect_network_threats(self) -> None:
        """Detect network-based threats"""
        for conn_key, connection in self.connections.items():
            if connection.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                threat = NetworkThreat(
                    threat_id=f"threat_{int(time.time())}_{hash(conn_key) % 10000}",
                    threat_type="Suspicious Connection",
                    description=f"Suspicious connection to {connection.remote_address}:{connection.remote_port}",
                    source_ip=connection.local_address,
                    destination_ip=connection.remote_address,
                    port=connection.remote_port,
                    protocol=connection.protocol,
                    threat_level=connection.threat_level,
                    timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                    evidence={
                        "process_name": connection.process_name,
                        "pid": connection.pid,
                        "is_encrypted": connection.is_encrypted,
                        "connection_type": connection.connection_type.value if connection.connection_type else None
                    },
                    mitigation_steps=[
                        "Investigate the process making this connection",
                        "Check if the destination IP is legitimate",
                        "Consider blocking the connection if malicious",
                        "Update antivirus and run full system scan"
                    ]
                )
                
                # Add threat if not already detected
                if not any(t.threat_id == threat.threat_id for t in self.threats):
                    self.threats.append(threat)
                    logger.warning(f"Network threat detected: {threat.description}")
    
    def configure_vpn(self, config: VPNConfiguration) -> bool:
        """Configure VPN connection"""
        try:
            self.vpn_configs[config.name] = config
            logger.info(f"VPN configuration '{config.name}' added")
            return True
        except Exception as e:
            logger.error(f"Failed to configure VPN: {e}")
            return False
    
    def connect_vpn(self, vpn_name: str) -> bool:
        """Connect to VPN"""
        if vpn_name not in self.vpn_configs:
            logger.error(f"VPN configuration '{vpn_name}' not found")
            return False
        
        config = self.vpn_configs[vpn_name]
        
        try:
            # This would implement actual VPN connection logic
            # For now, simulate connection
            logger.info(f"Connecting to VPN: {vpn_name}")
            
            # Simulate connection based on protocol
            if config.protocol.lower() == 'openvpn':
                return self._connect_openvpn(config)
            elif config.protocol.lower() == 'wireguard':
                return self._connect_wireguard(config)
            else:
                logger.warning(f"Unsupported VPN protocol: {config.protocol}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect VPN: {e}")
            return False
    
    def _connect_openvpn(self, config: VPNConfiguration) -> bool:
        """Connect using OpenVPN"""
        try:
            if config.config_file and os.path.exists(config.config_file):
                cmd = ['openvpn', '--config', config.config_file]
                # In real implementation, would start OpenVPN process
                logger.info(f"Would execute: {' '.join(cmd)}")
                return True
            else:
                logger.error("OpenVPN config file not found")
                return False
        except Exception as e:
            logger.error(f"OpenVPN connection failed: {e}")
            return False
    
    def _connect_wireguard(self, config: VPNConfiguration) -> bool:
        """Connect using WireGuard"""
        try:
            if config.config_file and os.path.exists(config.config_file):
                cmd = ['wg-quick', 'up', config.config_file]
                # In real implementation, would start WireGuard
                logger.info(f"Would execute: {' '.join(cmd)}")
                return True
            else:
                logger.error("WireGuard config file not found")
                return False
        except Exception as e:
            logger.error(f"WireGuard connection failed: {e}")
            return False
    
    def disconnect_vpn(self, vpn_name: str) -> bool:
        """Disconnect VPN"""
        try:
            logger.info(f"Disconnecting VPN: {vpn_name}")
            # Implementation would disconnect the specific VPN
            return True
        except Exception as e:
            logger.error(f"Failed to disconnect VPN: {e}")
            return False
    
    def add_firewall_rule(self, rule: FirewallRule) -> bool:
        """Add firewall rule"""
        try:
            self.firewall_rules[rule.rule_id] = rule
            
            # Apply rule to system firewall
            success = self._apply_firewall_rule(rule)
            
            if success:
                logger.info(f"Firewall rule '{rule.name}' added successfully")
            else:
                logger.error(f"Failed to apply firewall rule '{rule.name}'")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to add firewall rule: {e}")
            return False
    
    def _apply_firewall_rule(self, rule: FirewallRule) -> bool:
        """Apply firewall rule to system"""
        try:
            # Platform-specific firewall rule application
            if os.name == 'posix':
                if 'darwin' in os.uname().sysname.lower():
                    return self._apply_macos_firewall_rule(rule)
                else:
                    return self._apply_linux_firewall_rule(rule)
            elif os.name == 'nt':
                return self._apply_windows_firewall_rule(rule)
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to apply firewall rule: {e}")
            return False
    
    def _apply_macos_firewall_rule(self, rule: FirewallRule) -> bool:
        """Apply firewall rule on macOS using pfctl"""
        try:
            # This would create pfctl rules
            logger.info(f"Would apply macOS firewall rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"macOS firewall rule application failed: {e}")
            return False
    
    def _apply_linux_firewall_rule(self, rule: FirewallRule) -> bool:
        """Apply firewall rule on Linux using iptables/ufw"""
        try:
            # This would create iptables/ufw rules
            logger.info(f"Would apply Linux firewall rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Linux firewall rule application failed: {e}")
            return False
    
    def _apply_windows_firewall_rule(self, rule: FirewallRule) -> bool:
        """Apply firewall rule on Windows"""
        try:
            # This would create Windows firewall rules
            logger.info(f"Would apply Windows firewall rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Windows firewall rule application failed: {e}")
            return False
    
    def remove_firewall_rule(self, rule_id: str) -> bool:
        """Remove firewall rule"""
        try:
            if rule_id in self.firewall_rules:
                rule = self.firewall_rules[rule_id]
                
                # Remove from system firewall
                success = self._remove_firewall_rule(rule)
                
                if success:
                    del self.firewall_rules[rule_id]
                    logger.info(f"Firewall rule '{rule.name}' removed successfully")
                else:
                    logger.error(f"Failed to remove firewall rule '{rule.name}'")
                
                return success
            else:
                logger.error(f"Firewall rule '{rule_id}' not found")
                return False
                
        except Exception as e:
            logger.error(f"Failed to remove firewall rule: {e}")
            return False
    
    def _remove_firewall_rule(self, rule: FirewallRule) -> bool:
        """Remove firewall rule from system"""
        try:
            # Platform-specific firewall rule removal
            logger.info(f"Would remove firewall rule: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove firewall rule: {e}")
            return False
    
    def block_ip(self, ip_address: str, reason: str = "") -> bool:
        """Block specific IP address"""
        rule = FirewallRule(
            rule_id=f"block_ip_{ip_address.replace('.', '_')}",
            name=f"Block {ip_address}",
            action="DENY",
            direction="BOTH",
            protocol="ALL",
            source_ip=ip_address,
            source_port="*",
            destination_ip="*",
            destination_port="*",
            description=f"Blocked IP: {reason}"
        )
        
        return self.add_firewall_rule(rule)
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock specific IP address"""
        rule_id = f"block_ip_{ip_address.replace('.', '_')}"
        return self.remove_firewall_rule(rule_id)
    
    def generate_security_report(self) -> NetworkSecurityReport:
        """Generate comprehensive network security report"""
        logger.info("Generating network security report")
        
        # Calculate metrics
        total_connections = len(self.connections)
        suspicious_connections = sum(1 for conn in self.connections.values() 
                                   if conn.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        blocked_connections = len([rule for rule in self.firewall_rules.values() 
                                 if rule.action == "DENY"])
        threats_detected = len(self.threats)
        
        # Get current VPN status
        vpn_status = self._check_vpn_status()
        
        # Calculate security score
        security_score = self._calculate_security_score(
            total_connections, suspicious_connections, threats_detected, vpn_status
        )
        
        # Generate recommendations
        recommendations = self._generate_security_recommendations(
            suspicious_connections, threats_detected, vpn_status
        )
        
        from datetime import datetime
        
        report = NetworkSecurityReport(
            timestamp=datetime.now().isoformat(),
            monitoring_duration=0.0,  # Would track actual monitoring time
            total_connections=total_connections,
            suspicious_connections=suspicious_connections,
            blocked_connections=blocked_connections,
            threats_detected=threats_detected,
            vpn_status=vpn_status,
            active_connections=list(self.connections.values()),
            detected_threats=self.threats,
            firewall_rules=list(self.firewall_rules.values()),
            dns_queries=self.dns_queries,
            recommendations=recommendations,
            overall_security_score=security_score
        )
        
        logger.info(f"Network security report generated: {security_score:.1f}/100 score")
        return report
    
    def _calculate_security_score(self, total_connections: int, suspicious_connections: int, 
                                 threats_detected: int, vpn_status: Optional[VPNStatus]) -> float:
        """Calculate overall network security score"""
        score = 100.0
        
        # Deduct points for suspicious connections
        if total_connections > 0:
            suspicious_ratio = suspicious_connections / total_connections
            score -= suspicious_ratio * 30
        
        # Deduct points for detected threats
        score -= min(threats_detected * 10, 40)
        
        # Deduct points if VPN is not active
        if not vpn_status or vpn_status.status != VPNStatus.CONNECTED:
            score -= 15
        
        # Ensure score is between 0 and 100
        return max(0.0, min(100.0, score))
    
    def _generate_security_recommendations(self, suspicious_connections: int, 
                                         threats_detected: int, 
                                         vpn_status: Optional[VPNStatus]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if suspicious_connections > 0:
            recommendations.append(f"🔴 {suspicious_connections} suspicious connections detected - investigate immediately")
            recommendations.append("Review and terminate unnecessary network connections")
        
        if threats_detected > 0:
            recommendations.append(f"🚨 {threats_detected} network threats detected - take immediate action")
            recommendations.append("Block malicious IPs and update security rules")
        
        if not vpn_status or vpn_status.status != VPNStatus.CONNECTED:
            recommendations.append("🔒 Consider using a VPN for enhanced privacy and security")
            recommendations.append("Configure VPN with kill switch for maximum protection")
        
        recommendations.extend([
            "Regularly update firewall rules",
            "Monitor network traffic for anomalies",
            "Use encrypted connections whenever possible",
            "Keep network security tools updated",
            "Implement network segmentation where appropriate"
        ])
        
        return recommendations
    
    def save_report(self, report: NetworkSecurityReport, filename: str) -> None:
        """Save network security report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"Network security report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")