"""Network Traffic Analyzer

Monitor and analyze network communications to detect suspicious data transmissions,
command & control communications, and data exfiltration attempts.
"""

import time
import json
import socket
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

import psutil
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from loguru import logger


@dataclass
class NetworkFlow:
    """Represents a network flow between two endpoints"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    suspicious_score: float = 0.0
    flags: List[str] = None
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = []


@dataclass
class DNSQuery:
    """DNS query information"""
    timestamp: float
    query_name: str
    query_type: str
    response_ip: Optional[str] = None
    suspicious: bool = False
    reason: str = ""


@dataclass
class NetworkAlert:
    """Network security alert"""
    timestamp: str
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    evidence: Dict


class NetworkTrafficAnalyzer:
    """Network traffic analyzer for detecting suspicious communications"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.flows = {}
        self.dns_queries = deque(maxlen=1000)
        self.alerts = []
        self.suspicious_domains = self._load_suspicious_domains()
        self.suspicious_ips = self._load_suspicious_ips()
        self.baseline_traffic = defaultdict(int)
        self.monitoring = False
        self.packet_count = 0
        
    def _load_suspicious_domains(self) -> Set[str]:
        """Load known suspicious domains"""
        return {
            'malware-c2.com',
            'suspicious-domain.net',
            'data-exfil.org',
            'spyware-command.io',
            'pegasus-c2.net',
            'nso-group.com',
            'cellebrite.com',
            'grayshift.com'
        }
    
    def _load_suspicious_ips(self) -> Set[str]:
        """Load known suspicious IP addresses"""
        return {
            '192.168.100.1',  # Example suspicious IPs
            '10.0.0.100',
            '172.16.0.100'
        }
    
    def start_monitoring(self, duration: Optional[int] = None) -> None:
        """Start network traffic monitoring"""
        logger.info(f"Starting network monitoring on interface: {self.interface or 'all'}")
        self.monitoring = True
        
        def stop_monitoring():
            if duration:
                time.sleep(duration)
                self.stop_monitoring()
        
        if duration:
            threading.Thread(target=stop_monitoring, daemon=True).start()
        
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.monitoring,
                store=False
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.monitoring = False
    
    def stop_monitoring(self) -> None:
        """Stop network traffic monitoring"""
        logger.info("Stopping network monitoring")
        self.monitoring = False
    
    def _process_packet(self, packet) -> None:
        """Process captured network packet"""
        self.packet_count += 1
        
        if IP in packet:
            self._analyze_ip_packet(packet)
        
        if DNS in packet:
            self._analyze_dns_packet(packet)
    
    def _analyze_ip_packet(self, packet) -> None:
        """Analyze IP packet for suspicious activity"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Determine protocol and ports
        protocol = "Unknown"
        src_port = dst_port = 0
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Create flow key
        flow_key = self._create_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        # Update or create flow
        if flow_key not in self.flows:
            self.flows[flow_key] = NetworkFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                first_seen=time.time()
            )
        
        flow = self.flows[flow_key]
        flow.last_seen = time.time()
        flow.packets_sent += 1
        flow.bytes_sent += len(packet)
        
        # Analyze for suspicious patterns
        self._check_suspicious_patterns(flow, packet)
    
    def _analyze_dns_packet(self, packet) -> None:
        """Analyze DNS packet for suspicious queries"""
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
            query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            query_type = packet[DNS].qd.qtype
            
            dns_query = DNSQuery(
                timestamp=time.time(),
                query_name=query_name,
                query_type=self._get_dns_type_name(query_type)
            )
            
            # Check if domain is suspicious
            if self._is_suspicious_domain(query_name):
                dns_query.suspicious = True
                dns_query.reason = "Known malicious domain"
                
                self._create_alert(
                    "DNS_SUSPICIOUS_DOMAIN",
                    "HIGH",
                    packet[IP].src,
                    "DNS_SERVER",
                    f"Query to suspicious domain: {query_name}",
                    {"domain": query_name, "query_type": dns_query.query_type}
                )
            
            self.dns_queries.append(dns_query)
    
    def is_suspicious_ip(self, ip: str) -> bool:
        """Check if an IP address is suspicious"""
        return ip in self.suspicious_ips
    
    def _create_flow_key(self, src_ip: str, dst_ip: str, src_port: int, 
                        dst_port: int, protocol: str) -> str:
        """Create unique flow identifier"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{protocol}"
    
    def _check_suspicious_patterns(self, flow: NetworkFlow, packet) -> None:
        """Check flow for suspicious patterns"""
        # Check for suspicious IPs
        if flow.dst_ip in self.suspicious_ips:
            flow.flags.append("SUSPICIOUS_DESTINATION")
            flow.suspicious_score += 30.0
            
            self._create_alert(
                "SUSPICIOUS_IP_COMMUNICATION",
                "HIGH",
                flow.src_ip,
                flow.dst_ip,
                f"Communication with known suspicious IP: {flow.dst_ip}",
                {"flow": asdict(flow)}
            )
        
        # Check for unusual ports
        suspicious_ports = [4444, 5555, 6666, 8080, 9999, 31337]
        if flow.dst_port in suspicious_ports:
            flow.flags.append("SUSPICIOUS_PORT")
            flow.suspicious_score += 20.0
        
        # Check for high data volume (potential exfiltration)
        if flow.bytes_sent > 10 * 1024 * 1024:  # 10MB
            flow.flags.append("HIGH_DATA_VOLUME")
            flow.suspicious_score += 25.0
            
            self._create_alert(
                "POTENTIAL_DATA_EXFILTRATION",
                "MEDIUM",
                flow.src_ip,
                flow.dst_ip,
                f"High data volume detected: {flow.bytes_sent} bytes",
                {"bytes_sent": flow.bytes_sent, "flow": asdict(flow)}
            )
        
        # Check for encrypted payload patterns
        if Raw in packet:
            payload = packet[Raw].load
            if self._is_likely_encrypted(payload):
                flow.flags.append("ENCRYPTED_PAYLOAD")
                flow.suspicious_score += 15.0
        
        # Check for beaconing behavior
        if self._is_beaconing_behavior(flow):
            flow.flags.append("BEACONING")
            flow.suspicious_score += 35.0
            
            self._create_alert(
                "BEACONING_DETECTED",
                "HIGH",
                flow.src_ip,
                flow.dst_ip,
                "Regular beaconing behavior detected (potential C2 communication)",
                {"flow": asdict(flow)}
            )
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        domain_lower = domain.lower()
        
        # Check against known suspicious domains
        if domain_lower in self.suspicious_domains:
            return True
        
        # Check for domain generation algorithm patterns
        if self._is_dga_domain(domain_lower):
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
            return True
        
        return False
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain matches DGA patterns"""
        # Simple heuristics for DGA detection
        if len(domain) > 20:  # Very long domains
            return True
        
        # High ratio of consonants to vowels
        vowels = 'aeiou'
        consonants = sum(1 for c in domain if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in domain if c in vowels)
        
        if vowel_count > 0 and consonants / vowel_count > 3:
            return True
        
        return False
    
    def _is_likely_encrypted(self, payload: bytes) -> bool:
        """Check if payload is likely encrypted"""
        if len(payload) < 16:
            return False
        
        # Check entropy (simplified)
        byte_counts = [0] * 256
        for byte in payload:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / len(payload)
                entropy -= p * (p.bit_length() - 1)
        
        return entropy > 7.0  # High entropy suggests encryption
    
    def _is_beaconing_behavior(self, flow: NetworkFlow) -> bool:
        """Check for regular beaconing patterns"""
        # Simple check: regular intervals between packets
        if flow.packets_sent < 5:
            return False
        
        # Check if communication happens at regular intervals
        duration = flow.last_seen - flow.first_seen
        if duration > 0:
            avg_interval = duration / flow.packets_sent
            # If packets are sent at very regular intervals (within 10% variance)
            return 30 <= avg_interval <= 300  # Between 30 seconds and 5 minutes
        
        return False
    
    def _get_dns_type_name(self, qtype: int) -> str:
        """Get DNS query type name"""
        dns_types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
            12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'
        }
        return dns_types.get(qtype, f'TYPE{qtype}')
    
    def _create_alert(self, alert_type: str, severity: str, src_ip: str,
                     dst_ip: str, description: str, evidence: Dict) -> None:
        """Create security alert"""
        alert = NetworkAlert(
            timestamp=datetime.now().isoformat(),
            alert_type=alert_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            description=description,
            evidence=evidence
        )
        
        self.alerts.append(alert)
        logger.warning(f"ALERT [{severity}] {alert_type}: {description}")
    
    def get_suspicious_flows(self, threshold: float = 50.0) -> List[NetworkFlow]:
        """Get flows with suspicion score above threshold"""
        return [flow for flow in self.flows.values() if flow.suspicious_score >= threshold]
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top communicating IP addresses"""
        ip_bytes = defaultdict(int)
        
        for flow in self.flows.values():
            ip_bytes[flow.src_ip] += flow.bytes_sent
            ip_bytes[flow.dst_ip] += flow.bytes_received
        
        return sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_dns_analysis(self) -> Dict:
        """Get DNS query analysis"""
        total_queries = len(self.dns_queries)
        suspicious_queries = sum(1 for q in self.dns_queries if q.suspicious)
        
        # Top queried domains
        domain_counts = defaultdict(int)
        for query in self.dns_queries:
            domain_counts[query.query_name] += 1
        
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_queries': total_queries,
            'suspicious_queries': suspicious_queries,
            'top_domains': top_domains,
            'suspicious_percentage': (suspicious_queries / total_queries * 100) if total_queries > 0 else 0
        }
    
    def generate_report(self) -> Dict:
        """Generate comprehensive network analysis report"""
        suspicious_flows = self.get_suspicious_flows()
        top_talkers = self.get_top_talkers()
        dns_analysis = self.get_dns_analysis()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'monitoring_duration': time.time() - min(flow.first_seen for flow in self.flows.values()) if self.flows else 0,
            'total_packets': self.packet_count,
            'total_flows': len(self.flows),
            'suspicious_flows': len(suspicious_flows),
            'alerts': len(self.alerts),
            'top_talkers': top_talkers,
            'dns_analysis': dns_analysis,
            'suspicious_flows_detail': [asdict(flow) for flow in suspicious_flows[:10]],
            'recent_alerts': [asdict(alert) for alert in self.alerts[-10:]]
        }
    
    def save_report(self, filename: str) -> None:
        """Save analysis report to file"""
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Network analysis report saved to {filename}")


if __name__ == "__main__":
    # Example usage
    analyzer = NetworkTrafficAnalyzer()
    
    print("Starting network monitoring for 60 seconds...")
    analyzer.start_monitoring(duration=60)
    
    # Generate and save report
    report = analyzer.generate_report()
    print(f"\nMonitoring completed:")
    print(f"Total packets: {report['total_packets']}")
    print(f"Total flows: {report['total_flows']}")
    print(f"Suspicious flows: {report['suspicious_flows']}")
    print(f"Alerts generated: {report['alerts']}")
    
    analyzer.save_report("network_analysis_report.json")