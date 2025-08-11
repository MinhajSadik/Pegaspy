#!/usr/bin/env python3
"""
Enhanced Network Surveillance Implementation
Real-time network monitoring and packet analysis
For authorized security research only.
"""

import asyncio
import os
import time
import threading
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Set
import json
import logging

# Network monitoring dependencies
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class NetworkSurveillanceEngine:
    """Enhanced network surveillance with real packet capture"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.logger = self._setup_logging()
        self.active_sessions = {}
        self.captured_packets = []
        self.suspicious_activity = []
        
        # Network interfaces
        self.available_interfaces = self._get_network_interfaces()
        
        self._ensure_directories()
        self.logger.info("Network Surveillance Engine initialized")
    
    def _default_config(self) -> Dict:
        return {
            'capture_interface': None,  # Auto-detect
            'capture_filter': '',  # BPF filter
            'packet_limit': 10000,
            'capture_timeout': 300,  # 5 minutes
            'output_format': 'pcap',
            'real_time_analysis': True,
            'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389, 5432, 6379],
            'monitor_dns': True,
            'monitor_http': True,
            'alert_threshold': 100,  # packets per minute
        }
    
    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('network_surveillance')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            os.makedirs('surveillance', exist_ok=True)
            handler = logging.FileHandler('surveillance/network_surveillance.log')
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _ensure_directories(self):
        """Ensure output directories exist"""
        directories = [
            'surveillance/network',
            'surveillance/packets',
            'surveillance/alerts'
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        interfaces = []
        
        if SCAPY_AVAILABLE:
            try:
                for iface in scapy.get_if_list():
                    interfaces.append(iface)
            except:
                pass
        
        if PSUTIL_AVAILABLE:
            try:
                for iface_name, iface_info in psutil.net_if_addrs().items():
                    if iface_name not in interfaces:
                        interfaces.append(iface_name)
            except:
                pass
        
        return interfaces
    
    async def start_packet_capture(self, interface: Optional[str] = None, 
                                 duration: Optional[float] = None) -> str:
        """Start real packet capture using Scapy"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")
        
        session_id = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output_path = f"surveillance/packets/{session_id}.pcap"
        
        # Auto-detect interface if not specified
        if interface is None:
            interface = self._get_best_interface()
        
        if interface not in self.available_interfaces:
            raise ValueError(f"Interface {interface} not available")
        
        self.logger.info(f"Starting packet capture on {interface}: {session_id}")
        
        # Start capture in background thread
        capture_thread = threading.Thread(
            target=self._packet_capture_worker,
            args=(interface, output_path, duration)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        self.active_sessions[session_id] = {
            'type': 'packet_capture',
            'interface': interface,
            'thread': capture_thread,
            'output_path': output_path,
            'start_time': datetime.now(),
            'active': True,
            'packets_captured': 0
        }
        
        return session_id
    
    def _get_best_interface(self) -> str:
        """Get the best network interface for monitoring"""
        # Prefer wireless or ethernet interfaces
        preferred = ['wlan0', 'wlp0s20f3', 'eth0', 'enp0s3', 'en0', 'Wi-Fi']
        
        for iface in preferred:
            if iface in self.available_interfaces:
                return iface
        
        # Return first available interface
        if self.available_interfaces:
            return self.available_interfaces[0]
        
        raise RuntimeError("No network interfaces available")
    
    def _packet_capture_worker(self, interface: str, output_path: str, duration: Optional[float]):
        """Worker thread for packet capture"""
        captured_count = 0
        suspicious_count = 0
        start_time = time.time()
        
        # Real packet capture using Scapy
        def packet_handler(packet):
            nonlocal captured_count, suspicious_count
            
            captured_count += 1
            
            # Store packet for analysis
            self.captured_packets.append({
                'timestamp': datetime.now().isoformat(),
                'packet_summary': str(packet.summary()),
                'packet_size': len(packet),
                'protocol': self._get_packet_protocol(packet)
            })
            
            # Real-time analysis
            if self.config['real_time_analysis']:
                if self._analyze_packet_suspicious(packet):
                    suspicious_count += 1
                    self._log_suspicious_activity(packet, captured_count)
            
            # Update session stats
            for session in self.active_sessions.values():
                if session.get('type') == 'packet_capture' and session.get('active'):
                    session['packets_captured'] = captured_count
            
            # Log progress every 100 packets
            if captured_count % 100 == 0:
                self.logger.info(f"Captured {captured_count} packets ({suspicious_count} suspicious)")
        
        try:
            # Start packet capture with Scapy
            if duration:
                scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    timeout=duration,
                    store=False
                )
            else:
                scapy.sniff(
                    iface=interface,
                    prn=packet_handler,
                    count=self.config['packet_limit'],
                    store=False
                )
                
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
        finally:
            # Save captured packet data
            self._save_packet_analysis(output_path.replace('.pcap', '_analysis.json'))
            self.logger.info(f"Packet capture completed: {captured_count} packets ({suspicious_count} suspicious)")
    
    def _get_packet_protocol(self, packet) -> str:
        """Determine packet protocol"""
        if packet.haslayer(TCP):
            return f"TCP/{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            return f"UDP/{packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(IP):
            return f"IP/{packet[IP].proto}"
        else:
            return "Unknown"
    
    def _analyze_packet_suspicious(self, packet) -> bool:
        """Analyze packet for suspicious activity"""
        suspicious = False
        
        # Check for suspicious ports
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            if port in self.config['suspicious_ports']:
                suspicious = True
        elif packet.haslayer(UDP):
            port = packet[UDP].dport  
            if port in self.config['suspicious_ports']:
                suspicious = True
        
        # Check for DNS queries to suspicious domains
        if packet.haslayer(DNS) and self.config['monitor_dns']:
            dns_query = packet[DNS].qd
            if dns_query and hasattr(dns_query, 'qname'):
                domain = dns_query.qname.decode()
                if self._is_suspicious_domain(domain):
                    suspicious = True
        
        # Check for HTTP requests
        if packet.haslayer(HTTPRequest) and self.config['monitor_http']:
            http_host = packet[HTTPRequest].Host
            if http_host and self._is_suspicious_domain(http_host.decode()):
                suspicious = True
        
        return suspicious
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        suspicious_indicators = [
            '.tk', '.ml', '.cf', '.ga',  # Free TLD abuse
            'tempmail', 'guerrillamail',  # Temporary email
            'bit.ly', 'tinyurl',  # URL shorteners
            'torrent', 'pirate'  # P2P indicators
        ]
        
        domain_lower = domain.lower()
        return any(indicator in domain_lower for indicator in suspicious_indicators)
    
    def _log_suspicious_activity(self, packet, packet_number: int):
        """Log suspicious network activity"""
        activity = {
            'timestamp': datetime.now().isoformat(),
            'packet_number': packet_number,
            'summary': str(packet.summary()),
            'protocol': self._get_packet_protocol(packet),
            'size': len(packet)
        }
        
        # Add specific details based on protocol
        if packet.haslayer(IP):
            activity['src_ip'] = packet[IP].src
            activity['dst_ip'] = packet[IP].dst
        
        if packet.haslayer(TCP):
            activity['src_port'] = packet[TCP].sport
            activity['dst_port'] = packet[TCP].dport
            activity['tcp_flags'] = packet[TCP].flags
        
        if packet.haslayer(UDP):
            activity['src_port'] = packet[UDP].sport
            activity['dst_port'] = packet[UDP].dport
        
        self.suspicious_activity.append(activity)
        
        # Save alert if threshold exceeded
        if len(self.suspicious_activity) >= self.config['alert_threshold']:
            self._save_alert(f"High suspicious activity: {len(self.suspicious_activity)} events")
    
    def _save_packet_analysis(self, output_path: str):
        """Save packet analysis results"""
        analysis_data = {
            'capture_info': {
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(self.captured_packets),
                'suspicious_packets': len(self.suspicious_activity),
                'analysis_duration': time.time()
            },
            'captured_packets': self.captured_packets[-1000:],  # Last 1000 packets
            'suspicious_activity': self.suspicious_activity,
            'protocol_distribution': self._get_protocol_distribution(),
            'top_destinations': self._get_top_destinations()
        }
        
        with open(output_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        
        self.logger.info(f"Packet analysis saved: {output_path}")
    
    def _get_protocol_distribution(self) -> Dict[str, int]:
        """Get distribution of protocols in captured packets"""
        protocols = {}
        for packet_info in self.captured_packets:
            protocol = packet_info['protocol']
            protocols[protocol] = protocols.get(protocol, 0) + 1
        return protocols
    
    def _get_top_destinations(self) -> List[Dict]:
        """Get top destination addresses from suspicious activity"""
        destinations = {}
        for activity in self.suspicious_activity:
            if 'dst_ip' in activity:
                dst = activity['dst_ip']
                destinations[dst] = destinations.get(dst, 0) + 1
        
        return [
            {'ip': ip, 'count': count} 
            for ip, count in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _save_alert(self, message: str):
        """Save security alert"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'network_suspicious_activity',
            'message': message,
            'details': {
                'total_suspicious': len(self.suspicious_activity),
                'recent_activity': self.suspicious_activity[-10:]  # Last 10 events
            }
        }
        
        alert_file = f"surveillance/alerts/network_alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(alert_file, 'w') as f:
            json.dump(alert_data, f, indent=2)
        
        self.logger.warning(f"Network alert saved: {alert_file}")
    
    async def start_connection_monitoring(self) -> str:
        """Start monitoring network connections using psutil"""
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil not available for connection monitoring")
        
        session_id = f"connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output_path = f"surveillance/network/{session_id}_connections.json"
        
        self.logger.info(f"Starting connection monitoring: {session_id}")
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self._connection_monitor_worker,
            args=(output_path,)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        self.active_sessions[session_id] = {
            'type': 'connection_monitor',
            'thread': monitor_thread,
            'output_path': output_path,
            'start_time': datetime.now(),
            'active': True
        }
        
        return session_id
    
    def _connection_monitor_worker(self, output_path: str):
        """Worker thread for connection monitoring"""
        connection_history = []
        
        try:
            while True:
                session_still_active = any(
                    session.get('active', False) and session['type'] == 'connection_monitor'
                    for session in self.active_sessions.values()
                )
                
                if not session_still_active:
                    break
                
                timestamp = datetime.now().isoformat()
                
                # Get current connections
                connections = []
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == psutil.CONN_ESTABLISHED:
                        try:
                            # Get process info
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = proc.name() if proc else 'Unknown'
                            
                            connections.append({
                                'timestamp': timestamp,
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status,
                                'pid': conn.pid,
                                'process_name': proc_name,
                                'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                                'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                
                # Check for new/suspicious connections
                new_connections = self._detect_new_connections(connections, connection_history)
                if new_connections:
                    self.logger.info(f"Detected {len(new_connections)} new connections")
                    for conn in new_connections:
                        if self._is_suspicious_connection(conn):
                            self._save_alert(f"Suspicious connection detected: {conn['remote_address']} by {conn['process_name']}")
                
                connection_history.append({
                    'timestamp': timestamp,
                    'connections': connections,
                    'connection_count': len(connections)
                })
                
                # Save data periodically
                if len(connection_history) >= 20:  # Save every 20 samples
                    with open(output_path, 'w') as f:
                        json.dump(connection_history, f, indent=2)
                    connection_history = connection_history[-100:]  # Keep last 100 samples
                
                time.sleep(5)  # Check every 5 seconds
                
        except Exception as e:
            self.logger.error(f"Connection monitoring error: {e}")
        finally:
            # Save final data
            with open(output_path, 'w') as f:
                json.dump(connection_history, f, indent=2)
            self.logger.info(f"Connection monitoring data saved: {output_path}")
    
    def _detect_new_connections(self, current_connections: List[Dict], 
                               history: List[Dict]) -> List[Dict]:
        """Detect new connections compared to previous samples"""
        if not history:
            return current_connections
        
        # Get the most recent connections from history
        previous_connections = history[-1]['connections'] if history else []
        previous_addresses = {conn['remote_address'] for conn in previous_connections}
        
        # Find new connections
        new_connections = [
            conn for conn in current_connections 
            if conn['remote_address'] not in previous_addresses
        ]
        
        return new_connections
    
    def _is_suspicious_connection(self, connection: Dict) -> bool:
        """Check if connection is suspicious"""
        # Check remote port
        if connection.get('remote_address'):
            try:
                _, port_str = connection['remote_address'].split(':')
                port = int(port_str)
                if port in self.config['suspicious_ports']:
                    return True
            except:
                pass
        
        # Check process name
        proc_name = connection.get('process_name', '').lower()
        suspicious_processes = ['tor', 'i2p', 'freenet', 'bitcoin', 'monero']
        if any(suspicious_proc in proc_name for suspicious_proc in suspicious_processes):
            return True
        
        return False
    
    async def stop_surveillance(self, session_id: str) -> bool:
        """Stop specific network surveillance session"""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        session_type = session['type']
        
        self.logger.info(f"Stopping network surveillance: {session_id} ({session_type})")
        
        try:
            session['active'] = False
            
            # Remove from active sessions
            del self.active_sessions[session_id]
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping session {session_id}: {e}")
            return False
    
    def stop_all_surveillance(self) -> int:
        """Stop all active network surveillance sessions"""
        session_ids = list(self.active_sessions.keys())
        stopped_count = 0
        
        for session_id in session_ids:
            if asyncio.run(self.stop_surveillance(session_id)):
                stopped_count += 1
        
        self.logger.info(f"Stopped {stopped_count} network surveillance sessions")
        return stopped_count
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Get available network surveillance capabilities"""
        return {
            'packet_capture': SCAPY_AVAILABLE,
            'connection_monitoring': PSUTIL_AVAILABLE,
            'real_time_analysis': SCAPY_AVAILABLE,
            'protocol_analysis': SCAPY_AVAILABLE,
            'dns_monitoring': SCAPY_AVAILABLE,
            'http_monitoring': SCAPY_AVAILABLE
        }
    
    def get_active_sessions(self) -> Dict:
        """Get information about active network surveillance sessions"""
        return {
            session_id: {
                'type': session['type'],
                'start_time': session['start_time'].isoformat(),
                'output_path': session['output_path'],
                'packets_captured': session.get('packets_captured', 0)
            }
            for session_id, session in self.active_sessions.items()
        }
    
    def get_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        return self.available_interfaces


# Test function
async def main():
    print("🌐 Enhanced Network Surveillance Engine Test")
    print("=" * 50)
    
    engine = NetworkSurveillanceEngine()
    capabilities = engine.get_capabilities()
    interfaces = engine.get_interfaces()
    
    print("\n📋 Available Capabilities:")
    for capability, available in capabilities.items():
        status = "✅" if available else "❌"
        print(f"   {status} {capability.replace('_', ' ').title()}")
    
    print(f"\n🔌 Available Network Interfaces: {interfaces}")
    
    if not any(capabilities.values()):
        print("\n❌ No network surveillance capabilities available")
        print("   Install: pip install scapy psutil")
        return
    
    print("\n⚠️  Starting network surveillance tests...")
    print("   This will monitor real network traffic!")
    
    active_sessions = []
    
    try:
        # Test connection monitoring if available
        if capabilities['connection_monitoring']:
            print("\n🔗 Starting connection monitoring...")
            conn_session = await engine.start_connection_monitoring()
            active_sessions.append(conn_session)
            print(f"   ✅ Connection session: {conn_session}")
        
        # Test packet capture if available (requires root/admin)
        if capabilities['packet_capture']:
            print("\n📡 Starting packet capture (may require sudo)...")
            try:
                packet_session = await engine.start_packet_capture(duration=10.0)
                active_sessions.append(packet_session)
                print(f"   ✅ Packet session: {packet_session}")
            except Exception as e:
                print(f"   ❌ Packet capture failed: {e}")
                print("   Note: Packet capture typically requires administrator privileges")
        
        print(f"\n📊 Active Sessions: {len(active_sessions)}")
        for session_id, info in engine.get_active_sessions().items():
            print(f"   • {session_id}: {info['type']}")
        
        print("\n⏳ Monitoring network activity for 15 seconds...")
        await asyncio.sleep(15)
        
    finally:
        print("\n🛑 Stopping all network surveillance...")
        stopped = engine.stop_all_surveillance()
        print(f"   ✅ Stopped {stopped} sessions")
        
        print("\n📄 Check surveillance/network/ directory for captured data")
        print("⚠️  Network data contains sensitive information - handle carefully")

if __name__ == "__main__":
    asyncio.run(main())
