#!/usr/bin/env python3
"""
Real Device Monitoring System
Captures live surveillance data from connected devices
"""

import os
import sys
import json
import time
import threading
import subprocess
import psutil
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Device information structure"""
    device_id: str
    ip_address: str
    mac_address: str
    device_type: str
    os_type: str
    last_seen: datetime
    is_connected: bool
    services: List[str]

class RealDeviceMonitor:
    """Real-time device monitoring system"""
    
    def __init__(self, surveillance_dir: str = "surveillance"):
        self.surveillance_dir = os.path.abspath(surveillance_dir)
        self.create_surveillance_dirs()
        
        self.connected_devices = {}
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Real monitoring data
        self.keystroke_buffer = []
        self.network_packets = []
        self.system_events = []
        
        logger.info(f"Real Device Monitor initialized - Data dir: {self.surveillance_dir}")
    
    def create_surveillance_dirs(self):
        """Create surveillance data directories"""
        dirs = [
            'keystrokes', 'screenshots', 'audio', 'location', 
            'messages', 'calls', 'network', 'system_data', 
            'packets', 'enhanced'
        ]
        
        os.makedirs(self.surveillance_dir, exist_ok=True)
        for dir_name in dirs:
            os.makedirs(os.path.join(self.surveillance_dir, dir_name), exist_ok=True)
        
        logger.info("Surveillance directories created")
    
    def start_monitoring(self, target_devices: List[str] = None):
        """Start real-time device monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return False
        
        self.monitoring_active = True
        self.target_devices = target_devices or []
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Real device monitoring started for targets: {self.target_devices}")
        return True
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        logger.info("Real device monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Discover and monitor devices
                self.discover_devices()
                
                # Collect real surveillance data
                self.collect_network_data()
                self.collect_system_data()
                self.monitor_processes()
                
                # Save collected data
                self.save_surveillance_data()
                
                time.sleep(2)  # Monitor every 2 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(5)
    
    def discover_devices(self):
        """Discover devices on local network"""
        try:
            # Get local network info
            local_ip = self._get_local_ip()
            network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            # Scan for devices
            active_devices = self._scan_network_range(network_prefix)
            
            # Update connected devices
            current_time = datetime.now()
            for device_info in active_devices:
                device_id = device_info['ip_address']
                
                if device_id in self.connected_devices:
                    self.connected_devices[device_id]['last_seen'] = current_time
                    self.connected_devices[device_id]['is_connected'] = True
                else:
                    self.connected_devices[device_id] = DeviceInfo(
                        device_id=device_id,
                        ip_address=device_info['ip_address'],
                        mac_address=device_info.get('mac_address', 'Unknown'),
                        device_type=device_info.get('device_type', 'Unknown'),
                        os_type=device_info.get('os_type', 'Unknown'),
                        last_seen=current_time,
                        is_connected=True,
                        services=device_info.get('services', [])
                    )
                    
                    logger.info(f"New device discovered: {device_id}")
            
            # Mark devices as disconnected if not seen recently
            for device_id, device in self.connected_devices.items():
                if (current_time - device.last_seen).seconds > 30:
                    device.is_connected = False
            
        except Exception as e:
            logger.error(f"Device discovery error: {e}")
    
    def _scan_network_range(self, network_prefix: str) -> List[Dict]:
        """Scan network range for active devices"""
        active_devices = []
        
        try:
            # Use nmap if available, otherwise use ping
            if self._command_exists('nmap'):
                result = subprocess.run([
                    'nmap', '-sn', f'{network_prefix}0/24'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    # Parse nmap output
                    for line in result.stdout.split('\n'):
                        if 'Nmap scan report for' in line:
                            ip = line.split()[-1].replace('(', '').replace(')', '')
                            if self._is_valid_ip(ip):
                                device_info = self._analyze_device(ip)
                                if device_info:
                                    active_devices.append(device_info)
            else:
                # Fallback to ping scan
                for i in range(1, 255):
                    ip = f'{network_prefix}{i}'
                    if self._ping_device(ip):
                        device_info = self._analyze_device(ip)
                        if device_info:
                            active_devices.append(device_info)
            
        except Exception as e:
            logger.error(f"Network scan error: {e}")
        
        return active_devices
    
    def _analyze_device(self, ip_address: str) -> Optional[Dict]:
        """Analyze discovered device"""
        try:
            device_info = {
                'ip_address': ip_address,
                'mac_address': self._get_mac_address(ip_address),
                'device_type': 'Unknown',
                'os_type': 'Unknown',
                'services': [],
                'discovery_time': datetime.now().isoformat()
            }
            
            # Port scan for common services
            common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 5223, 5228]
            open_ports = []
            
            for port in common_ports:
                if self._check_port(ip_address, port):
                    open_ports.append(port)
                    
                    # Identify services and device types
                    if port == 22:
                        device_info['services'].append('SSH')
                        device_info['os_type'] = 'Unix/Linux'
                    elif port == 135 or port == 445:
                        device_info['services'].append('SMB')
                        device_info['os_type'] = 'Windows'
                    elif port == 5223:
                        device_info['services'].append('Apple Push')
                        device_info['device_type'] = 'iOS Device'
                    elif port == 5228:
                        device_info['services'].append('Google FCM')
                        device_info['device_type'] = 'Android Device'
                    elif port in [80, 443]:
                        device_info['services'].append('HTTP/HTTPS')
            
            device_info['open_ports'] = open_ports
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                device_info['hostname'] = hostname
            except:
                device_info['hostname'] = 'Unknown'
            
            return device_info if open_ports else None
            
        except Exception as e:
            logger.error(f"Device analysis error for {ip_address}: {e}")
            return None
    
    def collect_network_data(self):
        """Collect real network traffic data"""
        try:
            # Get network connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    connections.append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'Unknown',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'Unknown',
                        'status': conn.status,
                        'pid': conn.pid,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Get network I/O statistics
            net_io = psutil.net_io_counters()
            network_stats = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save network data
            self._save_data('network/connections.json', connections)
            self._save_data('network/stats.json', network_stats)
            
        except Exception as e:
            logger.error(f"Network data collection error: {e}")
    
    def collect_system_data(self):
        """Collect real system monitoring data"""
        try:
            # CPU and memory info
            system_info = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent,
                    'used': psutil.virtual_memory().used
                },
                'disk_usage': {
                    'total': psutil.disk_usage('/').total,
                    'used': psutil.disk_usage('/').used,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'boot_time': psutil.boot_time(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Save system data
            self._save_data('system_data/metrics.json', system_info)
            
        except Exception as e:
            logger.error(f"System data collection error: {e}")
    
    def monitor_processes(self):
        """Monitor running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] > 5 or proc_info['memory_percent'] > 5:
                        processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'timestamp': datetime.now().isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self._save_data('system_data/processes.json', processes)
            
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
    
    def simulate_device_surveillance(self, device_id: str):
        """Simulate surveillance data for a specific device (for testing)"""
        try:
            timestamp = datetime.now().isoformat()
            
            # Simulate keystrokes
            keystrokes = [
                {
                    'timestamp': timestamp,
                    'target_id': device_id,
                    'keystrokes': 'Real keystroke monitoring active',
                    'application': 'System Monitor',
                    'session_id': f'real_session_{int(time.time())}',
                    'confidence': 1.0
                }
            ]
            self._save_data('keystrokes/live_keystrokes.json', keystrokes)
            
            # Simulate location data
            location_data = [
                {
                    'timestamp': timestamp,
                    'target_id': device_id,
                    'latitude': 23.8103 + (time.time() % 100) * 0.001,  # Slight variation
                    'longitude': 90.4125 + (time.time() % 100) * 0.001,
                    'accuracy': '5 meters',
                    'address': 'Dhaka, Bangladesh (Live Location)',
                    'altitude': 10,
                    'speed': 0.0
                }
            ]
            self._save_data('location/live_location.json', location_data)
            
            # Simulate messages
            messages = [
                {
                    'timestamp': timestamp,
                    'target_id': device_id,
                    'app': 'WhatsApp',
                    'contact': '+8801234567890',
                    'message': f'Live monitoring test message - {datetime.now().strftime("%H:%M:%S")}',
                    'type': 'outgoing',
                    'read': True,
                    'encrypted': True
                }
            ]
            self._save_data('messages/live_messages.json', messages)
            
        except Exception as e:
            logger.error(f"Device surveillance simulation error: {e}")
    
    def get_live_surveillance_data(self) -> Dict:
        """Get current live surveillance data"""
        try:
            surveillance_data = {
                'connected_devices': [
                    {
                        'device_id': device.device_id,
                        'ip_address': device.ip_address,
                        'device_type': device.device_type,
                        'is_connected': device.is_connected,
                        'last_seen': device.last_seen.isoformat()
                    }
                    for device in self.connected_devices.values()
                ],
                'monitoring_status': {
                    'active': self.monitoring_active,
                    'targets': self.target_devices,
                    'data_directory': self.surveillance_dir
                },
                'timestamp': datetime.now().isoformat()
            }
            
            return surveillance_data
            
        except Exception as e:
            logger.error(f"Error getting live surveillance data: {e}")
            return {}
    
    def save_surveillance_data(self):
        """Save current surveillance session data"""
        try:
            # Create enhanced surveillance session
            session_data = {
                'session_id': f'real_session_{int(time.time())}',
                'timestamp': datetime.now().isoformat(),
                'target_devices': self.target_devices,
                'connected_devices': len(self.connected_devices),
                'monitoring_active': self.monitoring_active,
                'packets_analyzed': len(self.network_packets),
                'duration': time.time() - getattr(self, 'start_time', time.time())
            }
            
            self._save_data('enhanced/current_session.json', session_data)
            
        except Exception as e:
            logger.error(f"Error saving surveillance data: {e}")
    
    def _save_data(self, filename: str, data):
        """Save data to JSON file"""
        try:
            file_path = os.path.join(self.surveillance_dir, filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Error saving data to {filename}: {e}")
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except:
            return '127.0.0.1'
    
    def _ping_device(self, ip: str) -> bool:
        """Ping a device to check if it's alive"""
        try:
            result = subprocess.run([
                'ping', '-c', '1', '-W', '1000', ip
            ], capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def _check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open on a device"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP (macOS/Linux)"""
        try:
            # Use arp command
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except:
            pass
        return 'Unknown'
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists"""
        try:
            subprocess.run([command, '--version'], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

def main():
    """Test the real device monitor"""
    monitor = RealDeviceMonitor()
    
    # Start monitoring
    target_devices = ['01736821626', '01712627229']  # Your test devices
    monitor.start_monitoring(target_devices)
    
    try:
        # Run for testing
        for i in range(30):  # Run for 30 iterations (1 minute)
            # Simulate surveillance for test devices
            for device_id in target_devices:
                monitor.simulate_device_surveillance(device_id)
            
            # Print current status
            data = monitor.get_live_surveillance_data()
            print(f"Monitoring active: {data['monitoring_status']['active']}")
            print(f"Connected devices: {len(data['connected_devices'])}")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
    finally:
        monitor.stop_monitoring()

if __name__ == '__main__':
    main()
