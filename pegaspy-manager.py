#!/usr/bin/env python3
"""
PegaSpy Application Manager
Unified automation script for managing the entire PegaSpy ecosystem

Usage:
    python pegaspy-manager.py start    # Start all services
    python pegaspy-manager.py stop     # Stop all services
    python pegaspy-manager.py status   # Check service status
    python pegaspy-manager.py health   # Run health checks
    python pegaspy-manager.py restart  # Restart all services
    python pegaspy-manager.py logs     # Show service logs
    python pegaspy-manager.py test     # Run comprehensive tests
"""

import os
import sys
import time
import json
import signal
import subprocess
import threading
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class PegaSpyManager:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.services = {
            'go-backend': {
                'cmd': ['go', 'run', 'cmd/pegaspy-server/main.go'],
                'cwd': self.base_dir / 'go-backend',
                'port': 8080,
                'health_url': 'http://localhost:8080/health',
                'process': None
            },
            'python-legacy': {
                'cmd': ['python', 'pegaspy.py'],
                'cwd': self.base_dir,
                'port': 5000,
                'health_url': 'http://127.0.0.1:5000/',
                'process': None,
                'env': {'VIRTUAL_ENV': str(self.base_dir / 'venv')}
            },
            'mobile-app': {
                'cmd': ['npm', 'start'],
                'cwd': self.base_dir / 'mobile-app',
                'port': 8081,
                'health_url': None,  # Expo doesn't have a simple health endpoint
                'process': None
            }
        }
        self.log_file = self.base_dir / 'pegaspy-manager.log'
        
    def log(self, message: str, level: str = 'INFO'):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def check_dependencies(self) -> bool:
        """Check if required dependencies are available"""
        self.log("🔍 Checking dependencies...")
        
        # Check Go
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"✅ Go: {result.stdout.strip()}")
            else:
                self.log("❌ Go not found", 'ERROR')
                return False
        except FileNotFoundError:
            self.log("❌ Go not found", 'ERROR')
            return False
        
        # Check Python
        try:
            result = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
            self.log(f"✅ Python: {result.stdout.strip()}")
        except Exception as e:
            self.log(f"❌ Python check failed: {e}", 'ERROR')
            return False
        
        # Check Node.js
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"✅ Node.js: {result.stdout.strip()}")
            else:
                self.log("❌ Node.js not found", 'ERROR')
                return False
        except FileNotFoundError:
            self.log("❌ Node.js not found", 'ERROR')
            return False
        
        # Check npm
        try:
            result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"✅ npm: {result.stdout.strip()}")
            else:
                self.log("❌ npm not found", 'ERROR')
                return False
        except FileNotFoundError:
            self.log("❌ npm not found", 'ERROR')
            return False
        
        return True
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return False
            except OSError:
                return True
    
    def _get_pid_by_port(self, port: int) -> Optional[int]:
        """Get PID of process using a specific port"""
        try:
            result = subprocess.run(
                ['lsof', '-ti', f':{port}'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split('\n')[0])
        except (subprocess.SubprocessError, ValueError, FileNotFoundError):
            pass
        return None
    
    def start_service(self, name: str) -> bool:
        """Start a specific service"""
        service = self.services[name]
        
        if service['process'] and service['process'].poll() is None:
            self.log(f"⚠️  Service {name} is already running")
            return True
        
        self.log(f"🚀 Starting {name}...")
        
        try:
            env = os.environ.copy()
            if 'env' in service:
                env.update(service['env'])
            
            # Activate virtual environment for Python services
            if name == 'python-legacy':
                venv_activate = self.base_dir / 'venv' / 'bin' / 'activate'
                if venv_activate.exists():
                    env['VIRTUAL_ENV'] = str(self.base_dir / 'venv')
                    env['PATH'] = f"{self.base_dir / 'venv' / 'bin'}:{env['PATH']}"
            
            service['process'] = subprocess.Popen(
                service['cmd'],
                cwd=service['cwd'],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give service time to start
            time.sleep(3)
            
            if service['process'].poll() is None:
                self.log(f"✅ {name} started successfully (PID: {service['process'].pid})")
                return True
            else:
                stdout, stderr = service['process'].communicate()
                self.log(f"❌ {name} failed to start", 'ERROR')
                self.log(f"STDOUT: {stdout}", 'ERROR')
                self.log(f"STDERR: {stderr}", 'ERROR')
                return False
                
        except Exception as e:
            self.log(f"❌ Failed to start {name}: {e}", 'ERROR')
            return False
    
    def stop_service(self, name: str) -> bool:
        """Stop a specific service"""
        service = self.services[name]
        
        if not service['process'] or service['process'].poll() is not None:
            self.log(f"⚠️  Service {name} is not running")
            return True
        
        self.log(f"🛑 Stopping {name}...")
        
        try:
            service['process'].terminate()
            
            # Wait for graceful shutdown
            try:
                service['process'].wait(timeout=10)
                self.log(f"✅ {name} stopped gracefully")
            except subprocess.TimeoutExpired:
                self.log(f"⚠️  Force killing {name}...")
                service['process'].kill()
                service['process'].wait()
                self.log(f"✅ {name} force stopped")
            
            service['process'] = None
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to stop {name}: {e}", 'ERROR')
            return False
    
    def check_service_health(self, name: str) -> Dict:
        """Check health of a specific service"""
        service = self.services[name]
        status = {
            'name': name,
            'running': False,
            'healthy': False,
            'port': service.get('port'),
            'pid': None,
            'response_time': None,
            'error': None
        }
        
        # Check if process is running (managed by this script)
        if service['process'] and service['process'].poll() is None:
            status['running'] = True
            status['pid'] = service['process'].pid
        
        # Check health endpoint if available (detects external processes too)
        if service.get('health_url'):
            try:
                start_time = time.time()
                response = requests.get(service['health_url'], timeout=5)
                status['response_time'] = round((time.time() - start_time) * 1000, 2)
                
                if response.status_code == 200:
                    status['healthy'] = True
                    status['running'] = True  # Service is responding, so it's running
                    # Try to get PID from system if not managed by us
                    if not status['pid']:
                        status['pid'] = self._get_pid_by_port(service['port'])
                else:
                    status['error'] = f"HTTP {response.status_code}"
                    
            except requests.exceptions.RequestException as e:
                status['error'] = str(e)
        elif name == 'mobile-app':
            # For mobile app, check if port is in use
            if self._is_port_in_use(service['port']):
                status['running'] = True
                status['healthy'] = True
                status['pid'] = self._get_pid_by_port(service['port'])
        
        return status
    
    def run_health_checks(self) -> Dict:
        """Run comprehensive health checks"""
        self.log("🏥 Running health checks...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'services': {},
            'api_tests': {}
        }
        
        # Check each service
        for name in self.services:
            status = self.check_service_health(name)
            results['services'][name] = status
            
            if not status['healthy']:
                results['overall_status'] = 'unhealthy'
            
            # Log status
            if status['healthy']:
                self.log(f"✅ {name}: Healthy (PID: {status['pid']}, Response: {status['response_time']}ms)")
            else:
                self.log(f"❌ {name}: Unhealthy - {status['error']}", 'ERROR')
        
        # Test API endpoints if Go backend is healthy
        if results['services']['go-backend']['healthy']:
            api_tests = {
                'stats': 'http://localhost:8080/api/v1/stats',
                'ml_stats': 'http://localhost:8080/api/v1/ml/stats',
                'audit_stats': 'http://localhost:8080/api/v1/audit/stats',
                'system_info': 'http://localhost:8080/api/v1/system/info'
            }
            
            for test_name, url in api_tests.items():
                try:
                    response = requests.get(url, timeout=5)
                    results['api_tests'][test_name] = {
                        'status': 'pass' if response.status_code == 200 else 'fail',
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds() * 1000
                    }
                except Exception as e:
                    results['api_tests'][test_name] = {
                        'status': 'fail',
                        'error': str(e)
                    }
        
        return results
    
    def start_all(self) -> bool:
        """Start all services"""
        self.log("🚀 Starting PegaSpy ecosystem...")
        
        if not self.check_dependencies():
            self.log("❌ Dependency check failed", 'ERROR')
            return False
        
        success = True
        
        # Start services in order
        for name in ['go-backend', 'python-legacy', 'mobile-app']:
            if not self.start_service(name):
                success = False
        
        if success:
            self.log("✅ All services started successfully")
            time.sleep(5)  # Wait for services to fully initialize
            
            # Run health checks
            health_results = self.run_health_checks()
            
            if health_results['overall_status'] == 'healthy':
                self.log("🎉 PegaSpy ecosystem is fully operational!")
                self.log("📊 Access points:")
                self.log("   • Go Backend API: http://localhost:8080")
                self.log("   • Python Dashboard: http://127.0.0.1:5000")
                self.log("   • Mobile App: Scan QR code in terminal")
            else:
                self.log("⚠️  Some services are unhealthy", 'WARNING')
        
        return success
    
    def stop_all(self) -> bool:
        """Stop all services"""
        self.log("🛑 Stopping PegaSpy ecosystem...")
        
        success = True
        for name in self.services:
            if not self.stop_service(name):
                success = False
        
        if success:
            self.log("✅ All services stopped successfully")
        
        return success
    
    def restart_all(self) -> bool:
        """Restart all services"""
        self.log("🔄 Restarting PegaSpy ecosystem...")
        
        if not self.stop_all():
            return False
        
        time.sleep(2)
        return self.start_all()
    
    def show_status(self):
        """Show current status of all services"""
        self.log("📊 PegaSpy Service Status")
        self.log("=" * 50)
        
        for name in self.services:
            status = self.check_service_health(name)
            
            status_icon = "✅" if status['healthy'] else "❌"
            running_icon = "🟢" if status['running'] else "🔴"
            
            self.log(f"{status_icon} {name}:")
            self.log(f"   Running: {running_icon} {'Yes' if status['running'] else 'No'}")
            
            if status['pid']:
                self.log(f"   PID: {status['pid']}")
            
            if status['port']:
                self.log(f"   Port: {status['port']}")
            
            if status['response_time']:
                self.log(f"   Response Time: {status['response_time']}ms")
            
            if status['error']:
                self.log(f"   Error: {status['error']}")
            
            self.log("")
    
    def show_logs(self):
        """Show recent logs from all services"""
        self.log("📋 Recent Service Logs")
        self.log("=" * 50)
        
        for name, service in self.services.items():
            if service['process'] and service['process'].poll() is None:
                self.log(f"\n📝 {name} logs:")
                try:
                    # This is a simplified log display
                    # In a real implementation, you might want to tail log files
                    self.log(f"   Service running with PID {service['process'].pid}")
                except Exception as e:
                    self.log(f"   Error reading logs: {e}")
    
    def run_tests(self):
        """Run comprehensive system tests"""
        self.log("🧪 Running comprehensive tests...")
        
        # Health checks
        health_results = self.run_health_checks()
        
        # API functionality tests
        if health_results['services']['go-backend']['healthy']:
            self.log("\n🔬 Testing API functionality...")
            
            # Test scan endpoint
            try:
                response = requests.post(
                    'http://localhost:8080/api/v1/scan',
                    json={'target': 'test-device', 'scan_type': 'quick'},
                    timeout=10
                )
                if response.status_code == 200:
                    self.log("✅ Scan API: Working")
                else:
                    self.log(f"❌ Scan API: Failed ({response.status_code})")
            except Exception as e:
                self.log(f"❌ Scan API: Error - {e}")
            
            # Test ML prediction
            try:
                test_features = [0.5] * 20  # 20-dimensional feature vector
                response = requests.post(
                    'http://localhost:8080/api/v1/ml/predict',
                    json={'features': test_features},
                    timeout=10
                )
                if response.status_code == 200:
                    self.log("✅ ML Prediction API: Working")
                else:
                    self.log(f"❌ ML Prediction API: Failed ({response.status_code})")
            except Exception as e:
                self.log(f"❌ ML Prediction API: Error - {e}")
        
        # Save test results
        test_report = {
            'timestamp': datetime.now().isoformat(),
            'health_results': health_results,
            'test_status': 'completed'
        }
        
        report_file = self.base_dir / f'test_report_{int(time.time())}.json'
        with open(report_file, 'w') as f:
            json.dump(test_report, f, indent=2)
        
        self.log(f"📄 Test report saved to: {report_file}")

def main():
    manager = PegaSpyManager()
    
    if len(sys.argv) < 2:
        print("PegaSpy Application Manager")
        print("Usage:")
        print("  python pegaspy-manager.py start    # Start all services")
        print("  python pegaspy-manager.py stop     # Stop all services")
        print("  python pegaspy-manager.py status   # Check service status")
        print("  python pegaspy-manager.py health   # Run health checks")
        print("  python pegaspy-manager.py restart  # Restart all services")
        print("  python pegaspy-manager.py logs     # Show service logs")
        print("  python pegaspy-manager.py test     # Run comprehensive tests")
        return
    
    command = sys.argv[1].lower()
    
    try:
        if command == 'start':
            manager.start_all()
        elif command == 'stop':
            manager.stop_all()
        elif command == 'restart':
            manager.restart_all()
        elif command == 'status':
            manager.show_status()
        elif command == 'health':
            results = manager.run_health_checks()
            print(json.dumps(results, indent=2))
        elif command == 'logs':
            manager.show_logs()
        elif command == 'test':
            manager.run_tests()
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        manager.stop_all()
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()