#!/usr/bin/env python3
"""
PegaSpy to Pegasus Enhancement Setup Script
Automated setup for Pegasus-like capabilities
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from typing import List, Dict

class PegasusSetup:
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.required_dirs = [
            "advanced_exploits/ios",
            "advanced_exploits/android", 
            "advanced_exploits/cross_platform",
            "surveillance/audio",
            "surveillance/video",
            "surveillance/location",
            "surveillance/data",
            "surveillance/screenshots",
            "data_exfiltration/channels",
            "data_exfiltration/processors",
            "data_exfiltration/encoders",
            "evasion/anti_debug",
            "evasion/sandbox_escape",
            "evasion/behavioral",
            "testing/results",
            "testing/reports",
            "c2_enhanced/blockchain",
            "c2_enhanced/protocols",
            "persistence_advanced/ios",
            "persistence_advanced/android",
            "persistence_advanced/cross_platform",
            "mobile_specific/ios_hooks",
            "mobile_specific/android_hooks",
            "web_dashboard_v2/templates",
            "web_dashboard_v2/static",
            "logs",
            "config"
        ]
        
        self.required_packages = [
            "opencv-python",
            "pyaudio", 
            "numpy",
            "asyncio",
            "cryptography",
            "requests",
            "websockets",
            "pillow",
            "psutil",
            "scapy",
            "pynput",
            "flask-socketio",
            "sqlalchemy",
            "redis",
            "celery",
            "paramiko",
            "pycryptodome",
            "steganography",
            "python-nmap",
            "bluetooth-python"
        ]
    
    def setup_directories(self):
        """Create required directory structure"""
        print("🏗️  Creating directory structure...")
        
        for dir_path in self.required_dirs:
            full_path = self.base_dir / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created: {dir_path}")
        
        print(f"✅ Created {len(self.required_dirs)} directories")
    
    def install_dependencies(self):
        """Install required Python packages"""
        print("📦 Installing dependencies...")
        
        # Check if pip is available
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"], 
                         check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print("❌ pip is not available. Please install pip first.")
            return False
        
        # Install packages
        failed_packages = []
        
        for package in self.required_packages:
            try:
                print(f"   Installing {package}...")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    print(f"   ✅ {package} installed successfully")
                else:
                    print(f"   ⚠️  {package} installation failed: {result.stderr}")
                    failed_packages.append(package)
                    
            except subprocess.TimeoutExpired:
                print(f"   ⏰ {package} installation timed out")
                failed_packages.append(package)
            except Exception as e:
                print(f"   ❌ Error installing {package}: {e}")
                failed_packages.append(package)
        
        if failed_packages:
            print(f"\n⚠️  Failed to install: {', '.join(failed_packages)}")
            print("You may need to install these manually or check system requirements.")
        else:
            print("✅ All dependencies installed successfully")
        
        return len(failed_packages) == 0
    
    def create_config_files(self):
        """Create configuration files"""
        print("⚙️  Creating configuration files...")
        
        # Main configuration
        config = {
            "framework": {
                "name": "PegaSpy Enhanced",
                "version": "2.0.0",
                "mode": "research"
            },
            "exploits": {
                "enabled": True,
                "auto_update": False,
                "stealth_mode": True,
                "target_platforms": ["ios", "android", "web", "desktop"]
            },
            "surveillance": {
                "audio_enabled": True,
                "video_enabled": True,
                "screen_capture_enabled": True,
                "location_tracking_enabled": True,
                "max_concurrent_sessions": 10
            },
            "data_exfiltration": {
                "encryption_enabled": True,
                "compression_enabled": True,
                "stealth_delays": True,
                "max_chunk_size": 1024,
                "channels": {
                    "dns_tunneling": True,
                    "http_steganography": True,
                    "sms_covert": False,
                    "bluetooth_beacon": False
                }
            },
            "c2": {
                "blockchain_enabled": True,
                "encryption": "AES-256",
                "heartbeat_interval": 300,
                "backup_channels": 3
            },
            "persistence": {
                "kernel_hooks_enabled": True,
                "auto_restart": True,
                "stealth_techniques": True
            },
            "evasion": {
                "anti_debugging": True,
                "sandbox_detection": True,
                "vm_detection": True,
                "behavioral_analysis": True
            },
            "logging": {
                "level": "INFO",
                "file_logging": True,
                "max_log_size": "100MB",
                "log_retention_days": 30
            },
            "security": {
                "self_destruct_enabled": True,
                "evidence_cleanup": True,
                "secure_delete": True
            }
        }
        
        config_file = self.base_dir / "config" / "pegasus_config.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"   ✅ Created: {config_file}")
        
        # Create requirements.txt
        requirements_file = self.base_dir / "requirements_enhanced.txt"
        with open(requirements_file, 'w') as f:
            for package in self.required_packages:
                f.write(f"{package}\n")
        
        print(f"   ✅ Created: {requirements_file}")
        
        # Create .gitignore for sensitive files
        gitignore_content = """
# Pegasus Enhancement - Sensitive Files
logs/
*.log
config/secrets.json
surveillance/
data_exfiltration/output/
testing/results/
*.db
*.sqlite
*.key
*.pem
*.p12

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
"""
        
        gitignore_file = self.base_dir / ".gitignore_enhanced"
        with open(gitignore_file, 'w') as f:
            f.write(gitignore_content)
        
        print(f"   ✅ Created: {gitignore_file}")
        
        print("✅ Configuration files created")
    
    def create_init_files(self):
        """Create __init__.py files for Python modules"""
        print("🐍 Creating Python module files...")
        
        module_dirs = [
            "advanced_exploits",
            "advanced_exploits/ios",
            "advanced_exploits/android",
            "advanced_exploits/cross_platform",
            "surveillance",
            "data_exfiltration",
            "evasion",
            "testing",
            "c2_enhanced",
            "persistence_advanced",
            "mobile_specific"
        ]
        
        for module_dir in module_dirs:
            init_file = self.base_dir / module_dir / "__init__.py"
            
            # Create basic __init__.py content
            init_content = f'"""\n{module_dir.replace("_", " ").title()} Module\nPart of PegaSpy Enhanced Framework\n"""\n\n__version__ = "2.0.0"\n'
            
            with open(init_file, 'w') as f:
                f.write(init_content)
            
            print(f"   ✅ Created: {init_file}")
        
        print("✅ Python modules initialized")
    
    def create_launcher_script(self):
        """Create main launcher script"""
        print("🚀 Creating launcher script...")
        
        launcher_content = '''#!/usr/bin/env python3
"""
PegaSpy Enhanced Framework Launcher
Main entry point for Pegasus-like capabilities
"""

import sys
import os
import json
import asyncio
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def load_config():
    """Load framework configuration"""
    config_file = project_root / "config" / "pegasus_config.json"
    
    if not config_file.exists():
        print("❌ Configuration file not found. Run setup first.")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        return json.load(f)

def print_banner():
    """Print framework banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    PegaSpy Enhanced v2.0                    ║
║              Advanced Research Security Framework            ║
║                                                              ║
║  ⚠️  FOR AUTHORIZED SECURITY RESEARCH ONLY ⚠️               ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def show_menu():
    """Show main menu"""
    menu = """
🎯 Available Modules:

1. 📱 Mobile Exploit Framework
2. 🕵️  Surveillance Engine  
3. 📤 Data Exfiltration
4. 🌐 C2 Communication
5. 🔒 Persistence Manager
6. 🥷 Evasion Techniques
7. 🧪 Testing Suite
8. 📊 Web Dashboard
9. ⚙️  Configuration
0. 🚪 Exit

Select option: """
    
    return input(menu)

async def main():
    """Main application entry point"""
    print_banner()
    
    # Load configuration
    try:
        config = load_config()
        print(f"✅ Loaded configuration for {config['framework']['name']}")
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        return
    
    # Main application loop
    while True:
        try:
            choice = show_menu()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
            elif choice == "1":
                print("🚧 Mobile Exploit Framework - Coming Soon")
            elif choice == "2":
                print("🚧 Surveillance Engine - Coming Soon")
            elif choice == "3":
                print("🚧 Data Exfiltration - Coming Soon")
            elif choice == "4":
                print("🚧 C2 Communication - Coming Soon")
            elif choice == "5":
                print("🚧 Persistence Manager - Coming Soon")
            elif choice == "6":
                print("🚧 Evasion Techniques - Coming Soon")
            elif choice == "7":
                print("🧪 Starting Test Suite...")
                # Import and run test suite when implemented
                # from testing.pegasus_test_suite import PegasusTestSuite
                # test_suite = PegasusTestSuite()
                # await test_suite.run_all_tests()
            elif choice == "8":
                print("🚧 Web Dashboard - Coming Soon")
            elif choice == "9":
                print(f"📋 Current Configuration: {config['framework']['name']} v{config['framework']['version']}")
            else:
                print("❌ Invalid option. Please try again.")
            
            input("\nPress Enter to continue...")
            
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main())
'''
        
        launcher_file = self.base_dir / "pegasus_launcher.py"
        with open(launcher_file, 'w') as f:
            f.write(launcher_content)
        
        # Make executable
        os.chmod(launcher_file, 0o755)
        
        print(f"   ✅ Created: {launcher_file}")
        print("✅ Launcher script created")
    
    def run_setup(self):
        """Run complete setup process"""
        print("🎯 PegaSpy to Pegasus Enhancement Setup")
        print("=" * 50)
        
        try:
            # Setup directories
            self.setup_directories()
            print()
            
            # Create configuration files
            self.create_config_files()
            print()
            
            # Create Python modules
            self.create_init_files()
            print()
            
            # Create launcher
            self.create_launcher_script()
            print()
            
            # Install dependencies
            print("📦 Installing dependencies...")
            print("This may take several minutes...")
            self.install_dependencies()
            print()
            
            print("🎉 Setup completed successfully!")
            print()
            print("Next steps:")
            print("1. Review the IMPLEMENTATION_ROADMAP.md file")
            print("2. Implement the code examples provided")
            print("3. Run: python pegasus_launcher.py")
            print("4. Start with the testing suite to validate setup")
            print()
            print("⚠️  Remember: This framework is for authorized security research only!")
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            return False
        
        return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PegaSpy to Pegasus Enhancement Setup")
    parser.add_argument("--base-dir", help="Base directory for setup (default: current directory)")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    
    args = parser.parse_args()
    
    setup = PegasusSetup(args.base_dir)
    
    if args.skip_deps:
        setup.required_packages = []  # Skip package installation
    
    success = setup.run_setup()
    sys.exit(0 if success else 1)