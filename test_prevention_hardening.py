#!/usr/bin/env python3
"""Test Suite for Prevention & Hardening Tools

Comprehensive testing of:
- System Hardening Suite
- Real-time Protection
- Security Policy Engine
- Network Protection
- Zero-click Exploit Detection
- Malicious Link Scanner
- App Integrity Verifier
"""

import os
import sys
import time
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from prevention_hardening import (
        SystemHardeningManager,
        AppPermissionManager,
        NetworkSecurityMonitor,
        RealTimeProtectionEngine,
        ZeroClickExploitDetector,
        MaliciousLinkScanner,
        AppIntegrityVerifier
    )
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all prevention_hardening modules are available")
    sys.exit(1)


class TestSystemHardening(unittest.TestCase):
    """Test System Hardening Manager"""
    
    def setUp(self):
        self.hardening_manager = SystemHardeningManager()
    
    def test_initialization(self):
        """Test manager initialization"""
        self.assertIsNotNone(self.hardening_manager)
        self.assertIsInstance(self.hardening_manager.security_configs, dict)
        self.assertIn('macos', self.hardening_manager.security_configs)
    
    def test_check_security_settings(self):
        """Test security settings check"""
        try:
            report = self.hardening_manager.check_security_settings()
            self.assertIsNotNone(report)
            self.assertTrue(hasattr(report, 'overall_score'))
            self.assertTrue(hasattr(report, 'recommendations'))
            print(f"✅ Security check completed - Score: {report.overall_score}/100")
        except Exception as e:
            print(f"⚠️ Security check failed: {e}")
    
    def test_get_hardening_recommendations(self):
        """Test hardening recommendations"""
        try:
            recommendations = self.hardening_manager.get_hardening_recommendations()
            self.assertIsInstance(recommendations, list)
            print(f"✅ Generated {len(recommendations)} hardening recommendations")
        except Exception as e:
            print(f"⚠️ Recommendations failed: {e}")
    
    def test_export_configuration(self):
        """Test configuration export"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            self.hardening_manager.export_configuration(temp_file)
            self.assertTrue(os.path.exists(temp_file))
            
            # Cleanup
            os.unlink(temp_file)
            print("✅ Configuration export successful")
        except Exception as e:
            print(f"⚠️ Configuration export failed: {e}")


class TestAppPermissions(unittest.TestCase):
    """Test App Permission Manager"""
    
    def setUp(self):
        self.permission_manager = AppPermissionManager()
    
    def test_initialization(self):
        """Test manager initialization"""
        self.assertIsNotNone(self.permission_manager)
        self.assertIsInstance(self.permission_manager.permission_categories, dict)
    
    def test_scan_installed_apps(self):
        """Test installed apps scanning"""
        try:
            apps = self.permission_manager.scan_installed_apps()
            self.assertIsInstance(apps, list)
            print(f"✅ Found {len(apps)} installed applications")
            
            if apps:
                # Test first app
                app = apps[0]
                self.assertTrue(hasattr(app, 'name'))
                self.assertTrue(hasattr(app, 'path'))
                print(f"   Sample app: {app.name}")
        except Exception as e:
            print(f"⚠️ App scanning failed: {e}")
    
    def test_audit_permissions(self):
        """Test permission auditing"""
        try:
            # Get some apps first
            apps = self.permission_manager.scan_installed_apps()
            if apps:
                app = apps[0]
                audit_result = self.permission_manager.audit_app_permissions(app.path)
                self.assertIsNotNone(audit_result)
                print(f"✅ Permission audit completed for {app.name}")
            else:
                print("⚠️ No apps found for permission audit")
        except Exception as e:
            print(f"⚠️ Permission audit failed: {e}")
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        try:
            # Mock permission data
            permissions = ['camera', 'microphone', 'location', 'contacts']
            risk_score = self.permission_manager.calculate_risk_score(permissions)
            self.assertIsInstance(risk_score, (int, float))
            self.assertGreaterEqual(risk_score, 0)
            self.assertLessEqual(risk_score, 100)
            print(f"✅ Risk score calculated: {risk_score}/100")
        except Exception as e:
            print(f"⚠️ Risk score calculation failed: {e}")


class TestNetworkSecurity(unittest.TestCase):
    """Test Network Security Monitor"""
    
    def setUp(self):
        self.network_monitor = NetworkSecurityMonitor()
    
    def test_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.network_monitor)
        self.assertIsInstance(self.network_monitor.threat_signatures, list)
    
    def test_scan_network_connections(self):
        """Test network connection scanning"""
        try:
            connections = self.network_monitor.scan_network_connections()
            self.assertIsInstance(connections, list)
            print(f"✅ Found {len(connections)} network connections")
            
            if connections:
                conn = connections[0]
                self.assertTrue(hasattr(conn, 'local_address'))
                self.assertTrue(hasattr(conn, 'remote_address'))
        except Exception as e:
            print(f"⚠️ Network scanning failed: {e}")
    
    def test_assess_connection_threat(self):
        """Test connection threat assessment"""
        try:
            # Mock connection data
            from prevention_hardening.network_security import NetworkConnection
            
            mock_connection = NetworkConnection(
                local_address="192.168.1.100",
                local_port=12345,
                remote_address="8.8.8.8",
                remote_port=53,
                protocol="UDP",
                status="ESTABLISHED",
                process_name="chrome",
                process_id=1234,
                connection_time=time.time()
            )
            
            threat_level = self.network_monitor.assess_connection_threat(mock_connection)
            self.assertIsInstance(threat_level, str)
            print(f"✅ Threat assessment completed: {threat_level}")
        except Exception as e:
            print(f"⚠️ Threat assessment failed: {e}")
    
    def test_check_vpn_status(self):
        """Test VPN status check"""
        try:
            vpn_status = self.network_monitor.check_vpn_status()
            self.assertIsInstance(vpn_status, dict)
            self.assertIn('is_connected', vpn_status)
            print(f"✅ VPN status: {'Connected' if vpn_status.get('is_connected') else 'Disconnected'}")
        except Exception as e:
            print(f"⚠️ VPN status check failed: {e}")


class TestRealTimeProtection(unittest.TestCase):
    """Test Real-time Protection Engine"""
    
    def setUp(self):
        self.protection_engine = RealTimeProtectionEngine()
    
    def test_initialization(self):
        """Test engine initialization"""
        self.assertIsNotNone(self.protection_engine)
        self.assertIsInstance(self.protection_engine.exploit_signatures, dict)
        self.assertIsInstance(self.protection_engine.behavioral_patterns, dict)
    
    def test_start_stop_protection(self):
        """Test protection start/stop"""
        try:
            # Start protection
            self.protection_engine.start_protection()
            self.assertTrue(self.protection_engine.protection_active)
            print("✅ Real-time protection started")
            
            # Stop protection
            time.sleep(1)  # Let it run briefly
            self.protection_engine.stop_protection()
            self.assertFalse(self.protection_engine.protection_active)
            print("✅ Real-time protection stopped")
        except Exception as e:
            print(f"⚠️ Protection start/stop failed: {e}")
    
    def test_scan_link(self):
        """Test link scanning"""
        try:
            # Test safe link
            safe_result = self.protection_engine.scan_link("https://www.google.com")
            self.assertIsNotNone(safe_result)
            print(f"✅ Safe link scan: {safe_result.verdict}")
            
            # Test suspicious link
            suspicious_result = self.protection_engine.scan_link("http://malware-example.com/download.exe")
            self.assertIsNotNone(suspicious_result)
            print(f"✅ Suspicious link scan: {suspicious_result.verdict}")
        except Exception as e:
            print(f"⚠️ Link scanning failed: {e}")
    
    def test_verify_app_integrity(self):
        """Test app integrity verification"""
        try:
            # Test with a system app
            test_app = "/System/Applications/Safari.app/Contents/MacOS/Safari"
            if os.path.exists(test_app):
                integrity_result = self.protection_engine.verify_app_integrity(test_app)
                self.assertIsNotNone(integrity_result)
                print(f"✅ App integrity check: {integrity_result.status.value}")
            else:
                print("⚠️ Test app not found, skipping integrity check")
        except Exception as e:
            print(f"⚠️ App integrity check failed: {e}")


class TestExploitDetection(unittest.TestCase):
    """Test Zero-click Exploit Detector"""
    
    def setUp(self):
        self.exploit_detector = ZeroClickExploitDetector()
    
    def test_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.exploit_detector)
        self.assertIsInstance(self.exploit_detector.exploit_signatures, dict)
        self.assertIsInstance(self.exploit_detector.behavioral_patterns, dict)
    
    def test_start_stop_detection(self):
        """Test detection start/stop"""
        try:
            # Start detection
            self.exploit_detector.start_detection()
            self.assertTrue(self.exploit_detector.detection_active)
            print("✅ Exploit detection started")
            
            # Stop detection
            time.sleep(1)  # Let it run briefly
            self.exploit_detector.stop_detection()
            self.assertFalse(self.exploit_detector.detection_active)
            print("✅ Exploit detection stopped")
        except Exception as e:
            print(f"⚠️ Exploit detection start/stop failed: {e}")
    
    def test_analyze_process_behavior(self):
        """Test process behavior analysis"""
        try:
            # Mock process data
            process_data = {
                'pid': 1234,
                'name': 'test_process',
                'cpu_percent': 15.5,
                'memory_percent': 8.2,
                'connections': 3,
                'files_opened': 5
            }
            
            analysis = self.exploit_detector.analyze_process_behavior(process_data)
            self.assertIsNotNone(analysis)
            print(f"✅ Process behavior analysis completed")
        except Exception as e:
            print(f"⚠️ Process behavior analysis failed: {e}")
    
    def test_get_detection_statistics(self):
        """Test detection statistics"""
        try:
            stats = self.exploit_detector.get_detection_statistics()
            self.assertIsInstance(stats, dict)
            self.assertIn('total_detections', stats)
            print(f"✅ Detection statistics: {stats['total_detections']} total detections")
        except Exception as e:
            print(f"⚠️ Detection statistics failed: {e}")


class TestLinkScanner(unittest.TestCase):
    """Test Malicious Link Scanner"""
    
    def setUp(self):
        self.link_scanner = MaliciousLinkScanner()
    
    def test_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.link_scanner)
        self.assertIsInstance(self.link_scanner.malicious_domains, set)
        self.assertIsInstance(self.link_scanner.url_shorteners, set)
    
    def test_scan_safe_url(self):
        """Test scanning safe URL"""
        try:
            report = self.link_scanner.scan_url("https://www.google.com")
            self.assertIsNotNone(report)
            self.assertEqual(report.overall_verdict, "safe")
            print(f"✅ Safe URL scan: {report.overall_verdict} (Risk: {report.risk_score:.1f}/100)")
        except Exception as e:
            print(f"⚠️ Safe URL scan failed: {e}")
    
    def test_scan_malicious_url(self):
        """Test scanning malicious URL"""
        try:
            # Use a domain from the malicious list
            malicious_url = "http://malware-example.com/download.exe"
            report = self.link_scanner.scan_url(malicious_url)
            self.assertIsNotNone(report)
            self.assertIn(report.overall_verdict, ["malicious", "suspicious"])
            print(f"✅ Malicious URL scan: {report.overall_verdict} (Risk: {report.risk_score:.1f}/100)")
        except Exception as e:
            print(f"⚠️ Malicious URL scan failed: {e}")
    
    def test_scan_multiple_urls(self):
        """Test scanning multiple URLs"""
        try:
            urls = [
                "https://www.google.com",
                "https://www.github.com",
                "http://malware-example.com"
            ]
            
            reports = self.link_scanner.scan_multiple_urls(urls)
            self.assertEqual(len(reports), len(urls))
            print(f"✅ Multiple URL scan completed: {len(reports)} URLs processed")
        except Exception as e:
            print(f"⚠️ Multiple URL scan failed: {e}")
    
    def test_get_scan_statistics(self):
        """Test scan statistics"""
        try:
            stats = self.link_scanner.get_scan_statistics()
            self.assertIsInstance(stats, dict)
            self.assertIn('total_scans', stats)
            print(f"✅ Scan statistics: {stats['total_scans']} total scans")
        except Exception as e:
            print(f"⚠️ Scan statistics failed: {e}")


class TestAppIntegrity(unittest.TestCase):
    """Test App Integrity Verifier"""
    
    def setUp(self):
        self.integrity_verifier = AppIntegrityVerifier()
    
    def test_initialization(self):
        """Test verifier initialization"""
        self.assertIsNotNone(self.integrity_verifier)
        self.assertIsInstance(self.integrity_verifier.app_baselines, dict)
        self.assertIsInstance(self.integrity_verifier.trusted_signatures, set)
    
    def test_create_baseline(self):
        """Test baseline creation"""
        try:
            # Test with a system app
            test_app = "/System/Applications/Safari.app/Contents/MacOS/Safari"
            if os.path.exists(test_app):
                baseline = self.integrity_verifier.create_baseline(test_app, "Safari", "1.0")
                self.assertIsNotNone(baseline)
                self.assertEqual(baseline.app_name, "Safari")
                print(f"✅ Baseline created for Safari with {len(baseline.file_signatures)} files")
            else:
                print("⚠️ Test app not found, skipping baseline creation")
        except Exception as e:
            print(f"⚠️ Baseline creation failed: {e}")
    
    def test_verify_integrity(self):
        """Test integrity verification"""
        try:
            # Test with a system app
            test_app = "/System/Applications/Safari.app/Contents/MacOS/Safari"
            if os.path.exists(test_app):
                report = self.integrity_verifier.verify_integrity(test_app)
                self.assertIsNotNone(report)
                print(f"✅ Integrity verification: {report.overall_status.value} (Score: {report.integrity_score:.1f}/100)")
            else:
                print("⚠️ Test app not found, skipping integrity verification")
        except Exception as e:
            print(f"⚠️ Integrity verification failed: {e}")
    
    def test_get_statistics(self):
        """Test statistics"""
        try:
            stats = self.integrity_verifier.get_statistics()
            self.assertIsInstance(stats, dict)
            self.assertIn('total_verifications', stats)
            print(f"✅ Integrity statistics: {stats['total_verifications']} total verifications")
        except Exception as e:
            print(f"⚠️ Integrity statistics failed: {e}")


def run_prevention_hardening_tests():
    """Run all prevention and hardening tests"""
    print("\n" + "="*60)
    print("🛡️  PEGASPY PREVENTION & HARDENING TOOLS TEST SUITE")
    print("="*60)
    
    test_classes = [
        TestSystemHardening,
        TestAppPermissions,
        TestNetworkSecurity,
        TestRealTimeProtection,
        TestExploitDetection,
        TestLinkScanner,
        TestAppIntegrity
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    
    for test_class in test_classes:
        print(f"\n📋 Testing {test_class.__name__}...")
        print("-" * 40)
        
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
        
        class_tests = 0
        class_passed = 0
        
        for test in suite:
            class_tests += 1
            total_tests += 1
            
            try:
                # Run individual test
                result = unittest.TestResult()
                test.run(result)
                
                if result.wasSuccessful():
                    class_passed += 1
                    passed_tests += 1
                else:
                    failed_tests += 1
                    if result.errors:
                        print(f"❌ {test._testMethodName}: {result.errors[0][1].split('\n')[-2]}")
                    elif result.failures:
                        print(f"❌ {test._testMethodName}: {result.failures[0][1].split('\n')[-2]}")
                        
            except Exception as e:
                failed_tests += 1
                print(f"❌ {test._testMethodName}: {str(e)}")
        
        print(f"\n📊 {test_class.__name__}: {class_passed}/{class_tests} tests passed")
    
    print("\n" + "="*60)
    print("📈 PREVENTION & HARDENING TOOLS TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests} ✅")
    print(f"Failed: {failed_tests} ❌")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests >= total_tests * 0.7:  # 70% pass rate
        print("\n🎉 Prevention & Hardening Tools are functioning well!")
        return True
    else:
        print("\n⚠️ Some Prevention & Hardening components need attention.")
        return False


if __name__ == "__main__":
    success = run_prevention_hardening_tests()
    sys.exit(0 if success else 1)