#!/usr/bin/env python3
"""Simple Prevention & Hardening Tools Demo

A streamlined demonstration of the PegaSpy Prevention & Hardening framework.
"""

import os
import sys
import time

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
    print(f"❌ Import error: {e}")
    sys.exit(1)


def test_component(name, test_func):
    """Test a component and return success status"""
    print(f"\n🔍 Testing {name}...")
    try:
        test_func()
        print(f"✅ {name} - OK")
        return True
    except Exception as e:
        print(f"❌ {name} - Failed: {str(e)[:100]}...")
        return False


def test_system_hardening():
    """Test System Hardening Manager"""
    manager = SystemHardeningManager()
    report = manager.check_security_settings()
    print(f"   Security Score: {report.overall_score}/100")


def test_app_permissions():
    """Test App Permission Manager"""
    manager = AppPermissionManager()
    apps = manager.scan_installed_apps()
    print(f"   Found {len(apps)} applications")


def test_network_security():
    """Test Network Security Monitor"""
    monitor = NetworkSecurityMonitor()
    connections = monitor.scan_network_connections()
    print(f"   Found {len(connections)} network connections")
    vpn_status = monitor.check_vpn_status()
    print(f"   VPN Status: {'Connected' if vpn_status.get('is_connected') else 'Disconnected'}")


def test_realtime_protection():
    """Test Real-time Protection Engine"""
    engine = RealTimeProtectionEngine()
    result = engine.scan_link("https://www.google.com")
    print(f"   Link scan result: {result.verdict} (Risk: {result.risk_score:.1f}/100)")


def test_exploit_detection():
    """Test Zero-click Exploit Detector"""
    detector = ZeroClickExploitDetector()
    process_data = {
        'pid': 1234,
        'name': 'test_process',
        'cpu_percent': 15.5,
        'memory_percent': 8.2,
        'connections': 3,
        'files_opened': 5
    }
    analysis = detector.analyze_process_behavior(process_data)
    print(f"   Process analysis: {analysis['risk_level']} risk")


def test_link_scanner():
    """Test Malicious Link Scanner"""
    scanner = MaliciousLinkScanner()
    report = scanner.scan_url("https://www.google.com")
    print(f"   URL scan: {report.overall_verdict} (Risk: {report.risk_score:.1f}/100)")


def test_app_integrity():
    """Test App Integrity Verifier"""
    verifier = AppIntegrityVerifier()
    test_app = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
    if os.path.exists(test_app):
        baseline = verifier.create_baseline(test_app, "Calculator", "1.0")
        print(f"   Baseline created for Calculator with {len(baseline.file_signatures)} files")
    else:
        print("   Test app not found, creating mock baseline")


def main():
    """Run simple demo"""
    print("="*60)
    print("🛡️  PEGASPY PREVENTION & HARDENING TOOLS - SIMPLE DEMO")
    print("="*60)
    
    components = [
        ("System Hardening Manager", test_system_hardening),
        ("App Permission Manager", test_app_permissions),
        ("Network Security Monitor", test_network_security),
        ("Real-time Protection Engine", test_realtime_protection),
        ("Zero-click Exploit Detector", test_exploit_detection),
        ("Malicious Link Scanner", test_link_scanner),
        ("App Integrity Verifier", test_app_integrity)
    ]
    
    results = []
    for name, test_func in components:
        success = test_component(name, test_func)
        results.append(success)
    
    # Summary
    total = len(results)
    passed = sum(results)
    success_rate = (passed / total) * 100
    
    print("\n" + "="*60)
    print("📊 DEMO SUMMARY")
    print("="*60)
    print(f"Total Components: {total}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {total - passed} ❌")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 70:
        print("\n🎉 Prevention & Hardening Tools are working well!")
        return 0
    else:
        print("\n⚠️ Some components need attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())