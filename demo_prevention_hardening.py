#!/usr/bin/env python3
"""Prevention & Hardening Tools Demo

Demonstrates the capabilities of the PegaSpy Prevention & Hardening framework:
- System Hardening Suite
- Real-time Protection
- Network Security Monitoring
- Zero-click Exploit Detection
- Malicious Link Scanner
- App Integrity Verification
"""

import os
import sys
import time
import json
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
    print(f"❌ Import error: {e}")
    print("Make sure all prevention_hardening modules are available")
    sys.exit(1)


def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"🛡️  {title}")
    print("="*60)


def print_section(title):
    """Print a formatted section header"""
    print(f"\n📋 {title}")
    print("-" * 40)


def demo_system_hardening():
    """Demonstrate System Hardening capabilities"""
    print_section("System Hardening Suite")
    
    try:
        hardening_manager = SystemHardeningManager()
        
        # Check current security settings
        print("🔍 Checking current security settings...")
        report = hardening_manager.check_security_settings()
        print(f"   Overall Security Score: {report.overall_score}/100")
        print(f"   Critical Issues: {len([r for r in report.recommendations if r.priority == 'critical'])}")
        print(f"   High Priority Issues: {len([r for r in report.recommendations if r.priority == 'high'])}")
        
        # Get hardening recommendations
        print("\n💡 Getting hardening recommendations...")
        recommendations = hardening_manager.get_hardening_recommendations()
        print(f"   Generated {len(recommendations)} recommendations")
        
        if recommendations:
            print("   Top 3 recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec.title} (Priority: {rec.priority})")
        
        # Export configuration
        print("\n📄 Exporting security configuration...")
        config_file = "reports/security_config.json"
        os.makedirs("reports", exist_ok=True)
        hardening_manager.export_configuration(config_file)
        print(f"   Configuration exported to {config_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ System hardening demo failed: {e}")
        return False


def demo_app_permissions():
    """Demonstrate App Permission Management"""
    print_section("App Permission Management")
    
    try:
        permission_manager = AppPermissionManager()
        
        # Scan installed apps
        print("🔍 Scanning installed applications...")
        apps = permission_manager.scan_installed_apps()
        print(f"   Found {len(apps)} installed applications")
        
        if apps:
            # Analyze top 5 apps
            print("\n🔒 Analyzing app permissions (top 5 apps):")
            for i, app in enumerate(apps[:5], 1):
                try:
                    audit_result = permission_manager.audit_app_permissions(app.path)
                    risk_score = permission_manager.calculate_risk_score(audit_result.permissions)
                    print(f"   {i}. {app.name}: Risk Score {risk_score:.1f}/100")
                except Exception as e:
                    print(f"   {i}. {app.name}: Analysis failed ({str(e)[:50]}...)")
        
        # Generate permission report
        print("\n📊 Generating permission audit report...")
        report = permission_manager.generate_permission_report()
        print(f"   Total apps analyzed: {report.total_apps}")
        print(f"   High-risk apps: {report.high_risk_apps}")
        print(f"   Apps with excessive permissions: {report.excessive_permissions}")
        
        return True
        
    except Exception as e:
        print(f"❌ App permissions demo failed: {e}")
        return False


def demo_network_security():
    """Demonstrate Network Security Monitoring"""
    print_section("Network Security Monitoring")
    
    try:
        network_monitor = NetworkSecurityMonitor()
        
        # Scan network connections
        print("🌐 Scanning network connections...")
        connections = network_monitor.scan_network_connections()
        print(f"   Found {len(connections)} active connections")
        
        # Analyze threats
        if connections:
            print("\n🚨 Analyzing connection threats:")
            threat_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            
            for conn in connections[:10]:  # Analyze first 10 connections
                threat_level = network_monitor.assess_connection_threat(conn)
                threat_counts[threat_level] += 1
            
            print(f"   Low risk: {threat_counts['low']} connections")
            print(f"   Medium risk: {threat_counts['medium']} connections")
            print(f"   High risk: {threat_counts['high']} connections")
            print(f"   Critical risk: {threat_counts['critical']} connections")
        
        # Check VPN status
        print("\n🔐 Checking VPN status...")
        vpn_status = network_monitor.check_vpn_status()
        print(f"   VPN Connected: {'Yes' if vpn_status.get('is_connected') else 'No'}")
        if vpn_status.get('vpn_name'):
            print(f"   VPN Name: {vpn_status['vpn_name']}")
        
        # Generate security report
        print("\n📊 Generating network security report...")
        report = network_monitor.generate_security_report()
        print(f"   Total connections analyzed: {report.total_connections}")
        print(f"   Suspicious connections: {report.suspicious_connections}")
        print(f"   Blocked IPs: {len(report.blocked_ips)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Network security demo failed: {e}")
        return False


def demo_realtime_protection():
    """Demonstrate Real-time Protection"""
    print_section("Real-time Protection Engine")
    
    try:
        protection_engine = RealTimeProtectionEngine()
        
        # Start protection briefly
        print("🛡️ Starting real-time protection...")
        protection_engine.start_protection()
        print("   Protection active")
        
        # Test link scanning
        print("\n🔗 Testing link scanner:")
        test_links = [
            "https://www.google.com",
            "https://github.com",
            "http://malware-example.com/download.exe"
        ]
        
        for link in test_links:
            result = protection_engine.scan_link(link)
            print(f"   {link}: {result.verdict.upper()} (Risk: {result.risk_score:.1f}/100)")
        
        # Test app integrity (if Safari exists)
        print("\n🔍 Testing app integrity verification:")
        test_app = "/System/Applications/Safari.app/Contents/MacOS/Safari"
        if os.path.exists(test_app):
            integrity_result = protection_engine.verify_app_integrity(test_app)
            print(f"   Safari integrity: {integrity_result.status.value}")
            print(f"   Integrity score: {integrity_result.integrity_score:.1f}/100")
        else:
            print("   Safari not found, skipping integrity check")
        
        # Stop protection
        time.sleep(2)
        protection_engine.stop_protection()
        print("\n✅ Real-time protection stopped")
        
        # Generate protection report
        report = protection_engine.generate_protection_report()
        print(f"\n📊 Protection Summary:")
        print(f"   Links scanned: {report.links_scanned}")
        print(f"   Malicious links blocked: {report.malicious_links_blocked}")
        print(f"   Apps verified: {report.apps_verified}")
        print(f"   Integrity violations: {report.integrity_violations}")
        
        return True
        
    except Exception as e:
        print(f"❌ Real-time protection demo failed: {e}")
        return False


def demo_exploit_detection():
    """Demonstrate Zero-click Exploit Detection"""
    print_section("Zero-click Exploit Detection")
    
    try:
        exploit_detector = ZeroClickExploitDetector()
        
        # Start detection briefly
        print("🕵️ Starting exploit detection...")
        exploit_detector.start_detection()
        print("   Detection active")
        
        # Simulate process behavior analysis
        print("\n🔍 Analyzing process behaviors:")
        test_processes = [
            {'pid': 1234, 'name': 'Messages', 'cpu_percent': 5.2, 'memory_percent': 3.1, 'connections': 2, 'files_opened': 1},
            {'pid': 5678, 'name': 'Safari', 'cpu_percent': 15.8, 'memory_percent': 12.4, 'connections': 8, 'files_opened': 3},
            {'pid': 9999, 'name': 'suspicious_app', 'cpu_percent': 85.0, 'memory_percent': 45.2, 'connections': 25, 'files_opened': 100}
        ]
        
        for process in test_processes:
            analysis = exploit_detector.analyze_process_behavior(process)
            print(f"   {process['name']} (PID: {process['pid']}): {analysis['risk_level']} risk")
            if analysis['suspicious_indicators']:
                print(f"     Indicators: {', '.join(analysis['suspicious_indicators'])}")
        
        # Stop detection
        time.sleep(2)
        exploit_detector.stop_detection()
        print("\n✅ Exploit detection stopped")
        
        # Get detection statistics
        stats = exploit_detector.get_detection_statistics()
        print(f"\n📊 Detection Statistics:")
        print(f"   Total detections: {stats['total_detections']}")
        print(f"   High-risk detections: {stats['high_risk_detections']}")
        print(f"   Processes monitored: {stats['processes_monitored']}")
        print(f"   Files monitored: {stats['files_monitored']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Exploit detection demo failed: {e}")
        return False


def demo_link_scanner():
    """Demonstrate Malicious Link Scanner"""
    print_section("Malicious Link Scanner")
    
    try:
        link_scanner = MaliciousLinkScanner()
        
        # Test various types of URLs
        print("🔗 Scanning various URLs:")
        test_urls = [
            "https://www.google.com",
            "https://github.com/pegaspy/framework",
            "http://bit.ly/suspicious-link",
            "http://malware-example.com/download.exe",
            "https://phishing-site.fake/login.html",
            "ftp://anonymous@suspicious-server.com/data"
        ]
        
        scan_results = []
        for url in test_urls:
            try:
                report = link_scanner.scan_url(url)
                scan_results.append(report)
                print(f"   {url}")
                print(f"     Verdict: {report.overall_verdict.upper()}")
                print(f"     Risk Score: {report.risk_score:.1f}/100")
                print(f"     Confidence: {report.confidence_score:.1f}%")
                if report.threat_categories:
                    print(f"     Threats: {', '.join(report.threat_categories)}")
            except Exception as e:
                print(f"   {url}: Scan failed ({str(e)[:50]}...)")
        
        # Batch scan demonstration
        print("\n📊 Batch scanning results:")
        batch_reports = link_scanner.scan_multiple_urls(test_urls[:4])
        verdicts = {}
        for report in batch_reports:
            verdict = report.overall_verdict
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        
        for verdict, count in verdicts.items():
            print(f"   {verdict.capitalize()}: {count} URLs")
        
        # Get scanner statistics
        stats = link_scanner.get_scan_statistics()
        print(f"\n📈 Scanner Statistics:")
        print(f"   Total scans: {stats['total_scans']}")
        print(f"   Malicious detected: {stats['malicious_detected']}")
        print(f"   Safe URLs: {stats['safe_urls']}")
        print(f"   Cache hits: {stats['cache_hits']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Link scanner demo failed: {e}")
        return False


def demo_app_integrity():
    """Demonstrate App Integrity Verification"""
    print_section("App Integrity Verification")
    
    try:
        integrity_verifier = AppIntegrityVerifier()
        
        # Test with system applications
        print("🔍 Verifying system application integrity:")
        system_apps = [
            ("/System/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
            ("/System/Applications/Mail.app/Contents/MacOS/Mail", "Mail"),
            ("/System/Applications/Calculator.app/Contents/MacOS/Calculator", "Calculator")
        ]
        
        verified_apps = 0
        for app_path, app_name in system_apps:
            if os.path.exists(app_path):
                try:
                    # Create baseline first
                    baseline = integrity_verifier.create_baseline(app_path, app_name, "system")
                    print(f"   ✅ Baseline created for {app_name}")
                    
                    # Verify integrity
                    report = integrity_verifier.verify_integrity(app_path)
                    print(f"   🔍 {app_name}: {report.overall_status.value}")
                    print(f"      Integrity Score: {report.integrity_score:.1f}/100")
                    print(f"      Files checked: {len(report.file_results)}")
                    
                    if report.violations:
                        print(f"      Violations: {len(report.violations)}")
                    
                    verified_apps += 1
                    
                except Exception as e:
                    print(f"   ❌ {app_name}: Verification failed ({str(e)[:50]}...)")
            else:
                print(f"   ⚠️ {app_name}: Not found at {app_path}")
        
        # Get verification statistics
        stats = integrity_verifier.get_statistics()
        print(f"\n📊 Integrity Verification Statistics:")
        print(f"   Total verifications: {stats['total_verifications']}")
        print(f"   Successful verifications: {stats['successful_verifications']}")
        print(f"   Integrity violations: {stats['integrity_violations']}")
        print(f"   Apps with baselines: {len(integrity_verifier.app_baselines)}")
        
        return verified_apps > 0
        
    except Exception as e:
        print(f"❌ App integrity demo failed: {e}")
        return False


def generate_demo_report(results):
    """Generate a comprehensive demo report"""
    print_header("DEMO SUMMARY REPORT")
    
    total_demos = len(results)
    successful_demos = sum(results.values())
    success_rate = (successful_demos / total_demos) * 100
    
    print(f"\n📊 Demo Results:")
    for demo_name, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"   {demo_name}: {status}")
    
    print(f"\n📈 Overall Statistics:")
    print(f"   Total Demos: {total_demos}")
    print(f"   Successful: {successful_demos}")
    print(f"   Failed: {total_demos - successful_demos}")
    print(f"   Success Rate: {success_rate:.1f}%")
    
    # Save report to file
    report_data = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'demo_results': results,
        'summary': {
            'total_demos': total_demos,
            'successful_demos': successful_demos,
            'success_rate': success_rate
        }
    }
    
    os.makedirs('reports', exist_ok=True)
    report_file = f"reports/prevention_hardening_demo_{int(time.time())}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📄 Demo report saved to: {report_file}")
    
    if success_rate >= 70:
        print("\n🎉 Prevention & Hardening Tools Demo Completed Successfully!")
        print("   The framework is ready for production use.")
    else:
        print("\n⚠️ Some components need attention before production deployment.")
    
    return success_rate >= 70


def main():
    """Run the complete Prevention & Hardening Tools demo"""
    print_header("PEGASPY PREVENTION & HARDENING TOOLS DEMO")
    print("This demo showcases the comprehensive security capabilities")
    print("of the PegaSpy Prevention & Hardening framework.")
    
    # Run all demos
    demo_results = {
        'System Hardening': demo_system_hardening(),
        'App Permissions': demo_app_permissions(),
        'Network Security': demo_network_security(),
        'Real-time Protection': demo_realtime_protection(),
        'Exploit Detection': demo_exploit_detection(),
        'Link Scanner': demo_link_scanner(),
        'App Integrity': demo_app_integrity()
    }
    
    # Generate final report
    success = generate_demo_report(demo_results)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())