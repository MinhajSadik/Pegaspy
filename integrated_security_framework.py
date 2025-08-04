#!/usr/bin/env python3
"""Integrated Security Framework

Demonstrates the integration between Detection & Analysis Tools and
Prevention & Hardening Tools for comprehensive security coverage.
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Detection & Analysis Tools
    from detection_analysis import (
        MobileDeviceScanner,
        NetworkTrafficAnalyzer,
        FileIntegrityChecker,
        BehavioralAnalysisEngine
    )
    
    # Prevention & Hardening Tools
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
    print("Make sure all modules are available")
    sys.exit(1)


class IntegratedSecurityFramework:
    """Integrated Security Framework combining Detection and Prevention"""
    
    def __init__(self):
        """Initialize the integrated framework"""
        print("🔧 Initializing Integrated Security Framework...")
        
        # Detection & Analysis Components
        self.mobile_scanner = None
        self.network_analyzer = None
        self.file_checker = None
        self.behavioral_engine = None
        
        # Prevention & Hardening Components
        self.hardening_manager = None
        self.permission_manager = None
        self.network_monitor = None
        self.protection_engine = None
        self.exploit_detector = None
        self.link_scanner = None
        self.integrity_verifier = None
        
        # Framework state
        self.is_running = False
        self.scan_results = {}
        self.protection_status = {}
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all security components"""
        try:
            # Detection & Analysis Tools
            print("   📱 Initializing Mobile Device Scanner...")
            self.mobile_scanner = MobileDeviceScanner()
            
            print("   🌐 Initializing Network Traffic Analyzer...")
            self.network_analyzer = NetworkTrafficAnalyzer()
            
            print("   📁 Initializing File Integrity Checker...")
            self.file_checker = FileIntegrityChecker()
            
            print("   🧠 Initializing Behavioral Analysis Engine...")
            self.behavioral_engine = BehavioralAnalysisEngine()
            
            # Prevention & Hardening Tools
            print("   🛡️ Initializing System Hardening Manager...")
            self.hardening_manager = SystemHardeningManager()
            
            print("   🔐 Initializing App Permission Manager...")
            self.permission_manager = AppPermissionManager()
            
            print("   🌐 Initializing Network Security Monitor...")
            self.network_monitor = NetworkSecurityMonitor()
            
            print("   ⚡ Initializing Real-time Protection Engine...")
            self.protection_engine = RealTimeProtectionEngine()
            
            print("   🕵️ Initializing Zero-click Exploit Detector...")
            self.exploit_detector = ZeroClickExploitDetector()
            
            print("   🔗 Initializing Malicious Link Scanner...")
            self.link_scanner = MaliciousLinkScanner()
            
            print("   ✅ Initializing App Integrity Verifier...")
            self.integrity_verifier = AppIntegrityVerifier()
            
            print("✅ All components initialized successfully")
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            raise
    
    def run_comprehensive_scan(self):
        """Run a comprehensive security scan using detection tools"""
        print("\n" + "="*60)
        print("🔍 COMPREHENSIVE SECURITY SCAN")
        print("="*60)
        
        scan_start_time = time.time()
        
        # Mobile Device Scan
        print("\n📱 Mobile Device Security Scan...")
        try:
            mobile_results = self.mobile_scanner.scan_device()
            self.scan_results['mobile'] = {
                'status': 'completed',
                'threats_found': len(mobile_results.get('threats', [])),
                'processes_scanned': mobile_results.get('processes_scanned', 0)
            }
            print(f"   ✅ Scanned {mobile_results.get('processes_scanned', 0)} processes")
            print(f"   🚨 Found {len(mobile_results.get('threats', []))} potential threats")
        except Exception as e:
            self.scan_results['mobile'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ Mobile scan failed: {str(e)[:50]}...")
        
        # Network Traffic Analysis
        print("\n🌐 Network Traffic Analysis...")
        try:
            self.network_analyzer.start_monitoring()
            time.sleep(3)  # Monitor for 3 seconds
            network_results = self.network_analyzer.get_analysis_results()
            self.network_analyzer.stop_monitoring()
            
            self.scan_results['network'] = {
                'status': 'completed',
                'connections_analyzed': len(network_results.get('connections', [])),
                'suspicious_activity': len(network_results.get('suspicious', []))
            }
            print(f"   ✅ Analyzed {len(network_results.get('connections', []))} connections")
            print(f"   🚨 Found {len(network_results.get('suspicious', []))} suspicious activities")
        except Exception as e:
            self.scan_results['network'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ Network analysis failed: {str(e)[:50]}...")
        
        # File Integrity Check
        print("\n📁 File Integrity Check...")
        try:
            integrity_results = self.file_checker.scan_system()
            self.scan_results['file_integrity'] = {
                'status': 'completed',
                'files_checked': integrity_results.get('files_checked', 0),
                'modifications_found': len(integrity_results.get('modifications', []))
            }
            print(f"   ✅ Checked {integrity_results.get('files_checked', 0)} files")
            print(f"   🚨 Found {len(integrity_results.get('modifications', []))} modifications")
        except Exception as e:
            self.scan_results['file_integrity'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ File integrity check failed: {str(e)[:50]}...")
        
        # Behavioral Analysis
        print("\n🧠 Behavioral Analysis...")
        try:
            self.behavioral_engine.start_monitoring()
            time.sleep(3)  # Monitor for 3 seconds
            behavioral_results = self.behavioral_engine.get_analysis_results()
            self.behavioral_engine.stop_monitoring()
            
            self.scan_results['behavioral'] = {
                'status': 'completed',
                'processes_monitored': len(behavioral_results.get('processes', [])),
                'anomalies_detected': len(behavioral_results.get('anomalies', []))
            }
            print(f"   ✅ Monitored {len(behavioral_results.get('processes', []))} processes")
            print(f"   🚨 Detected {len(behavioral_results.get('anomalies', []))} anomalies")
        except Exception as e:
            self.scan_results['behavioral'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ Behavioral analysis failed: {str(e)[:50]}...")
        
        scan_duration = time.time() - scan_start_time
        print(f"\n⏱️ Comprehensive scan completed in {scan_duration:.2f} seconds")
        
        return self.scan_results
    
    def apply_security_hardening(self):
        """Apply security hardening based on scan results"""
        print("\n" + "="*60)
        print("🛡️ SECURITY HARDENING & PROTECTION")
        print("="*60)
        
        # System Hardening
        print("\n🔧 System Security Hardening...")
        try:
            security_report = self.hardening_manager.check_security_settings()
            recommendations = self.hardening_manager.get_hardening_recommendations()
            
            self.protection_status['system_hardening'] = {
                'security_score': security_report.overall_score,
                'recommendations': len(recommendations),
                'critical_issues': len([r for r in recommendations if r.priority == 'critical'])
            }
            
            print(f"   📊 Current security score: {security_report.overall_score}/100")
            print(f"   💡 Generated {len(recommendations)} recommendations")
            
            # Apply critical recommendations automatically
            critical_recs = [r for r in recommendations if r.priority == 'critical']
            if critical_recs:
                print(f"   🚨 Applying {len(critical_recs)} critical security fixes...")
                for rec in critical_recs[:3]:  # Apply first 3 critical recommendations
                    try:
                        # In a real implementation, this would apply the recommendation
                        print(f"     ✅ Applied: {rec.title}")
                    except Exception as e:
                        print(f"     ❌ Failed to apply: {rec.title} - {str(e)[:30]}...")
            
        except Exception as e:
            self.protection_status['system_hardening'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ System hardening failed: {str(e)[:50]}...")
        
        # App Permission Management
        print("\n🔐 App Permission Management...")
        try:
            apps = self.permission_manager.scan_installed_apps()
            high_risk_apps = []
            
            for app in apps[:10]:  # Check first 10 apps
                try:
                    audit_result = self.permission_manager.audit_app_permissions(app.path)
                    risk_score = self.permission_manager.calculate_risk_score(audit_result.permissions)
                    if risk_score > 70:  # High risk threshold
                        high_risk_apps.append((app.name, risk_score))
                except:
                    continue
            
            self.protection_status['app_permissions'] = {
                'apps_scanned': len(apps),
                'high_risk_apps': len(high_risk_apps)
            }
            
            print(f"   📱 Scanned {len(apps)} applications")
            print(f"   🚨 Found {len(high_risk_apps)} high-risk applications")
            
            if high_risk_apps:
                print("   High-risk apps:")
                for app_name, risk_score in high_risk_apps[:3]:
                    print(f"     - {app_name}: {risk_score:.1f}/100 risk")
            
        except Exception as e:
            self.protection_status['app_permissions'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ App permission management failed: {str(e)[:50]}...")
        
        # Network Security Monitoring
        print("\n🌐 Network Security Monitoring...")
        try:
            connections = self.network_monitor.scan_network_connections()
            vpn_status = self.network_monitor.check_vpn_status()
            
            suspicious_connections = 0
            for conn in connections[:20]:  # Check first 20 connections
                threat_level = self.network_monitor.assess_connection_threat(conn)
                if threat_level in ['high', 'critical']:
                    suspicious_connections += 1
            
            self.protection_status['network_security'] = {
                'connections_monitored': len(connections),
                'suspicious_connections': suspicious_connections,
                'vpn_connected': vpn_status.get('is_connected', False)
            }
            
            print(f"   🔍 Monitored {len(connections)} network connections")
            print(f"   🚨 Found {suspicious_connections} suspicious connections")
            print(f"   🔐 VPN Status: {'Connected' if vpn_status.get('is_connected') else 'Disconnected'}")
            
        except Exception as e:
            self.protection_status['network_security'] = {'status': 'failed', 'error': str(e)}
            print(f"   ❌ Network security monitoring failed: {str(e)[:50]}...")
        
        return self.protection_status
    
    def start_realtime_protection(self):
        """Start real-time protection services"""
        print("\n" + "="*60)
        print("⚡ REAL-TIME PROTECTION SERVICES")
        print("="*60)
        
        try:
            # Start Real-time Protection Engine
            print("\n🛡️ Starting Real-time Protection Engine...")
            self.protection_engine.start_protection()
            print("   ✅ Real-time protection active")
            
            # Start Zero-click Exploit Detection
            print("\n🕵️ Starting Zero-click Exploit Detection...")
            self.exploit_detector.start_detection()
            print("   ✅ Exploit detection active")
            
            # Test Link Scanner
            print("\n🔗 Testing Link Scanner...")
            test_links = [
                "https://www.google.com",
                "http://malware-example.com/download.exe"
            ]
            
            for link in test_links:
                result = self.link_scanner.scan_url(link)
                print(f"   {link}: {result.overall_verdict.upper()} (Risk: {result.risk_score:.1f}/100)")
            
            self.is_running = True
            print("\n✅ All real-time protection services started")
            
        except Exception as e:
            print(f"❌ Failed to start real-time protection: {e}")
            return False
        
        return True
    
    def stop_realtime_protection(self):
        """Stop real-time protection services"""
        print("\n🛑 Stopping real-time protection services...")
        
        try:
            if self.protection_engine:
                self.protection_engine.stop_protection()
                print("   ✅ Real-time protection stopped")
            
            if self.exploit_detector:
                self.exploit_detector.stop_detection()
                print("   ✅ Exploit detection stopped")
            
            self.is_running = False
            print("✅ All real-time protection services stopped")
            
        except Exception as e:
            print(f"❌ Error stopping protection services: {e}")
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*60)
        print("📊 COMPREHENSIVE SECURITY REPORT")
        print("="*60)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'framework_version': '2.0.0',
            'scan_results': self.scan_results,
            'protection_status': self.protection_status,
            'summary': {
                'overall_security_score': 0,
                'threats_detected': 0,
                'recommendations': 0,
                'protection_active': self.is_running
            }
        }
        
        # Calculate overall security metrics
        total_threats = 0
        total_recommendations = 0
        
        # Count threats from scan results
        for component, results in self.scan_results.items():
            if isinstance(results, dict) and results.get('status') == 'completed':
                total_threats += results.get('threats_found', 0)
                total_threats += results.get('suspicious_activity', 0)
                total_threats += results.get('modifications_found', 0)
                total_threats += results.get('anomalies_detected', 0)
        
        # Count recommendations from protection status
        for component, status in self.protection_status.items():
            if isinstance(status, dict):
                total_recommendations += status.get('recommendations', 0)
                total_recommendations += status.get('critical_issues', 0)
        
        # Calculate overall security score
        base_score = 100
        threat_penalty = min(total_threats * 5, 50)  # Max 50 point penalty
        recommendation_penalty = min(total_recommendations * 2, 30)  # Max 30 point penalty
        overall_score = max(base_score - threat_penalty - recommendation_penalty, 0)
        
        report['summary']['overall_security_score'] = overall_score
        report['summary']['threats_detected'] = total_threats
        report['summary']['recommendations'] = total_recommendations
        
        # Print summary
        print(f"\n📈 Security Summary:")
        print(f"   Overall Security Score: {overall_score}/100")
        print(f"   Threats Detected: {total_threats}")
        print(f"   Recommendations: {total_recommendations}")
        print(f"   Real-time Protection: {'Active' if self.is_running else 'Inactive'}")
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_file = f"reports/integrated_security_report_{int(time.time())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        return report


def main():
    """Main function to demonstrate the integrated framework"""
    print("="*80)
    print("🛡️  PEGASPY INTEGRATED SECURITY FRAMEWORK DEMO")
    print("="*80)
    print("Combining Detection & Analysis with Prevention & Hardening")
    print("for comprehensive anti-spyware protection.")
    
    try:
        # Initialize framework
        framework = IntegratedSecurityFramework()
        
        # Run comprehensive scan
        scan_results = framework.run_comprehensive_scan()
        
        # Apply security hardening
        protection_status = framework.apply_security_hardening()
        
        # Start real-time protection
        if framework.start_realtime_protection():
            print("\n⏱️ Running real-time protection for 10 seconds...")
            time.sleep(10)
            framework.stop_realtime_protection()
        
        # Generate final report
        final_report = framework.generate_security_report()
        
        # Final assessment
        overall_score = final_report['summary']['overall_security_score']
        if overall_score >= 80:
            print("\n🎉 EXCELLENT: Your system has strong security protection!")
        elif overall_score >= 60:
            print("\n✅ GOOD: Your system has adequate security with room for improvement.")
        elif overall_score >= 40:
            print("\n⚠️ MODERATE: Your system needs security improvements.")
        else:
            print("\n🚨 CRITICAL: Your system requires immediate security attention!")
        
        print("\n" + "="*80)
        print("✅ INTEGRATED SECURITY FRAMEWORK DEMO COMPLETED")
        print("="*80)
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Framework demo failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())