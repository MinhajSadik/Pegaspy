#!/usr/bin/env python3
"""Test script for PegaSpy Detection & Analysis Framework

This script tests the basic functionality of all detection modules.
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported successfully"""
    print("🔍 Testing module imports...")
    
    try:
        from detection_analysis.mobile_scanner import MobileDeviceScanner
        print("✅ MobileDeviceScanner imported successfully")
    except Exception as e:
        print(f"❌ Failed to import MobileDeviceScanner: {e}")
        return False
    
    try:
        from detection_analysis.network_analyzer import NetworkTrafficAnalyzer
        print("✅ NetworkTrafficAnalyzer imported successfully")
    except Exception as e:
        print(f"❌ Failed to import NetworkTrafficAnalyzer: {e}")
        return False
    
    try:
        from detection_analysis.file_integrity import FileIntegrityChecker
        print("✅ FileIntegrityChecker imported successfully")
    except Exception as e:
        print(f"❌ Failed to import FileIntegrityChecker: {e}")
        return False
    
    try:
        from detection_analysis.behavioral_engine import BehavioralAnalysisEngine
        print("✅ BehavioralAnalysisEngine imported successfully")
    except Exception as e:
        print(f"❌ Failed to import BehavioralAnalysisEngine: {e}")
        return False
    
    return True

def test_mobile_scanner():
    """Test MobileDeviceScanner basic functionality"""
    print("\n📱 Testing MobileDeviceScanner...")
    
    try:
        from detection_analysis.mobile_scanner import MobileDeviceScanner
        
        scanner = MobileDeviceScanner()
        print("✅ MobileDeviceScanner initialized")
        
        # Test process scanning
        processes = scanner.scan_processes()
        print(f"✅ Process scan completed: {len(processes)} processes found")
        
        # Test network connections
        connections = scanner.scan_network_connections()
        print(f"✅ Network scan completed: {len(connections)} connections found")
        
        return True
        
    except Exception as e:
        print(f"❌ MobileDeviceScanner test failed: {e}")
        return False

def test_file_integrity():
    """Test FileIntegrityChecker basic functionality"""
    print("\n📁 Testing FileIntegrityChecker...")
    
    try:
        from detection_analysis.file_integrity import FileIntegrityChecker
        
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = FileIntegrityChecker()
            print("✅ FileIntegrityChecker initialized")
            
            # Create a test file
            test_file = Path(temp_dir) / "test_file.txt"
            test_file.write_text("This is a test file")
            
            # Test file scanning
            changes = checker.scan_directory(temp_dir)
            print(f"✅ Directory scan completed: {len(changes)} changes detected")
            
            # Test file info retrieval
            file_info = checker.get_file_info(str(test_file))
            print(f"✅ File info retrieved: {file_info.size} bytes")
            
            return True
        
    except Exception as e:
        print(f"❌ FileIntegrityChecker test failed: {e}")
        return False

def test_network_analyzer():
    """Test NetworkTrafficAnalyzer basic functionality"""
    print("\n🌐 Testing NetworkTrafficAnalyzer...")
    
    try:
        from detection_analysis.network_analyzer import NetworkTrafficAnalyzer
        
        analyzer = NetworkTrafficAnalyzer()
        print("✅ NetworkTrafficAnalyzer initialized")
        
        # Test suspicious IP detection
        test_ips = ['192.168.1.1', '8.8.8.8', '127.0.0.1']
        for ip in test_ips:
            is_suspicious = analyzer.is_suspicious_ip(ip)
            print(f"✅ IP {ip} suspicious check: {is_suspicious}")
        
        # Test report generation
        report = analyzer.generate_report()
        print(f"✅ Report generated: {report['total_packets']} packets analyzed")
        
        return True
        
    except Exception as e:
        print(f"❌ NetworkTrafficAnalyzer test failed: {e}")
        return False

def test_behavioral_engine():
    """Test BehavioralAnalysisEngine basic functionality"""
    print("\n🧠 Testing BehavioralAnalysisEngine...")
    
    try:
        from detection_analysis.behavioral_engine import BehavioralAnalysisEngine
        
        engine = BehavioralAnalysisEngine()
        print("✅ BehavioralAnalysisEngine initialized")
        
        # Test pattern loading
        patterns = engine.suspicious_patterns
        print(f"✅ Loaded {len(patterns)} suspicious patterns")
        
        # Test process behavior collection (brief test)
        behaviors = engine.collect_process_behaviors()
        print(f"✅ Process behaviors collected: {len(behaviors)} processes")
        
        # Test report generation
        report = engine.generate_behavioral_report()
        print(f"✅ Behavioral report generated: {report.processes_monitored} processes monitored")
        
        return True
        
    except Exception as e:
        print(f"❌ BehavioralAnalysisEngine test failed: {e}")
        return False

def test_main_framework():
    """Test the main PegaSpy framework"""
    print("\n🛡️ Testing PegaSpy Framework...")
    
    try:
        from main import PegaSpyFramework
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            framework = PegaSpyFramework(output_dir=temp_dir)
            print("✅ PegaSpyFramework initialized")
            
            # Test quick scan (this might take a moment)
            print("🔍 Running quick scan test...")
            results = framework.run_quick_scan()
            
            print(f"✅ Quick scan completed")
            print(f"   • Scan type: {results['scan_type']}")
            print(f"   • Duration: {results['scan_duration']:.2f} seconds")
            
            if 'mobile_scan' in results['results']:
                mobile = results['results']['mobile_scan']
                if 'error' not in mobile:
                    print(f"   • Mobile scan: {mobile.get('threat_level', 'Unknown')} threat level")
                else:
                    print(f"   • Mobile scan error: {mobile['error']}")
            
            return True
        
    except Exception as e:
        print(f"❌ PegaSpyFramework test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 PegaSpy Detection & Analysis Framework - Test Suite")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Mobile Scanner", test_mobile_scanner),
        ("File Integrity Checker", test_file_integrity),
        ("Network Analyzer", test_network_analyzer),
        ("Behavioral Engine", test_behavioral_engine),
        ("Main Framework", test_main_framework)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            if test_func():
                print(f"✅ {test_name} - PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} - FAILED")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"🧪 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The framework is ready to use.")
        print("\n💡 Next steps:")
        print("   1. Install required dependencies: pip install -r requirements.txt")
        print("   2. Run a quick scan: python main.py --quick")
        print("   3. Run a comprehensive scan: python main.py --comprehensive")
    else:
        print(f"⚠️  {total - passed} tests failed. Please check the errors above.")
        print("\n💡 Common issues:")
        print("   • Missing dependencies (run: pip install -r requirements.txt)")
        print("   • Permission issues (some features require elevated privileges)")
        print("   • Platform-specific limitations")
    
    print("\n" + "=" * 60)
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)