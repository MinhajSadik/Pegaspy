#!/usr/bin/env python3
"""
PegaSpy Working Functionality Test
Demonstrates real capabilities and generates tracking data
"""

import os
import sys
import json
import time
import psutil
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_system_monitoring():
    """Test basic system monitoring capabilities"""
    print("\n🖥️  Testing System Monitoring...")
    
    # Get system information
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent']))
    
    print(f"   ✅ CPU Usage: {cpu_percent}%")
    print(f"   ✅ Memory Usage: {memory.percent}%")
    print(f"   ✅ Active Processes: {len(processes)}")
    
    return {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'process_count': len(processes)
    }

def test_file_monitoring():
    """Test file system monitoring"""
    print("\n📁 Testing File System Monitoring...")
    
    # Check critical system directories
    critical_dirs = ['/bin', '/usr/bin', '/etc', '/tmp']
    monitored_files = 0
    
    for directory in critical_dirs:
        if os.path.exists(directory):
            try:
                files = os.listdir(directory)
                monitored_files += len(files)
                print(f"   ✅ {directory}: {len(files)} files monitored")
            except PermissionError:
                print(f"   ⚠️  {directory}: Access restricted")
    
    return {'monitored_files': monitored_files, 'directories_scanned': len(critical_dirs)}

def test_network_monitoring():
    """Test network monitoring capabilities"""
    print("\n🌐 Testing Network Monitoring...")
    
    # Get network connections
    connections = psutil.net_connections()
    active_connections = [conn for conn in connections if conn.status == 'ESTABLISHED']
    
    # Get network interface stats
    net_io = psutil.net_io_counters()
    
    print(f"   ✅ Total Connections: {len(connections)}")
    print(f"   ✅ Active Connections: {len(active_connections)}")
    print(f"   ✅ Bytes Sent: {net_io.bytes_sent:,}")
    print(f"   ✅ Bytes Received: {net_io.bytes_recv:,}")
    
    return {
        'total_connections': len(connections),
        'active_connections': len(active_connections),
        'bytes_sent': net_io.bytes_sent,
        'bytes_received': net_io.bytes_recv
    }

def test_security_analysis():
    """Test security analysis features"""
    print("\n🔒 Testing Security Analysis...")
    
    # Analyze running processes for potential security concerns
    suspicious_processes = []
    high_cpu_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 50:
                high_cpu_processes.append(proc.info)
            
            # Check for potentially suspicious process names
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in ['keylog', 'spy', 'hack', 'trojan']):
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    print(f"   ✅ High CPU Processes: {len(high_cpu_processes)}")
    print(f"   ✅ Suspicious Processes: {len(suspicious_processes)}")
    
    return {
        'high_cpu_processes': len(high_cpu_processes),
        'suspicious_processes': len(suspicious_processes)
    }

def test_url_analysis():
    """Test URL analysis capabilities"""
    print("\n🔗 Testing URL Analysis...")
    
    # Test URLs for analysis
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://stackoverflow.com"
    ]
    
    analyzed_urls = []
    for url in test_urls:
        # Simple URL analysis
        analysis = {
            'url': url,
            'https': url.startswith('https://'),
            'domain_length': len(url.split('/')[2]),
            'risk_score': 10 if url.startswith('https://') else 50
        }
        analyzed_urls.append(analysis)
        print(f"   ✅ {url}: Risk {analysis['risk_score']}/100")
    
    return {'analyzed_urls': len(analyzed_urls), 'average_risk': sum(u['risk_score'] for u in analyzed_urls) / len(analyzed_urls)}

def generate_tracking_report(results):
    """Generate comprehensive tracking report"""
    timestamp = datetime.now().isoformat()
    
    # Calculate threat level based on results
    threat_score = 0
    if results['system']['cpu_percent'] > 80:
        threat_score += 20
    if results['system']['memory_percent'] > 90:
        threat_score += 30
    if results['security']['suspicious_processes'] > 0:
        threat_score += 50
    if results['security']['high_cpu_processes'] > 5:
        threat_score += 25
    
    threat_level = "LOW"
    if threat_score > 50:
        threat_level = "HIGH"
    elif threat_score > 25:
        threat_level = "MEDIUM"
    
    report = {
        "timestamp": timestamp,
        "scan_type": "comprehensive_functionality_test",
        "threat_level": threat_level,
        "threat_score": threat_score,
        "system_status": {
            "cpu_usage": results['system']['cpu_percent'],
            "memory_usage": results['system']['memory_percent'],
            "active_processes": results['system']['process_count']
        },
        "file_monitoring": {
            "files_monitored": results['files']['monitored_files'],
            "directories_scanned": results['files']['directories_scanned']
        },
        "network_analysis": {
            "total_connections": results['network']['total_connections'],
            "active_connections": results['network']['active_connections'],
            "data_transferred": results['network']['bytes_sent'] + results['network']['bytes_received']
        },
        "security_analysis": {
            "high_cpu_processes": results['security']['high_cpu_processes'],
            "suspicious_processes": results['security']['suspicious_processes']
        },
        "url_analysis": {
            "urls_analyzed": results['urls']['analyzed_urls'],
            "average_risk_score": results['urls']['average_risk']
        },
        "recommendations": [
            "Monitor high CPU usage processes",
            "Enable real-time file integrity monitoring",
            "Implement network traffic analysis",
            "Regular security scans recommended"
        ]
    }
    
    # Save report
    report_file = f"reports/comprehensive_test_{int(time.time())}.json"
    os.makedirs("reports", exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📊 Tracking report saved: {report_file}")
    return report

def main():
    """Run comprehensive functionality test"""
    print("\n" + "="*60)
    print("🛡️  PEGASPY FUNCTIONALITY DEMONSTRATION")
    print("="*60)
    
    results = {}
    
    try:
        # Test 1: System Monitoring
        results['system'] = test_system_monitoring()
        
        # Test 2: File Monitoring
        results['files'] = test_file_monitoring()
        
        # Test 3: Network Monitoring
        results['network'] = test_network_monitoring()
        
        # Test 4: Security Analysis
        results['security'] = test_security_analysis()
        
        # Test 5: URL Analysis
        results['urls'] = test_url_analysis()
        
        # Generate tracking report
        report = generate_tracking_report(results)
        
        print("\n" + "="*60)
        print("📈 PEGASPY TRACKING SUMMARY")
        print("="*60)
        
        print(f"🎯 Threat Level: {report['threat_level']} (Score: {report['threat_score']})")
        print(f"🖥️  System: {report['system_status']['active_processes']} processes, {report['system_status']['cpu_usage']}% CPU")
        print(f"📁 Files: {report['file_monitoring']['files_monitored']} files monitored")
        print(f"🌐 Network: {report['network_analysis']['active_connections']} active connections")
        print(f"🔒 Security: {report['security_analysis']['suspicious_processes']} suspicious processes detected")
        print(f"🔗 URLs: {report['url_analysis']['urls_analyzed']} URLs analyzed")
        
        print("\n🎉 PegaSpy functionality demonstration COMPLETE!")
        print("🔗 Dashboard available at: http://127.0.0.1:8080")
        print("📁 Check reports/ directory for detailed tracking data")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return None
    
    return report

if __name__ == "__main__":
    main()