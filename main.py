#!/usr/bin/env python3
"""PegaSpy - Anti-Spyware Defense Framework

Main CLI interface for running comprehensive spyware detection and analysis.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

from loguru import logger

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detection_analysis.mobile_scanner import MobileDeviceScanner
from detection_analysis.network_analyzer import NetworkTrafficAnalyzer
from detection_analysis.file_integrity import FileIntegrityChecker
from detection_analysis.behavioral_engine import BehavioralAnalysisEngine


class PegaSpyFramework:
    """Main PegaSpy framework coordinator"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.mobile_scanner = MobileDeviceScanner()
        self.network_analyzer = NetworkTrafficAnalyzer()
        self.file_checker = FileIntegrityChecker()
        self.behavioral_engine = BehavioralAnalysisEngine()
        
        # Configure logging
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_file = self.output_dir / "pegaspy.log"
        
        logger.remove()  # Remove default handler
        logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            level="INFO"
        )
        logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="DEBUG",
            rotation="10 MB"
        )
    
    def run_quick_scan(self) -> dict:
        """Run a quick security scan"""
        logger.info("Starting PegaSpy Quick Scan")
        start_time = time.time()
        
        results = {
            'scan_type': 'quick',
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        try:
            # Mobile/Process Scanner
            logger.info("Running process scan...")
            mobile_result = self.mobile_scanner.perform_full_scan()
            results['results']['mobile_scan'] = {
                'threat_level': mobile_result.threat_level,
                'suspicious_processes': len(mobile_result.suspicious_processes),
                'network_connections': len(mobile_result.network_connections),
                'file_modifications': len(mobile_result.file_modifications)
            }
            
            # Save detailed mobile scan results
            mobile_report_file = self.output_dir / f"mobile_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.mobile_scanner.save_scan_results(mobile_result, str(mobile_report_file))
            
        except Exception as e:
            logger.error(f"Mobile scan failed: {e}")
            results['results']['mobile_scan'] = {'error': str(e)}
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        results['scan_duration'] = scan_duration
        
        logger.info(f"Quick scan completed in {scan_duration:.2f} seconds")
        return results
    
    def run_comprehensive_scan(self, network_duration: int = 300, behavioral_duration: int = 600) -> dict:
        """Run a comprehensive security scan"""
        logger.info("Starting PegaSpy Comprehensive Scan")
        start_time = time.time()
        
        results = {
            'scan_type': 'comprehensive',
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        try:
            # 1. Mobile/Process Scanner
            logger.info("Running comprehensive process scan...")
            mobile_result = self.mobile_scanner.perform_full_scan()
            results['results']['mobile_scan'] = {
                'threat_level': mobile_result.threat_level,
                'suspicious_processes': len(mobile_result.suspicious_processes),
                'network_connections': len(mobile_result.network_connections),
                'file_modifications': len(mobile_result.file_modifications),
                'recommendations': mobile_result.recommendations
            }
            
            # Save mobile scan results
            mobile_report_file = self.output_dir / f"mobile_scan_comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.mobile_scanner.save_scan_results(mobile_result, str(mobile_report_file))
            
        except Exception as e:
            logger.error(f"Mobile scan failed: {e}")
            results['results']['mobile_scan'] = {'error': str(e)}
        
        try:
            # 2. File Integrity Check
            logger.info("Running file integrity check...")
            
            # Define scan paths based on OS
            if os.name == 'nt':  # Windows
                scan_paths = ['C:\\Windows\\System32', 'C:\\Program Files', 'C:\\Users']
            else:  # Unix-like
                scan_paths = ['/bin', '/usr/bin', '/etc', '/home', '/tmp']
            
            integrity_result = self.file_checker.generate_integrity_report(scan_paths)
            results['results']['file_integrity'] = {
                'total_files_scanned': integrity_result.total_files_scanned,
                'changes_detected': integrity_result.changes_detected,
                'suspicious_changes': integrity_result.suspicious_changes,
                'high_risk_changes': len(integrity_result.high_risk_changes),
                'recommendations': integrity_result.recommendations
            }
            
            # Save file integrity results
            integrity_report_file = self.output_dir / f"file_integrity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.file_checker.save_report(integrity_result, str(integrity_report_file))
            
        except Exception as e:
            logger.error(f"File integrity check failed: {e}")
            results['results']['file_integrity'] = {'error': str(e)}
        
        try:
            # 3. Network Traffic Analysis
            logger.info(f"Starting network monitoring for {network_duration} seconds...")
            self.network_analyzer.start_monitoring(duration=network_duration)
            
            # Wait for network monitoring to complete
            time.sleep(network_duration + 5)
            
            network_report = self.network_analyzer.generate_report()
            results['results']['network_analysis'] = {
                'total_packets': network_report['total_packets'],
                'total_flows': network_report['total_flows'],
                'suspicious_flows': network_report['suspicious_flows'],
                'alerts': network_report['alerts'],
                'dns_analysis': network_report['dns_analysis']
            }
            
            # Save network analysis results
            network_report_file = self.output_dir / f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.network_analyzer.save_report(str(network_report_file))
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            results['results']['network_analysis'] = {'error': str(e)}
        
        try:
            # 4. Behavioral Analysis
            logger.info(f"Starting behavioral monitoring for {behavioral_duration} seconds...")
            self.behavioral_engine.start_monitoring()
            
            # Wait for behavioral monitoring
            time.sleep(behavioral_duration)
            self.behavioral_engine.stop_monitoring()
            
            behavioral_report = self.behavioral_engine.generate_behavioral_report()
            results['results']['behavioral_analysis'] = {
                'processes_monitored': behavioral_report.processes_monitored,
                'alerts_generated': behavioral_report.alerts_generated,
                'high_risk_processes': len(behavioral_report.high_risk_processes),
                'behavioral_patterns': behavioral_report.behavioral_patterns,
                'recommendations': behavioral_report.recommendations
            }
            
            # Save behavioral analysis results
            behavioral_report_file = self.output_dir / f"behavioral_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.behavioral_engine.save_report(behavioral_report, str(behavioral_report_file))
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            results['results']['behavioral_analysis'] = {'error': str(e)}
        
        # Calculate total scan duration
        scan_duration = time.time() - start_time
        results['scan_duration'] = scan_duration
        
        # Generate overall threat assessment
        results['threat_assessment'] = self._generate_threat_assessment(results['results'])
        
        logger.info(f"Comprehensive scan completed in {scan_duration:.2f} seconds")
        return results
    
    def _generate_threat_assessment(self, scan_results: dict) -> dict:
        """Generate overall threat assessment from all scan results"""
        threat_score = 0
        threat_indicators = []
        
        # Mobile scan assessment
        if 'mobile_scan' in scan_results and 'error' not in scan_results['mobile_scan']:
            mobile = scan_results['mobile_scan']
            if mobile.get('threat_level') == 'HIGH':
                threat_score += 40
                threat_indicators.append('High-risk processes detected')
            elif mobile.get('threat_level') == 'MEDIUM':
                threat_score += 20
                threat_indicators.append('Medium-risk processes detected')
            
            if mobile.get('suspicious_processes', 0) > 0:
                threat_score += mobile['suspicious_processes'] * 5
                threat_indicators.append(f"{mobile['suspicious_processes']} suspicious processes")
        
        # File integrity assessment
        if 'file_integrity' in scan_results and 'error' not in scan_results['file_integrity']:
            integrity = scan_results['file_integrity']
            if integrity.get('suspicious_changes', 0) > 0:
                threat_score += integrity['suspicious_changes'] * 3
                threat_indicators.append(f"{integrity['suspicious_changes']} suspicious file changes")
            
            if integrity.get('high_risk_changes', 0) > 0:
                threat_score += integrity['high_risk_changes'] * 10
                threat_indicators.append(f"{integrity['high_risk_changes']} high-risk file changes")
        
        # Network analysis assessment
        if 'network_analysis' in scan_results and 'error' not in scan_results['network_analysis']:
            network = scan_results['network_analysis']
            if network.get('suspicious_flows', 0) > 0:
                threat_score += network['suspicious_flows'] * 5
                threat_indicators.append(f"{network['suspicious_flows']} suspicious network flows")
            
            if network.get('alerts', 0) > 0:
                threat_score += network['alerts'] * 8
                threat_indicators.append(f"{network['alerts']} network alerts")
        
        # Behavioral analysis assessment
        if 'behavioral_analysis' in scan_results and 'error' not in scan_results['behavioral_analysis']:
            behavioral = scan_results['behavioral_analysis']
            if behavioral.get('high_risk_processes', 0) > 0:
                threat_score += behavioral['high_risk_processes'] * 15
                threat_indicators.append(f"{behavioral['high_risk_processes']} high-risk behavioral patterns")
            
            if behavioral.get('alerts_generated', 0) > 0:
                threat_score += behavioral['alerts_generated'] * 10
                threat_indicators.append(f"{behavioral['alerts_generated']} behavioral alerts")
        
        # Determine overall threat level
        if threat_score >= 100:
            threat_level = "CRITICAL"
        elif threat_score >= 60:
            threat_level = "HIGH"
        elif threat_score >= 30:
            threat_level = "MEDIUM"
        elif threat_score >= 10:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        return {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'threat_indicators': threat_indicators,
            'recommendation': self._get_threat_recommendation(threat_level)
        }
    
    def _get_threat_recommendation(self, threat_level: str) -> str:
        """Get recommendation based on threat level"""
        recommendations = {
            'CRITICAL': 'IMMEDIATE ACTION REQUIRED: Disconnect from network and perform full system remediation',
            'HIGH': 'Urgent investigation required. Consider isolating system and running additional scans',
            'MEDIUM': 'Investigate detected issues and monitor system closely',
            'LOW': 'Minor issues detected. Continue regular monitoring',
            'CLEAN': 'System appears clean. Maintain regular security practices'
        }
        return recommendations.get(threat_level, 'Unknown threat level')
    
    def save_summary_report(self, results: dict, filename: str = None) -> str:
        """Save summary report to file"""
        if filename is None:
            filename = f"pegaspy_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_path = self.output_dir / filename
        
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Summary report saved to {report_path}")
        return str(report_path)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="PegaSpy - Anti-Spyware Defense Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --quick                    # Quick scan
  python main.py --comprehensive            # Full comprehensive scan
  python main.py --comprehensive --network-time 600 --behavioral-time 900
        """
    )
    
    parser.add_argument(
        '--quick', action='store_true',
        help='Run quick security scan (process and basic checks only)'
    )
    
    parser.add_argument(
        '--comprehensive', action='store_true',
        help='Run comprehensive security scan (all modules)'
    )
    
    parser.add_argument(
        '--network-time', type=int, default=300,
        help='Network monitoring duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--behavioral-time', type=int, default=600,
        help='Behavioral monitoring duration in seconds (default: 600)'
    )
    
    parser.add_argument(
        '--output-dir', type=str, default='reports',
        help='Output directory for reports (default: reports)'
    )
    
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if not args.quick and not args.comprehensive:
        parser.print_help()
        sys.exit(1)
    
    # Initialize framework
    framework = PegaSpyFramework(output_dir=args.output_dir)
    
    if args.verbose:
        logger.remove()
        logger.add(sys.stdout, level="DEBUG")
    
    print("\n" + "="*60)
    print("🛡️  PegaSpy - Anti-Spyware Defense Framework")
    print("="*60)
    print("Protecting against advanced spyware threats\n")
    
    try:
        if args.quick:
            print("🔍 Running Quick Security Scan...\n")
            results = framework.run_quick_scan()
        else:
            print(f"🔍 Running Comprehensive Security Scan...")
            print(f"📡 Network monitoring: {args.network_time} seconds")
            print(f"🧠 Behavioral monitoring: {args.behavioral_time} seconds\n")
            results = framework.run_comprehensive_scan(
                network_duration=args.network_time,
                behavioral_duration=args.behavioral_time
            )
        
        # Display results summary
        print("\n" + "="*60)
        print("📊 SCAN RESULTS SUMMARY")
        print("="*60)
        
        if 'threat_assessment' in results:
            assessment = results['threat_assessment']
            threat_level = assessment['threat_level']
            
            # Color coding for threat levels
            level_colors = {
                'CLEAN': '🟢',
                'LOW': '🟡',
                'MEDIUM': '🟠',
                'HIGH': '🔴',
                'CRITICAL': '🚨'
            }
            
            print(f"\n{level_colors.get(threat_level, '⚪')} Overall Threat Level: {threat_level}")
            print(f"📈 Threat Score: {assessment['threat_score']}")
            print(f"💡 Recommendation: {assessment['recommendation']}")
            
            if assessment['threat_indicators']:
                print(f"\n⚠️  Threat Indicators:")
                for indicator in assessment['threat_indicators']:
                    print(f"   • {indicator}")
        
        # Display module results
        if 'results' in results:
            scan_results = results['results']
            
            if 'mobile_scan' in scan_results and 'error' not in scan_results['mobile_scan']:
                mobile = scan_results['mobile_scan']
                print(f"\n📱 Process Scan: {mobile.get('threat_level', 'Unknown')} threat level")
                print(f"   • Suspicious processes: {mobile.get('suspicious_processes', 0)}")
                print(f"   • Network connections: {mobile.get('network_connections', 0)}")
            
            if 'file_integrity' in scan_results and 'error' not in scan_results['file_integrity']:
                integrity = scan_results['file_integrity']
                print(f"\n📁 File Integrity: {integrity.get('changes_detected', 0)} changes detected")
                print(f"   • Suspicious changes: {integrity.get('suspicious_changes', 0)}")
                print(f"   • High-risk changes: {integrity.get('high_risk_changes', 0)}")
            
            if 'network_analysis' in scan_results and 'error' not in scan_results['network_analysis']:
                network = scan_results['network_analysis']
                print(f"\n🌐 Network Analysis: {network.get('total_flows', 0)} flows analyzed")
                print(f"   • Suspicious flows: {network.get('suspicious_flows', 0)}")
                print(f"   • Alerts generated: {network.get('alerts', 0)}")
            
            if 'behavioral_analysis' in scan_results and 'error' not in scan_results['behavioral_analysis']:
                behavioral = scan_results['behavioral_analysis']
                print(f"\n🧠 Behavioral Analysis: {behavioral.get('processes_monitored', 0)} processes monitored")
                print(f"   • High-risk processes: {behavioral.get('high_risk_processes', 0)}")
                print(f"   • Alerts generated: {behavioral.get('alerts_generated', 0)}")
        
        print(f"\n⏱️  Total scan duration: {results.get('scan_duration', 0):.2f} seconds")
        
        # Save summary report
        report_path = framework.save_summary_report(results)
        print(f"\n📄 Detailed reports saved to: {args.output_dir}/")
        print(f"📄 Summary report: {report_path}")
        
        print("\n" + "="*60)
        print("✅ Scan completed successfully!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"\n❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()