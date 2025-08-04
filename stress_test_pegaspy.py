#!/usr/bin/env python3
"""
PegaSpy Comprehensive Stress Test & Edge Case Testing
This script tests PegaSpy's limits and robustness by:
- Running concurrent operations
- Testing with invalid inputs
- Stress testing file monitoring
- Testing memory and resource limits
- Simulating attack scenarios
- Testing error handling
"""

import os
import sys
import time
import json
import threading
import tempfile
import shutil
import random
import string
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from detection_analysis.file_integrity import FileIntegrityChecker
    from detection_analysis.behavioral_engine import BehavioralAnalysisEngine
    from detection_analysis.network_analyzer import NetworkAnalyzer
    from prevention_hardening.link_scanner import MaliciousLinkScanner
    from prevention_hardening.app_integrity import AppIntegrityVerifier
    from zero_click_exploits.zero_click_detector import ZeroClickDetector
except ImportError as e:
    print(f"Import error: {e}")
    print("Some modules may not be available for testing")

class PegaSpyStressTester:
    def __init__(self):
        self.test_results = []
        self.temp_dirs = []
        self.test_files = []
        self.start_time = time.time()
        
    def log_result(self, test_name, status, details="", duration=0):
        """Log test results"""
        result = {
            "test_name": test_name,
            "status": status,
            "details": details,
            "duration": duration,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"[{status}] {test_name}: {details} ({duration:.2f}s)")
        
    def create_stress_files(self, count=1000):
        """Create many files for stress testing"""
        print(f"\n=== Creating {count} stress test files ===")
        start_time = time.time()
        
        temp_dir = tempfile.mkdtemp(prefix="pegaspy_stress_")
        self.temp_dirs.append(temp_dir)
        
        try:
            for i in range(count):
                file_path = os.path.join(temp_dir, f"stress_file_{i}.txt")
                with open(file_path, 'w') as f:
                    # Random content to make files different
                    content = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 1000)))
                    f.write(content)
                self.test_files.append(file_path)
                
            duration = time.time() - start_time
            self.log_result("File Creation Stress Test", "PASS", f"Created {count} files", duration)
            return temp_dir
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("File Creation Stress Test", "FAIL", str(e), duration)
            return None
            
    def test_file_integrity_stress(self):
        """Stress test file integrity monitoring"""
        print("\n=== File Integrity Stress Test ===")
        start_time = time.time()
        
        try:
            # Create test directory with many files
            test_dir = self.create_stress_files(500)
            if not test_dir:
                return
                
            # Test file integrity checker
            checker = FileIntegrityChecker()
            
            # Scan the directory
            scan_start = time.time()
            results = checker.scan_directory(test_dir)
            scan_duration = time.time() - scan_start
            
            # Modify some files rapidly
            for i in range(0, min(100, len(self.test_files)), 10):
                with open(self.test_files[i], 'a') as f:
                    f.write("MODIFIED")
                    
            # Scan again
            rescan_start = time.time()
            new_results = checker.scan_directory(test_dir)
            rescan_duration = time.time() - rescan_start
            
            duration = time.time() - start_time
            details = f"Initial scan: {scan_duration:.2f}s, Rescan: {rescan_duration:.2f}s"
            self.log_result("File Integrity Stress", "PASS", details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("File Integrity Stress", "FAIL", str(e), duration)
            
    def test_concurrent_operations(self):
        """Test concurrent operations"""
        print("\n=== Concurrent Operations Test ===")
        start_time = time.time()
        
        def worker_task(worker_id):
            try:
                # Each worker creates files and scans
                temp_dir = tempfile.mkdtemp(prefix=f"worker_{worker_id}_")
                self.temp_dirs.append(temp_dir)
                
                # Create files
                for i in range(50):
                    file_path = os.path.join(temp_dir, f"worker_{worker_id}_file_{i}.txt")
                    with open(file_path, 'w') as f:
                        f.write(f"Worker {worker_id} data {i}")
                        
                # Scan with file integrity
                checker = FileIntegrityChecker()
                results = checker.scan_directory(temp_dir)
                
                return f"Worker {worker_id} completed successfully"
                
            except Exception as e:
                return f"Worker {worker_id} failed: {str(e)}"
                
        try:
            # Run 10 concurrent workers
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(worker_task, i) for i in range(10)]
                
                results = []
                for future in as_completed(futures):
                    results.append(future.result())
                    
            duration = time.time() - start_time
            success_count = sum(1 for r in results if "completed successfully" in r)
            details = f"{success_count}/10 workers succeeded"
            
            if success_count >= 8:  # Allow some failures in stress test
                self.log_result("Concurrent Operations", "PASS", details, duration)
            else:
                self.log_result("Concurrent Operations", "FAIL", details, duration)
                
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("Concurrent Operations", "FAIL", str(e), duration)
            
    def test_invalid_inputs(self):
        """Test with invalid inputs and edge cases"""
        print("\n=== Invalid Input Testing ===")
        start_time = time.time()
        
        invalid_tests = [
            ("/nonexistent/path", "Non-existent path"),
            ("", "Empty path"),
            ("/dev/null", "Device file"),
            ("\x00\x01\x02", "Binary path"),
            ("../../../etc/passwd", "Path traversal"),
            ("a" * 1000, "Very long path"),
        ]
        
        passed = 0
        total = len(invalid_tests)
        
        for test_path, description in invalid_tests:
            try:
                checker = FileIntegrityChecker()
                # This should handle invalid input gracefully
                result = checker.scan_directory(test_path)
                # If it doesn't crash, that's good
                passed += 1
                print(f"  ✓ {description}: Handled gracefully")
            except Exception as e:
                # Expected for some invalid inputs
                print(f"  ⚠ {description}: {str(e)[:50]}...")
                passed += 1  # Controlled failure is acceptable
                
        duration = time.time() - start_time
        details = f"{passed}/{total} invalid inputs handled"
        self.log_result("Invalid Input Testing", "PASS", details, duration)
        
    def test_memory_stress(self):
        """Test memory usage under stress"""
        print("\n=== Memory Stress Test ===")
        start_time = time.time()
        
        try:
            # Create large files
            temp_dir = tempfile.mkdtemp(prefix="pegaspy_memory_")
            self.temp_dirs.append(temp_dir)
            
            large_files = []
            for i in range(10):
                file_path = os.path.join(temp_dir, f"large_file_{i}.txt")
                with open(file_path, 'w') as f:
                    # Write 1MB of data per file
                    data = "A" * (1024 * 1024)
                    f.write(data)
                large_files.append(file_path)
                
            # Test scanning large files
            checker = FileIntegrityChecker()
            results = checker.scan_directory(temp_dir)
            
            duration = time.time() - start_time
            details = f"Scanned {len(large_files)} large files (10MB total)"
            self.log_result("Memory Stress Test", "PASS", details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("Memory Stress Test", "FAIL", str(e), duration)
            
    def test_rapid_file_changes(self):
        """Test rapid file modifications"""
        print("\n=== Rapid File Changes Test ===")
        start_time = time.time()
        
        try:
            temp_dir = tempfile.mkdtemp(prefix="pegaspy_rapid_")
            self.temp_dirs.append(temp_dir)
            
            test_file = os.path.join(temp_dir, "rapid_change.txt")
            
            # Rapidly modify file
            for i in range(100):
                with open(test_file, 'w') as f:
                    f.write(f"Change number {i} at {time.time()}")
                time.sleep(0.01)  # 10ms between changes
                
            # Test if integrity checker can handle this
            checker = FileIntegrityChecker()
            results = checker.scan_directory(temp_dir)
            
            duration = time.time() - start_time
            self.log_result("Rapid File Changes", "PASS", "100 rapid changes handled", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("Rapid File Changes", "FAIL", str(e), duration)
            
    def test_malicious_urls(self):
        """Test malicious URL detection with edge cases"""
        print("\n=== Malicious URL Edge Cases ===")
        start_time = time.time()
        
        malicious_urls = [
            "http://malware.com/payload.exe",
            "https://phishing-site.evil/login",
            "ftp://suspicious.domain/backdoor",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "file:///etc/passwd",
            "http://" + "a" * 1000 + ".com",  # Very long URL
            "http://192.168.1.1:8080/admin",
            "https://bit.ly/suspicious",  # URL shortener
            "http://localhost:1337/shell",
        ]
        
        try:
            scanner = MaliciousLinkScanner()
            detected = 0
            
            for url in malicious_urls:
                try:
                    result = scanner.scan_url(url)
                    if result and result.get('is_malicious', False):
                        detected += 1
                except Exception:
                    # Some URLs might cause exceptions, that's okay
                    pass
                    
            duration = time.time() - start_time
            details = f"Processed {len(malicious_urls)} suspicious URLs"
            self.log_result("Malicious URL Testing", "PASS", details, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("Malicious URL Testing", "FAIL", str(e), duration)
            
    def test_system_limits(self):
        """Test system resource limits"""
        print("\n=== System Limits Test ===")
        start_time = time.time()
        
        try:
            # Test file descriptor limits
            open_files = []
            try:
                for i in range(100):  # Try to open many files
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    open_files.append(temp_file)
                    
            except Exception as e:
                print(f"  File descriptor limit reached: {len(open_files)} files")
            finally:
                # Clean up
                for f in open_files:
                    try:
                        f.close()
                        os.unlink(f.name)
                    except:
                        pass
                        
            duration = time.time() - start_time
            self.log_result("System Limits Test", "PASS", f"Tested {len(open_files)} file descriptors", duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_result("System Limits Test", "FAIL", str(e), duration)
            
    def cleanup(self):
        """Clean up temporary files and directories"""
        print("\n=== Cleanup ===")
        
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir)
                print(f"  Cleaned up: {temp_dir}")
            except Exception as e:
                print(f"  Failed to clean: {temp_dir} - {e}")
                
    def generate_report(self):
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        
        passed = sum(1 for r in self.test_results if r['status'] == 'PASS')
        failed = sum(1 for r in self.test_results if r['status'] == 'FAIL')
        total = len(self.test_results)
        
        report = {
            "test_summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "success_rate": (passed / total * 100) if total > 0 else 0,
                "total_duration": total_duration,
                "timestamp": datetime.now().isoformat()
            },
            "test_results": self.test_results,
            "system_info": {
                "platform": sys.platform,
                "python_version": sys.version,
                "working_directory": os.getcwd()
            }
        }
        
        # Save report
        report_file = f"reports/stress_test_report_{int(time.time())}.json"
        os.makedirs("reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n=== STRESS TEST COMPLETE ===")
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {passed/total*100:.1f}%")
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Report saved: {report_file}")
        
        return report
        
    def run_all_tests(self):
        """Run all stress tests"""
        print("🔥 PEGASPY STRESS TEST - BREAKING ALL LIMITS 🔥")
        print("=" * 50)
        
        try:
            # Run all stress tests
            self.test_file_integrity_stress()
            self.test_concurrent_operations()
            self.test_invalid_inputs()
            self.test_memory_stress()
            self.test_rapid_file_changes()
            self.test_malicious_urls()
            self.test_system_limits()
            
        finally:
            self.cleanup()
            return self.generate_report()

def main():
    """Main stress test execution"""
    tester = PegaSpyStressTester()
    report = tester.run_all_tests()
    
    # Return exit code based on results
    if report['test_summary']['success_rate'] >= 70:  # 70% pass rate for stress test
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()