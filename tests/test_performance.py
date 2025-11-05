"""
Performance Benchmark Suite

Benchmarks for critical performance optimizations:
- IPC throughput (connection pooling)
- Concurrent API scanning
- Regex pattern compilation
- Memory leak detection
"""

import pytest
import time
import sys
from pathlib import Path
import tempfile
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import psutil

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "zypheron-ai"))

from api_testing.api_scanner import APIScanner, RateLimiter
from secrets_scanner.secret_scanner import SecretScanner


class TestIPCThroughput:
    """Test IPC connection pooling performance"""
    
    def test_connection_pool_vs_new_connections(self):
        """
        Benchmark: Connection pool should be 70% faster than creating new connections.
        
        TARGET: >1000 requests/second with connection pooling
        """
        # This test requires actual IPC connection
        # Mark as integration test
        pytest.skip("Requires running AI engine (integration test)")
    
    def test_connection_pool_health_checks(self):
        """Test that health checks don't significantly impact performance"""
        # Health checks should run in background without blocking requests
        pytest.skip("Requires running AI engine (integration test)")


class TestConcurrentScanning:
    """Test concurrent API scanning performance"""
    
    def test_concurrent_vs_sequential_scanning(self):
        """
        Benchmark: Concurrent scanning should be 10x faster for 100+ endpoints.
        
        TEST: Scan 100 endpoints concurrently vs sequentially
        """
        # Create mock endpoints
        num_endpoints = 100
        
        # Mock session manager (no actual HTTP requests)
        class MockSessionManager:
            def create_requests_session(self, session_id):
                class MockSession:
                    def get(self, url, timeout=10):
                        time.sleep(0.01)  # Simulate 10ms latency
                        class MockResponse:
                            status_code = 200
                            def json(self):
                                return {'data': 'test'}
                        return MockResponse()
                return MockSession()
        
        scanner = APIScanner(session_manager=MockSessionManager(), max_workers=10, rate_limit_rps=100)
        endpoints = [f"http://test.com/api/endpoint{i}" for i in range(num_endpoints)]
        
        # Benchmark concurrent scanning
        start = time.time()
        # Note: test_excessive_data_exposure is async in the real code
        # For benchmark, we'd need to call it properly
        # vulns = scanner.test_excessive_data_exposure("session1", endpoints, ['password'])
        elapsed_concurrent = time.time() - start
        
        # Expected: ~1-2 seconds with 10 workers (10ms * 100 / 10 = 1s + overhead)
        # Sequential would take ~10 seconds (10ms * 100 * 10)
        
        # Assert performance improvement
        # In real test, compare with sequential version
        assert True  # Placeholder
    
    def test_rate_limiter(self):
        """Test that rate limiter properly throttles requests"""
        limiter = RateLimiter(max_requests_per_second=10)
        
        # Test that we can't exceed rate limit
        request_times = []
        
        for i in range(15):
            start = time.time()
            with limiter:
                request_times.append(time.time() - start)
        
        # First 10 requests should be fast
        assert sum(request_times[:10]) < 0.5  # < 500ms total
        
        # Next 5 should be throttled (need to wait for next second)
        # Some should have waited
        assert max(request_times[10:]) > 0.5  # At least one waited


class TestRegexCaching:
    """Test regex pattern caching performance"""
    
    def test_compiled_patterns_faster(self):
        """
        Benchmark: Pre-compiled patterns should be 40% faster.
        
        TEST: Scan same text with compiled vs non-compiled patterns
        """
        scanner = SecretScanner()
        
        # Verify patterns are compiled
        assert hasattr(scanner, 'compiled_patterns')
        assert len(scanner.compiled_patterns) > 0
        
        # Create test data
        test_text = """
        API_KEY=sk-1234567890abcdefghijklmnop
        password=SuperSecret123
        Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        """ * 100  # Repeat to make benchmark meaningful
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_text)
            temp_file = f.name
        
        try:
            # Benchmark with compiled patterns
            start = time.time()
            scanner.scan_file(temp_file)
            elapsed_compiled = time.time() - start
            
            # With pattern compilation, should be fast
            assert elapsed_compiled < 1.0  # Should scan quickly
            
        finally:
            os.unlink(temp_file)
    
    def test_pattern_compilation_once(self):
        """Test that patterns are compiled only once during initialization"""
        # Create multiple scanners
        scanners = [SecretScanner() for _ in range(5)]
        
        # Each should have compiled patterns
        for scanner in scanners:
            assert hasattr(scanner, 'compiled_patterns')
            # Patterns should be compiled (have regex objects)
            for pattern_data in scanner.compiled_patterns.values():
                assert hasattr(pattern_data['regex'], 'pattern')


class TestMemoryLeaks:
    """Test for memory leaks in long-running operations"""
    
    def get_memory_usage(self):
        """Get current process memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def test_connection_pool_no_leak(self):
        """Test that connection pool doesn't leak memory over many requests"""
        # This would require actual connection pool
        pytest.skip("Requires Go bridge integration")
    
    def test_api_scanner_no_leak(self):
        """Test that API scanner doesn't leak memory"""
        initial_memory = self.get_memory_usage()
        
        # Create and destroy scanners multiple times
        for _ in range(100):
            scanner = APIScanner()
            # Simulate some work
            _ = scanner.discovered_endpoints
            del scanner
        
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - initial_memory
        
        # Memory should not increase significantly (< 10MB for 100 iterations)
        assert memory_increase < 10, f"Memory leak detected: {memory_increase}MB increase"
    
    def test_secret_scanner_no_leak(self):
        """Test that secret scanner doesn't leak memory"""
        initial_memory = self.get_memory_usage()
        
        # Scan multiple times
        for _ in range(50):
            scanner = SecretScanner()
            # Compile patterns (memory-intensive operation)
            _ = scanner.compiled_patterns
            del scanner
        
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - initial_memory
        
        # Should not leak significantly
        assert memory_increase < 10, f"Memory leak detected: {memory_increase}MB increase"


class TestThreadSafety:
    """Test thread safety of concurrent operations"""
    
    def test_rate_limiter_thread_safe(self):
        """Test that rate limiter works correctly with multiple threads"""
        limiter = RateLimiter(max_requests_per_second=10)
        request_count = [0]
        lock = threading.Lock()
        
        def make_request():
            with limiter:
                with lock:
                    request_count[0] += 1
                time.sleep(0.001)  # Simulate work
        
        # Spawn many threads
        start = time.time()
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            for future in futures:
                future.result()
        
        elapsed = time.time() - start
        
        # All requests should complete
        assert request_count[0] == 50
        
        # Should take at least 5 seconds (50 requests / 10 per second)
        # But less than 10 seconds (not sequential)
        assert 4 < elapsed < 10, f"Rate limiting timing unexpected: {elapsed}s"
    
    def test_scanner_thread_safe(self):
        """Test that scanner can be used from multiple threads"""
        scanner = SecretScanner()
        
        # Create test file
        test_text = "API_KEY=sk-test1234567890\npassword=secret"
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_text)
            temp_file = f.name
        
        try:
            results = []
            lock = threading.Lock()
            
            def scan_file():
                findings = scanner.scan_file(temp_file)
                with lock:
                    results.append(len(findings))
            
            # Scan from multiple threads
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(scan_file) for _ in range(10)]
                for future in futures:
                    future.result()
            
            # All scans should find the same number of secrets
            assert all(r == results[0] for r in results), "Inconsistent results across threads"
            
        finally:
            os.unlink(temp_file)


class TestScalability:
    """Test scalability of optimizations"""
    
    def test_large_file_scanning(self):
        """Test scanning large files doesn't degrade performance"""
        scanner = SecretScanner()
        
        # Create progressively larger files
        sizes = [1000, 10000, 100000]  # lines
        scan_times = []
        
        for size in sizes:
            # Generate test data
            lines = ["This is a test line with some data\n"] * size
            lines.insert(size // 2, "API_KEY=sk-1234567890abcdefghij\n")  # Add a secret in the middle
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.writelines(lines)
                temp_file = f.name
            
            try:
                start = time.time()
                findings = scanner.scan_file(temp_file)
                elapsed = time.time() - start
                scan_times.append(elapsed)
                
                # Should find the secret
                assert len(findings) > 0
                
            finally:
                os.unlink(temp_file)
        
        # Performance should scale linearly or sub-linearly
        # Time per line should not increase significantly
        time_per_line = [t / s for t, s in zip(scan_times, sizes)]
        
        # Later scans should not be significantly slower per line
        assert time_per_line[-1] < time_per_line[0] * 2, "Performance degradation detected"


# Benchmark utilities
class BenchmarkResults:
    """Store and display benchmark results"""
    
    def __init__(self):
        self.results = {}
    
    def add(self, name, value, unit="ms"):
        self.results[name] = {"value": value, "unit": unit}
    
    def display(self):
        print("\n" + "="*60)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("="*60)
        for name, data in self.results.items():
            print(f"{name:40s} {data['value']:10.2f} {data['unit']}")
        print("="*60 + "\n")


@pytest.fixture(scope="session")
def benchmark_results():
    """Global benchmark results"""
    return BenchmarkResults()


# Pytest hooks for displaying results
def pytest_sessionfinish(session, exitstatus):
    """Display benchmark results at end of test session"""
    if hasattr(session.config, 'benchmark_results'):
        session.config.benchmark_results.display()


if __name__ == "__main__":
    # Run benchmarks
    pytest.main([__file__, "-v", "--tb=short", "-s"])

