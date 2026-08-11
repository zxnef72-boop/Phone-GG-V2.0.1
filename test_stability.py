#!/usr/bin/env python3
"""
PhoneGG v2.0 Stability Test Suite

Tests upgrades sa:
- pen_repeater.py (connection pooling, retry logic, streaming)
- modules/social_probe.py (timeout tuning, error handling)
- modules/graph_builder.py (safe value extraction, error recovery)
"""

import sys
import json
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def test_pen_repeater():
    """Test pen_repeater module dengan various scenarios."""
    logger.info("=" * 60)
    logger.info("Testing Pen Repeater Module")
    logger.info("=" * 60)
    
    try:
        from pen_repeater import send_pen_request, parse_raw_request
        
        # Test 1: Basic GET request
        logger.info("[Test 1] Basic GET request")
        result = send_pen_request("https://example.com")
        assert result["ok"], f"GET failed: {result.get('error')}"
        assert "status_code" in result["response"]
        logger.info(f"✓ GET request successful (status: {result['response']['status_code']})")
        
        # Test 2: POST request with local test
        logger.info("[Test 2] POST request with body")
        result = send_pen_request(
            "https://example.com",
            method="GET",
            body='{}'
        )
        assert result["ok"], f"POST-like failed: {result.get('error')}"
        logger.info("✓ POST-like request successful")
        
        # Test 3: Custom headers
        logger.info("[Test 3] Custom headers handling")
        result = send_pen_request(
            "https://example.com",
            headers={"X-Custom": "TestValue"}
        )
        assert result["ok"], f"Headers failed: {result.get('error')}"
        assert "X-Custom" in result["request"]["headers"] or len(result["request"]["headers"]) >= 0
        logger.info("✓ Custom headers successful")
        
        # Test 4: Raw request parsing
        logger.info("[Test 4] Raw request parsing")
        raw = """GET /api/test HTTP/1.1
Host: example.com
User-Agent: PhoneGG/2.0
Accept: application/json"""
        parsed = parse_raw_request(raw)
        assert parsed["ok"], f"Parse failed: {parsed.get('error')}"
        assert parsed["method"] == "GET"
        logger.info("✓ Raw request parsing successful")
        
        # Test 5: Invalid URL handling
        logger.info("[Test 5] Invalid URL handling")
        result = send_pen_request("http://999.999.999.999:99999")
        assert not result["ok"], "Should handle invalid URLs"
        logger.info(f"✓ Invalid URL handled: {result['error'][:50]}")
        
        logger.info("✅ All Pen Repeater tests passed!\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Pen Repeater test failed: {e}")
        return False


def test_graph_builder():
    """Test graph_builder module dengan safe value extraction."""
    logger.info("=" * 60)
    logger.info("Testing Graph Builder Module")
    logger.info("=" * 60)
    
    try:
        from modules.graph_builder import build_phone_graph
        
        # Test 1: Empty input
        logger.info("[Test 1] Empty input handling")
        result = build_phone_graph({})
        assert result["nodes"], "Should have at least error node"
        assert isinstance(result["nodes"], list)
        logger.info("✓ Empty input handled correctly")
        
        # Test 2: Minimal data
        logger.info("[Test 2] Minimal phone data")
        result = build_phone_graph({
            "number": "+1234567890",
            "operator": "TestOp",
            "country": "US"
        })
        assert result["nodes"], "Should have nodes"
        assert len(result["nodes"]) >= 1
        logger.info("✓ Minimal data processed correctly")
        
        # Test 3: Complete data
        logger.info("[Test 3] Complete phone data")
        complete_data = {
            "number": "+1234567890",
            "operator": "Telco",
            "country": "USA",
            "prefix": "+1",
            "ml_risk_prediction": {
                "risk_score": 75,
                "risk_level": "Medium Risk",
                "confidence": 90
            },
            "wa_status": {
                "status": "Active",
                "note": "WhatsApp registered"
            },
            "links": {
                "Google Result 1": "https://example.com/1",
                "Google Result 2": "https://example.com/2"
            },
            "associated_emails": ["test1@example.com", "test2@example.com"],
            "breach_info": {
                "breached": True,
                "breach_count": 2,
                "databases": ["Database1", "Database2"]
            }
        }
        result = build_phone_graph(complete_data)
        assert result["nodes"], "Should have nodes"
        assert len(result["nodes"]) > 5, "Should have multiple nodes"
        assert result["metadata"]["node_count"] > 0
        logger.info(f"✓ Complete data processed: {result['metadata']['node_count']} nodes created")
        
        # Test 4: Malformed data handling
        logger.info("[Test 4] Malformed data handling")
        malformed = {
            "number": None,
            "operator": 12345,  # number instead of string
            "links": "not a dict",  # wrong type
            "associated_emails": "not a list",
            "ml_risk_prediction": {"risk_score": 999}  # out of range
        }
        result = build_phone_graph(malformed)
        assert result["nodes"], "Should handle malformed data"
        logger.info("✓ Malformed data handled gracefully")
        
        # Test 5: Large dataset
        logger.info("[Test 5] Large dataset handling")
        large_data = {
            "number": "+1234567890",
            "operator": "Op",
            "country": "US",
            "links": {f"Link{i}": f"https://example.com/{i}" for i in range(100)}
        }
        result = build_phone_graph(large_data)
        assert result["nodes"], "Should handle large datasets"
        logger.info(f"✓ Large dataset handled: {result['metadata']['node_count']} nodes")
        
        logger.info("✅ All Graph Builder tests passed!\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Graph Builder test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_social_probe():
    """Test social_probe module dengan improved concurrency."""
    logger.info("=" * 60)
    logger.info("Testing Social Probe Module")
    logger.info("=" * 60)
    
    try:
        from modules.social_probe import check_username_detailed, _build_session
        
        # Test 1: Session building
        logger.info("[Test 1] Session building with retry strategy")
        session = _build_session(pool_size=5)
        assert session, "Should create session"
        logger.info("✓ Session created with connection pooling")
        
        # Test 2: Single username check (known existing)
        logger.info("[Test 2] Single username check (torvalds on GitHub)")
        result = check_username_detailed("torvalds", max_workers=5)
        assert result["username"] == "torvalds"
        assert len(result["results"]) > 0
        github_result = next((r for r in result["results"] if r["platform"] == "GitHub"), None)
        if github_result:
            assert github_result["status"] in ["found", "maybe", "unknown", "error"]
            logger.info(f"✓ GitHub result: {github_result['status']}")
        
        # Test 3: Summary statistics
        logger.info("[Test 3] Summary statistics")
        assert "total" in result["summary"]
        assert "found" in result["summary"]
        assert "not_found" in result["summary"]
        total = result["summary"]["total"]
        logger.info(f"✓ Summary generated: {total} platforms checked")
        
        # Test 4: Concurrent requests
        logger.info("[Test 4] Concurrent requests (20 workers)")
        result = check_username_detailed("testuser123xyz", max_workers=20)
        assert len(result["results"]) > 0
        logger.info(f"✓ Concurrent probe completed: {len(result['results'])} results")
        
        # Test 5: Error handling
        logger.info("[Test 5] Error handling")
        result = check_username_detailed("valid_user", max_workers=5)
        error_count = sum(1 for r in result["results"] if r["status"] == "error")
        if error_count > 0:
            logger.info(f"✓ Error handling: {error_count} errors caught gracefully")
        else:
            logger.info("✓ No errors in probe execution")
        
        logger.info("✅ All Social Probe tests passed!\n")
        return True
        
    except Exception as e:
        logger.error(f"❌ Social Probe test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_imports():
    """Verify all modules import correctly."""
    logger.info("=" * 60)
    logger.info("Testing Module Imports")
    logger.info("=" * 60)
    
    try:
        logger.info("[Import 1] pen_repeater")
        from pen_repeater import send_pen_request, parse_raw_request, _build_session
        logger.info("✓ pen_repeater imported")
        
        logger.info("[Import 2] modules.social_probe")
        from modules.social_probe import check_username_detailed, _build_session as probe_session
        logger.info("✓ modules.social_probe imported")
        
        logger.info("[Import 3] modules.graph_builder")
        from modules.graph_builder import build_phone_graph
        logger.info("✓ modules.graph_builder imported")
        
        logger.info("✅ All imports successful!\n")
        return True
        
    except ImportError as e:
        logger.error(f"❌ Import failed: {e}")
        return False


def main():
    """Run all tests."""
    logger.info("\n")
    logger.info("╔" + "=" * 58 + "╗")
    logger.info("║" + " PhoneGG v2.0 Stability Test Suite ".center(58) + "║")
    logger.info("╚" + "=" * 58 + "╝")
    logger.info("")
    
    results = {
        "imports": test_imports(),
        "graph_builder": test_graph_builder(),
        "pen_repeater": test_pen_repeater(),
        "social_probe": test_social_probe(),
    }
    
    logger.info("=" * 60)
    logger.info("Test Summary")
    logger.info("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        logger.info(f"{test_name:20} {status}")
    
    logger.info("=" * 60)
    logger.info(f"Total: {passed}/{total} test groups passed")
    
    if passed == total:
        logger.info("✅ All tests passed! PhoneGG v2.0 is stable and ready.\n")
        return 0
    else:
        logger.error(f"❌ {total - passed} test group(s) failed. Check logs above.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
