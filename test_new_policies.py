#!/usr/bin/env python3
"""
Test script for the new lightweight security policies in SecNode.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

def test_confidential_data_policy():
    """Test the ConfidentialDataPolicy."""
    print("\n🔍 Testing ConfidentialDataPolicy...")
    
    try:
        from secnode.policies.builtin import ConfidentialDataPolicy
        
        policy = ConfidentialDataPolicy()
        
        # Test 1: Clean content
        clean_state = {"user_input": "Hello, how can I help you today?"}
        result = policy.check(clean_state)
        print(f"✅ Clean content: {result.decision} - {result.reason}")
        
        # Test 2: Confidential marker
        conf_state = {"user_input": "This document is CONFIDENTIAL and contains sensitive information."}
        result = policy.check(conf_state)
        print(f"✅ Confidential marker: {result.decision} - {result.reason}")
        
        # Test 3: API key pattern
        api_state = {"user_input": "My API key is sk-1234567890abcdef1234567890abcdef12345678"}
        result = policy.check(api_state)
        print(f"✅ API key detection: {result.decision} - {result.reason}")
        
    except Exception as e:
        print(f"❌ ConfidentialDataPolicy test failed: {e}")

def test_rate_limit_policy():
    """Test the RateLimitPolicy."""
    print("\n⏱️  Testing RateLimitPolicy...")
    
    try:
        from secnode.policies.builtin import RateLimitPolicy
        
        policy = RateLimitPolicy(requests_per_minute=5, requests_per_hour=20)
        
        # Test multiple requests
        for i in range(7):
            state = {"user_id": "test_user", "query": f"Request {i+1}"}
            result = policy.check(state)
            status = "✅" if result.decision == "ALLOW" else "🚫"
            print(f"{status} Request {i+1}: {result.decision} - {result.reason}")
            
    except Exception as e:
        print(f"❌ RateLimitPolicy test failed: {e}")

def test_content_length_policy():
    """Test the ContentLengthPolicy."""
    print("\n📏 Testing ContentLengthPolicy...")
    
    try:
        from secnode.policies.builtin import ContentLengthPolicy
        
        policy = ContentLengthPolicy(max_message_length=50, max_total_length=200)
        
        # Test 1: Normal length
        normal_state = {"user_input": "This is a normal message"}
        result = policy.check(normal_state)
        print(f"✅ Normal length: {result.decision} - {result.reason}")
        
        # Test 2: Too long message
        long_state = {"user_input": "x" * 100}  # 100 characters
        result = policy.check(long_state)
        print(f"✅ Long message: {result.decision} - {result.reason}")
        
    except Exception as e:
        print(f"❌ ContentLengthPolicy test failed: {e}")

def test_url_blacklist_policy():
    """Test the URLBlacklistPolicy."""
    print("\n🔗 Testing URLBlacklistPolicy...")
    
    try:
        from secnode.policies.builtin import URLBlacklistPolicy
        
        policy = URLBlacklistPolicy(blocked_domains=["malicious.com"])
        
        # Test 1: Safe URL
        safe_state = {"user_input": "Check out https://example.com for more info"}
        result = policy.check(safe_state)
        print(f"✅ Safe URL: {result.decision} - {result.reason}")
        
        # Test 2: Blocked domain
        bad_state = {"user_input": "Don't visit https://malicious.com - it's dangerous"}
        result = policy.check(bad_state)
        print(f"✅ Blocked URL: {result.decision} - {result.reason}")
        
        # Test 3: IP address URL
        ip_state = {"user_input": "Visit http://192.168.1.1 for the admin panel"}
        result = policy.check(ip_state)
        print(f"✅ IP URL: {result.decision} - {result.reason}")
        
    except Exception as e:
        print(f"❌ URLBlacklistPolicy test failed: {e}")

def test_keyword_filter_policy():
    """Test the KeywordFilterPolicy."""
    print("\n🔤 Testing KeywordFilterPolicy...")
    
    try:
        from secnode.policies.builtin import KeywordFilterPolicy
        
        policy = KeywordFilterPolicy(
            prohibited_keywords=["spam", "scam"],
            high_severity_keywords=["malware"]
        )
        
        # Test 1: Clean content
        clean_state = {"user_input": "This is a legitimate business proposal"}
        result = policy.check(clean_state)
        print(f"✅ Clean content: {result.decision} - {result.reason}")
        
        # Test 2: Prohibited keyword
        spam_state = {"user_input": "This looks like spam to me"}
        result = policy.check(spam_state)
        print(f"✅ Prohibited keyword: {result.decision} - {result.reason}")
        
        # Test 3: High severity keyword
        malware_state = {"user_input": "This file contains malware"}
        result = policy.check(malware_state)
        print(f"✅ High severity: {result.decision} - {result.reason}")
        
    except Exception as e:
        print(f"❌ KeywordFilterPolicy test failed: {e}")

def test_data_leakage_policy():
    """Test the DataLeakagePolicy."""
    print("\n💧 Testing DataLeakagePolicy...")
    
    try:
        from secnode.policies.builtin import DataLeakagePolicy
        
        policy = DataLeakagePolicy()
        
        # Test 1: Clean output
        clean_state = {"response": "Here's the information you requested."}
        result = policy.check(clean_state)
        print(f"✅ Clean output: {result.decision} - {result.reason}")
        
        # Test 2: System path leakage
        path_state = {"response": "Error: Could not access /etc/passwd"}
        result = policy.check(path_state)
        print(f"✅ System path: {result.decision} - {result.reason}")
        
        # Test 3: Database info leakage
        db_state = {"response": "SELECT * FROM users WHERE id=1"}
        result = policy.check(db_state)
        print(f"✅ Database leak: {result.decision} - {result.reason}")
        
    except Exception as e:
        print(f"❌ DataLeakagePolicy test failed: {e}")

def main():
    """Run all policy tests."""
    print("🚀 Testing SecNode New Security Policies\n")
    print("=" * 50)
    
    test_confidential_data_policy()
    test_rate_limit_policy()
    test_content_length_policy()
    test_url_blacklist_policy()
    test_keyword_filter_policy()
    test_data_leakage_policy()
    
    print("\n" + "=" * 50)
    print("🎉 All policy tests completed!")

if __name__ == "__main__":
    main()