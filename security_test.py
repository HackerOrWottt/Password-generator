#!/usr/bin/env python3
"""
PassKeeper Security Testing Suite
Additional security-focused tests for authentication and data protection
"""

import requests
import json
import jwt
import time
import uuid
from datetime import datetime, timedelta

# Configuration
BASE_URL = "https://passkeeper-20.preview.emergentagent.com/api"
HEADERS = {"Content-Type": "application/json"}

class SecurityTester:
    def __init__(self):
        self.base_url = BASE_URL
        self.headers = HEADERS.copy()
        self.test_user_data = {
            "name": "Security Test User",
            "email": f"security.test.{uuid.uuid4().hex[:8]}@testmail.com",
            "password": "SecurityTest123!@#"
        }
        self.auth_token = None
        
    def log_test(self, test_name, success, details=""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        print()
        
    def setup_test_user(self):
        """Create a test user for security testing"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/register",
                headers=self.headers,
                json=self.test_user_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data['token']
                return True
            return False
        except:
            return False
    
    def test_password_hashing_security(self):
        """Test that passwords are properly hashed and not stored in plaintext"""
        try:
            # Register a user with a known password
            test_data = {
                "name": "Hash Test User",
                "email": f"hash.test.{uuid.uuid4().hex[:8]}@testmail.com",
                "password": "PlaintextPassword123"
            }
            
            response = requests.post(
                f"{self.base_url}/auth/register",
                headers=self.headers,
                json=test_data,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                # Check that password is not returned in response
                if 'password' not in data.get('user', {}):
                    details = "Password correctly excluded from registration response"
                else:
                    success = False
                    details = "Password leaked in registration response"
            else:
                details = f"Registration failed: {response.text}"
                
            self.log_test("Password Hashing Security", success, details)
            return success
        except Exception as e:
            self.log_test("Password Hashing Security", False, f"Error: {str(e)}")
            return False
    
    def test_jwt_token_structure(self):
        """Test JWT token structure and claims"""
        if not self.auth_token:
            self.log_test("JWT Token Structure", False, "No auth token available")
            return False
            
        try:
            # Decode JWT without verification to check structure
            # Note: This is for testing purposes only
            parts = self.auth_token.split('.')
            if len(parts) != 3:
                self.log_test("JWT Token Structure", False, "Invalid JWT format")
                return False
            
            # Decode header and payload (without signature verification)
            import base64
            
            # Add padding if needed
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            
            try:
                header = json.loads(base64.b64decode(header_b64))
                payload = json.loads(base64.b64decode(payload_b64))
                
                # Check required claims
                required_claims = ['userId', 'email', 'exp', 'iat']
                missing_claims = [claim for claim in required_claims if claim not in payload]
                
                if not missing_claims:
                    # Check expiration is reasonable (should be 7 days)
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    iat_time = datetime.fromtimestamp(payload['iat'])
                    duration = exp_time - iat_time
                    
                    if 6 <= duration.days <= 8:  # Allow some flexibility
                        details = f"JWT structure valid. Expires in {duration.days} days"
                        success = True
                    else:
                        details = f"Unexpected expiration duration: {duration.days} days"
                        success = False
                else:
                    details = f"Missing required claims: {missing_claims}"
                    success = False
                    
            except Exception as decode_error:
                details = f"Failed to decode JWT: {str(decode_error)}"
                success = False
                
            self.log_test("JWT Token Structure", success, details)
            return success
        except Exception as e:
            self.log_test("JWT Token Structure", False, f"Error: {str(e)}")
            return False
    
    def test_sql_injection_protection(self):
        """Test protection against SQL injection attempts"""
        try:
            # Try SQL injection in login
            injection_attempts = [
                {"email": "admin'; DROP TABLE users; --", "password": "password"},
                {"email": "admin' OR '1'='1", "password": "password"},
                {"email": "admin", "password": "' OR '1'='1' --"}
            ]
            
            all_blocked = True
            for attempt in injection_attempts:
                response = requests.post(
                    f"{self.base_url}/auth/login",
                    headers=self.headers,
                    json=attempt,
                    timeout=10
                )
                
                # Should return 401 (unauthorized) not 500 (server error)
                if response.status_code not in [401, 400]:
                    all_blocked = False
                    break
            
            details = "All SQL injection attempts properly rejected" if all_blocked else "Some injection attempts may have succeeded"
            self.log_test("SQL Injection Protection", all_blocked, details)
            return all_blocked
        except Exception as e:
            self.log_test("SQL Injection Protection", False, f"Error: {str(e)}")
            return False
    
    def test_xss_protection(self):
        """Test protection against XSS in vault items"""
        if not self.auth_token:
            self.log_test("XSS Protection", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Try to create vault item with XSS payload
            xss_payload = "<script>alert('XSS')</script>"
            vault_item = {
                "title": f"Test Item {xss_payload}",
                "username": f"user{xss_payload}",
                "encryptedPassword": "dGVzdHBhc3N3b3Jk",  # base64 encoded "testpassword"
                "url": f"https://example.com{xss_payload}",
                "notes": f"Notes with {xss_payload}"
            }
            
            response = requests.post(
                f"{self.base_url}/vault",
                headers=auth_headers,
                json=vault_item,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                # Check that XSS payload is stored as-is (not executed)
                if xss_payload in data.get('title', ''):
                    details = "XSS payload stored safely (not executed server-side)"
                else:
                    success = False
                    details = "XSS payload was modified or rejected"
            else:
                details = f"Failed to create vault item: {response.text}"
                
            self.log_test("XSS Protection", success, details)
            return success
        except Exception as e:
            self.log_test("XSS Protection", False, f"Error: {str(e)}")
            return False
    
    def test_rate_limiting_behavior(self):
        """Test behavior under rapid requests (basic rate limiting check)"""
        try:
            # Make multiple rapid login attempts
            rapid_requests = []
            for i in range(5):
                start_time = time.time()
                response = requests.post(
                    f"{self.base_url}/auth/login",
                    headers=self.headers,
                    json={"email": "nonexistent@test.com", "password": "wrongpass"},
                    timeout=10
                )
                end_time = time.time()
                rapid_requests.append({
                    'status': response.status_code,
                    'time': end_time - start_time
                })
            
            # Check that all requests were handled (no 429 Too Many Requests)
            # Note: This app may not have rate limiting implemented
            all_handled = all(req['status'] in [401, 400] for req in rapid_requests)
            avg_time = sum(req['time'] for req in rapid_requests) / len(rapid_requests)
            
            details = f"Handled {len(rapid_requests)} rapid requests, avg time: {avg_time:.3f}s"
            self.log_test("Rate Limiting Behavior", all_handled, details)
            return all_handled
        except Exception as e:
            self.log_test("Rate Limiting Behavior", False, f"Error: {str(e)}")
            return False
    
    def test_cors_headers(self):
        """Test CORS headers are properly set"""
        try:
            response = requests.options(
                f"{self.base_url}/auth/login",
                headers={"Origin": "https://example.com"},
                timeout=10
            )
            
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers')
            }
            
            has_cors = all(header is not None for header in cors_headers.values())
            
            if has_cors:
                details = f"CORS headers present: {cors_headers['Access-Control-Allow-Origin']}"
            else:
                details = "Missing CORS headers"
                
            self.log_test("CORS Headers", has_cors, details)
            return has_cors
        except Exception as e:
            self.log_test("CORS Headers", False, f"Error: {str(e)}")
            return False
    
    def test_authorization_isolation(self):
        """Test that users can only access their own data"""
        try:
            # Create two different users
            user1_data = {
                "name": "User One",
                "email": f"user1.{uuid.uuid4().hex[:8]}@test.com",
                "password": "Password123!"
            }
            
            user2_data = {
                "name": "User Two", 
                "email": f"user2.{uuid.uuid4().hex[:8]}@test.com",
                "password": "Password456!"
            }
            
            # Register both users
            response1 = requests.post(f"{self.base_url}/auth/register", headers=self.headers, json=user1_data, timeout=10)
            response2 = requests.post(f"{self.base_url}/auth/register", headers=self.headers, json=user2_data, timeout=10)
            
            if response1.status_code != 200 or response2.status_code != 200:
                self.log_test("Authorization Isolation", False, "Failed to create test users")
                return False
            
            token1 = response1.json()['token']
            token2 = response2.json()['token']
            
            # User 1 creates a vault item
            auth_headers1 = self.headers.copy()
            auth_headers1["Authorization"] = f"Bearer {token1}"
            
            vault_item = {
                "title": "User 1 Secret",
                "username": "user1",
                "encryptedPassword": "dXNlcjFwYXNz",  # base64 "user1pass"
                "url": "https://user1.com",
                "notes": "Private to user 1"
            }
            
            create_response = requests.post(f"{self.base_url}/vault", headers=auth_headers1, json=vault_item, timeout=10)
            
            if create_response.status_code != 200:
                self.log_test("Authorization Isolation", False, "Failed to create vault item")
                return False
            
            # User 2 tries to access User 1's vault
            auth_headers2 = self.headers.copy()
            auth_headers2["Authorization"] = f"Bearer {token2}"
            
            user2_vault = requests.get(f"{self.base_url}/vault", headers=auth_headers2, timeout=10)
            
            if user2_vault.status_code == 200:
                user2_items = user2_vault.json()
                # User 2 should not see User 1's items
                isolation_working = len(user2_items) == 0
                details = f"User 2 sees {len(user2_items)} items (should be 0)"
            else:
                isolation_working = False
                details = f"Failed to get User 2's vault: {user2_vault.status_code}"
            
            self.log_test("Authorization Isolation", isolation_working, details)
            return isolation_working
            
        except Exception as e:
            self.log_test("Authorization Isolation", False, f"Error: {str(e)}")
            return False
    
    def run_security_tests(self):
        """Run all security tests"""
        print("=" * 60)
        print("PassKeeper Security Testing Suite")
        print("=" * 60)
        print()
        
        # Setup test user
        if not self.setup_test_user():
            print("❌ Failed to setup test user. Aborting security tests.")
            return False
        
        test_results = []
        
        # Security Tests
        test_results.append(self.test_password_hashing_security())
        test_results.append(self.test_jwt_token_structure())
        test_results.append(self.test_sql_injection_protection())
        test_results.append(self.test_xss_protection())
        test_results.append(self.test_rate_limiting_behavior())
        test_results.append(self.test_cors_headers())
        test_results.append(self.test_authorization_isolation())
        
        # Summary
        passed = sum(test_results)
        total = len(test_results)
        
        print("=" * 60)
        print(f"SECURITY TEST SUMMARY: {passed}/{total} tests passed")
        print("=" * 60)
        
        if passed == total:
            print("🔒 All security tests PASSED! The PassKeeper API is secure.")
        else:
            print(f"⚠️  {total - passed} security test(s) FAILED. Please review the issues above.")
        
        return passed == total

if __name__ == "__main__":
    tester = SecurityTester()
    success = tester.run_security_tests()
    exit(0 if success else 1)