#!/usr/bin/env python3
"""
PassKeeper Backend API Testing Suite
Tests authentication, JWT token management, and vault CRUD operations
"""

import requests
import json
import time
import uuid
from datetime import datetime, timedelta

# Configuration
BASE_URL = "https://passkeeper-20.preview.emergentagent.com/api"
HEADERS = {"Content-Type": "application/json"}

class PassKeeperAPITester:
    def __init__(self):
        self.base_url = BASE_URL
        self.headers = HEADERS.copy()
        self.test_user_data = {
            "name": "Sarah Johnson",
            "email": f"sarah.johnson.{uuid.uuid4().hex[:8]}@testmail.com",
            "password": "SecurePass123!@#"
        }
        self.auth_token = None
        self.user_id = None
        self.vault_items = []
        
    def log_test(self, test_name, success, details=""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        print()
        
    def test_api_health(self):
        """Test if API is running"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("API Health Check", success, details)
            return success
        except Exception as e:
            self.log_test("API Health Check", False, f"Connection error: {str(e)}")
            return False
    
    def test_user_registration(self):
        """Test user registration endpoint"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/register",
                headers=self.headers,
                json=self.test_user_data,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                if 'user' in data and 'token' in data:
                    self.auth_token = data['token']
                    self.user_id = data['user']['id']
                    details = f"User registered successfully. ID: {self.user_id[:8]}..."
                else:
                    success = False
                    details = "Missing user or token in response"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("User Registration", success, details)
            return success
        except Exception as e:
            self.log_test("User Registration", False, f"Request error: {str(e)}")
            return False
    
    def test_duplicate_registration(self):
        """Test duplicate email registration prevention"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/register",
                headers=self.headers,
                json=self.test_user_data,
                timeout=10
            )
            
            success = response.status_code == 400
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Duplicate Registration Prevention", success, details)
            return success
        except Exception as e:
            self.log_test("Duplicate Registration Prevention", False, f"Request error: {str(e)}")
            return False
    
    def test_user_login(self):
        """Test user login endpoint"""
        try:
            login_data = {
                "email": self.test_user_data["email"],
                "password": self.test_user_data["password"]
            }
            
            response = requests.post(
                f"{self.base_url}/auth/login",
                headers=self.headers,
                json=login_data,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                if 'user' in data and 'token' in data:
                    # Update token in case it's different
                    self.auth_token = data['token']
                    details = f"Login successful. Token length: {len(self.auth_token)}"
                else:
                    success = False
                    details = "Missing user or token in response"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("User Login", success, details)
            return success
        except Exception as e:
            self.log_test("User Login", False, f"Request error: {str(e)}")
            return False
    
    def test_invalid_login(self):
        """Test login with invalid credentials"""
        try:
            invalid_data = {
                "email": self.test_user_data["email"],
                "password": "WrongPassword123"
            }
            
            response = requests.post(
                f"{self.base_url}/auth/login",
                headers=self.headers,
                json=invalid_data,
                timeout=10
            )
            
            success = response.status_code == 401
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Invalid Login Rejection", success, details)
            return success
        except Exception as e:
            self.log_test("Invalid Login Rejection", False, f"Request error: {str(e)}")
            return False
    
    def test_jwt_verification(self):
        """Test JWT token verification"""
        if not self.auth_token:
            self.log_test("JWT Token Verification", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            response = requests.get(
                f"{self.base_url}/auth/verify",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                if 'user' in data and data['user']['id'] == self.user_id:
                    details = f"Token verified successfully for user: {data['user']['name']}"
                else:
                    success = False
                    details = "User data mismatch in verification"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("JWT Token Verification", success, details)
            return success
        except Exception as e:
            self.log_test("JWT Token Verification", False, f"Request error: {str(e)}")
            return False
    
    def test_invalid_token_rejection(self):
        """Test rejection of invalid JWT token"""
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = "Bearer invalid_token_here"
            
            response = requests.get(
                f"{self.base_url}/auth/verify",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 401
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Invalid Token Rejection", success, details)
            return success
        except Exception as e:
            self.log_test("Invalid Token Rejection", False, f"Request error: {str(e)}")
            return False
    
    def test_protected_route_without_auth(self):
        """Test accessing protected route without authentication"""
        try:
            response = requests.get(
                f"{self.base_url}/vault",
                headers=self.headers,
                timeout=10
            )
            
            success = response.status_code == 401
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Protected Route Without Auth", success, details)
            return success
        except Exception as e:
            self.log_test("Protected Route Without Auth", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_get_empty(self):
        """Test getting vault items (should be empty initially)"""
        if not self.auth_token:
            self.log_test("Vault Get (Empty)", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            response = requests.get(
                f"{self.base_url}/vault",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                if isinstance(data, list) and len(data) == 0:
                    details = "Empty vault returned successfully"
                else:
                    details = f"Vault contains {len(data)} items"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("Vault Get (Empty)", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Get (Empty)", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_create_item(self):
        """Test creating a vault item"""
        if not self.auth_token:
            self.log_test("Vault Create Item", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Simulate client-side encryption (using base64 for testing)
            import base64
            encrypted_password = base64.b64encode("MySecretPassword123!".encode()).decode()
            
            vault_item = {
                "title": "GitHub Account",
                "username": "sarah.johnson",
                "encryptedPassword": encrypted_password,
                "url": "https://github.com",
                "notes": "Personal GitHub account for projects"
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
                if 'id' in data and data['title'] == vault_item['title']:
                    self.vault_items.append(data)
                    details = f"Vault item created with ID: {data['id'][:8]}..."
                else:
                    success = False
                    details = "Invalid response structure"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("Vault Create Item", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Create Item", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_create_multiple_items(self):
        """Test creating multiple vault items"""
        if not self.auth_token:
            self.log_test("Vault Create Multiple Items", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            import base64
            
            additional_items = [
                {
                    "title": "Gmail Account",
                    "username": "sarah.johnson.test@gmail.com",
                    "encryptedPassword": base64.b64encode("GmailPass456!".encode()).decode(),
                    "url": "https://gmail.com",
                    "notes": "Primary email account"
                },
                {
                    "title": "Banking Portal",
                    "username": "sarah_j_2024",
                    "encryptedPassword": base64.b64encode("BankSecure789@".encode()).decode(),
                    "url": "https://mybank.com",
                    "notes": "Online banking access"
                }
            ]
            
            created_count = 0
            for item in additional_items:
                response = requests.post(
                    f"{self.base_url}/vault",
                    headers=auth_headers,
                    json=item,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.vault_items.append(data)
                    created_count += 1
            
            success = created_count == len(additional_items)
            details = f"Created {created_count}/{len(additional_items)} additional vault items"
            self.log_test("Vault Create Multiple Items", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Create Multiple Items", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_get_populated(self):
        """Test getting vault items after creation"""
        if not self.auth_token:
            self.log_test("Vault Get (Populated)", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            response = requests.get(
                f"{self.base_url}/vault",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                expected_count = len(self.vault_items)
                if isinstance(data, list) and len(data) == expected_count:
                    details = f"Retrieved {len(data)} vault items successfully"
                else:
                    success = False
                    details = f"Expected {expected_count} items, got {len(data) if isinstance(data, list) else 'invalid response'}"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("Vault Get (Populated)", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Get (Populated)", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_update_item(self):
        """Test updating a vault item"""
        if not self.auth_token or not self.vault_items:
            self.log_test("Vault Update Item", False, "No auth token or vault items available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Update the first vault item
            item_to_update = self.vault_items[0]
            item_id = item_to_update['id']
            
            import base64
            updated_data = {
                "title": "GitHub Account (Updated)",
                "username": "sarah.johnson.updated",
                "encryptedPassword": base64.b64encode("UpdatedPassword456!".encode()).decode(),
                "url": "https://github.com/sarah-johnson",
                "notes": "Updated GitHub account with new credentials"
            }
            
            response = requests.put(
                f"{self.base_url}/vault/{item_id}",
                headers=auth_headers,
                json=updated_data,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                details = f"Vault item {item_id[:8]}... updated successfully"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("Vault Update Item", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Update Item", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_delete_item(self):
        """Test deleting a vault item"""
        if not self.auth_token or not self.vault_items:
            self.log_test("Vault Delete Item", False, "No auth token or vault items available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Delete the last vault item
            item_to_delete = self.vault_items[-1]
            item_id = item_to_delete['id']
            
            response = requests.delete(
                f"{self.base_url}/vault/{item_id}",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 200
            if success:
                self.vault_items.pop()  # Remove from our local list
                details = f"Vault item {item_id[:8]}... deleted successfully"
            else:
                details = f"Status: {response.status_code}, Error: {response.text}"
                
            self.log_test("Vault Delete Item", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Delete Item", False, f"Request error: {str(e)}")
            return False
    
    def test_vault_unauthorized_access(self):
        """Test accessing another user's vault items"""
        if not self.auth_token:
            self.log_test("Vault Unauthorized Access", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Try to access/delete a non-existent item (simulates another user's item)
            fake_item_id = str(uuid.uuid4())
            
            response = requests.delete(
                f"{self.base_url}/vault/{fake_item_id}",
                headers=auth_headers,
                timeout=10
            )
            
            success = response.status_code == 404
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Vault Unauthorized Access", success, details)
            return success
        except Exception as e:
            self.log_test("Vault Unauthorized Access", False, f"Request error: {str(e)}")
            return False
    
    def test_malformed_requests(self):
        """Test handling of malformed requests"""
        if not self.auth_token:
            self.log_test("Malformed Requests Handling", False, "No auth token available")
            return False
            
        try:
            auth_headers = self.headers.copy()
            auth_headers["Authorization"] = f"Bearer {self.auth_token}"
            
            # Test creating vault item without required fields
            invalid_item = {
                "username": "test_user"
                # Missing title and encryptedPassword
            }
            
            response = requests.post(
                f"{self.base_url}/vault",
                headers=auth_headers,
                json=invalid_item,
                timeout=10
            )
            
            success = response.status_code == 400
            details = f"Status: {response.status_code}, Response: {response.text[:100]}"
            self.log_test("Malformed Requests Handling", success, details)
            return success
        except Exception as e:
            self.log_test("Malformed Requests Handling", False, f"Request error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all backend tests in sequence"""
        print("=" * 60)
        print("PassKeeper Backend API Testing Suite")
        print("=" * 60)
        print()
        
        test_results = []
        
        # API Health and Authentication Tests
        test_results.append(self.test_api_health())
        test_results.append(self.test_user_registration())
        test_results.append(self.test_duplicate_registration())
        test_results.append(self.test_user_login())
        test_results.append(self.test_invalid_login())
        
        # JWT and Security Tests
        test_results.append(self.test_jwt_verification())
        test_results.append(self.test_invalid_token_rejection())
        test_results.append(self.test_protected_route_without_auth())
        
        # Vault CRUD Tests
        test_results.append(self.test_vault_get_empty())
        test_results.append(self.test_vault_create_item())
        test_results.append(self.test_vault_create_multiple_items())
        test_results.append(self.test_vault_get_populated())
        test_results.append(self.test_vault_update_item())
        test_results.append(self.test_vault_delete_item())
        
        # Security and Edge Case Tests
        test_results.append(self.test_vault_unauthorized_access())
        test_results.append(self.test_malformed_requests())
        
        # Summary
        passed = sum(test_results)
        total = len(test_results)
        
        print("=" * 60)
        print(f"TEST SUMMARY: {passed}/{total} tests passed")
        print("=" * 60)
        
        if passed == total:
            print("🎉 All backend tests PASSED! The PassKeeper API is working correctly.")
        else:
            print(f"⚠️  {total - passed} test(s) FAILED. Please review the issues above.")
        
        return passed == total

if __name__ == "__main__":
    tester = PassKeeperAPITester()
    success = tester.run_all_tests()
    exit(0 if success else 1)