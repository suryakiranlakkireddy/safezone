import requests
import sys
import json
from datetime import datetime

class CyberSafeAPITester:
    def __init__(self, base_url="https://safecyber-connect.preview.emergentagent.com"):
        self.base_url = base_url
        self.parent_token = None
        self.child_token = None
        self.parent_user = None
        self.child_user = None
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def run_test(self, name, method, endpoint, expected_status, data=None, token=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    return True, response.json()
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"Response: {response.text[:200]}")
                self.failed_tests.append({
                    "test": name,
                    "expected": expected_status,
                    "actual": response.status_code,
                    "response": response.text[:200]
                })
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.failed_tests.append({
                "test": name,
                "error": str(e)
            })
            return False, {}

    def test_health_check(self):
        """Test API health check"""
        return self.run_test("Health Check", "GET", "api/", 200)

    def test_parent_registration(self):
        """Test parent registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        parent_data = {
            "username": f"test_parent_{timestamp}",
            "email": f"parent_{timestamp}@test.com",
            "password": "TestPass123!",
            "role": "parent"
        }
        
        success, response = self.run_test(
            "Parent Registration",
            "POST",
            "api/auth/register",
            200,
            data=parent_data
        )
        
        if success and 'token' in response:
            self.parent_token = response['token']
            self.parent_user = response['user']
            return True
        return False

    def test_child_registration(self):
        """Test child registration"""
        if not self.parent_user:
            print("❌ Cannot test child registration - no parent user")
            return False
            
        timestamp = datetime.now().strftime('%H%M%S')
        child_data = {
            "username": f"test_child_{timestamp}",
            "email": f"child_{timestamp}@test.com",
            "password": "TestPass123!",
            "role": "child",
            "parent_email": self.parent_user['email']
        }
        
        success, response = self.run_test(
            "Child Registration",
            "POST",
            "api/auth/register",
            200,
            data=child_data
        )
        
        if success and 'token' in response:
            self.child_token = response['token']
            self.child_user = response['user']
            return True
        return False

    def test_parent_login(self):
        """Test parent login"""
        if not self.parent_user:
            print("❌ Cannot test parent login - no parent user")
            return False
            
        login_data = {
            "email": self.parent_user['email'],
            "password": "TestPass123!"
        }
        
        success, response = self.run_test(
            "Parent Login",
            "POST",
            "api/auth/login",
            200,
            data=login_data
        )
        return success

    def test_child_login(self):
        """Test child login"""
        if not self.child_user:
            print("❌ Cannot test child login - no child user")
            return False
            
        login_data = {
            "email": self.child_user['email'],
            "password": "TestPass123!"
        }
        
        success, response = self.run_test(
            "Child Login",
            "POST",
            "api/auth/login",
            200,
            data=login_data
        )
        return success

    def test_chat_scanner(self):
        """Test chat message scanning"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test chat scanner - no child authentication")
            return False
            
        chat_data = {
            "message": "Hey, want to meet up alone? Don't tell your parents.",
            "child_id": self.child_user['id']
        }
        
        success, response = self.run_test(
            "Chat Scanner",
            "POST",
            "api/chat/scan",
            200,
            data=chat_data,
            token=self.child_token
        )
        
        if success and 'risk_level' in response:
            print(f"   Risk Level: {response['risk_level']}")
            return True
        return False

    def test_fake_profile_detection(self):
        """Test fake profile detection"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test profile detection - no child authentication")
            return False
            
        profile_data = {
            "profile_data": "Username: hotgirl123, 0 followers, 0 posts, created yesterday, no profile picture",
            "child_id": self.child_user['id']
        }
        
        success, response = self.run_test(
            "Fake Profile Detection",
            "POST",
            "api/profile/detect",
            200,
            data=profile_data,
            token=self.child_token
        )
        
        if success and 'is_fake' in response:
            print(f"   Is Fake: {response['is_fake']}")
            return True
        return False

    def test_sos_alert(self):
        """Test SOS alert trigger"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test SOS alert - no child authentication")
            return False
            
        sos_data = {
            "child_id": self.child_user['id'],
            "location": "School playground",
            "message": "Someone is following me"
        }
        
        success, response = self.run_test(
            "SOS Alert Trigger",
            "POST",
            "api/sos/trigger",
            200,
            data=sos_data,
            token=self.child_token
        )
        return success

    def test_awareness_quiz(self):
        """Test awareness quiz generation"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test awareness quiz - no child authentication")
            return False
            
        quiz_data = {
            "topic": "Password Safety",
            "child_id": self.child_user['id']
        }
        
        success, response = self.run_test(
            "Awareness Quiz Generation",
            "POST",
            "api/awareness/quiz",
            200,
            data=quiz_data,
            token=self.child_token
        )
        
        if success and 'quiz' in response:
            print(f"   Quiz generated successfully")
            return True
        return False

    def test_awareness_scenario(self):
        """Test awareness scenario generation"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test awareness scenario - no child authentication")
            return False
            
        scenario_data = {
            "scenario_type": "Stranger Message",
            "child_id": self.child_user['id']
        }
        
        success, response = self.run_test(
            "Awareness Scenario Generation",
            "POST",
            "api/awareness/scenario",
            200,
            data=scenario_data,
            token=self.child_token
        )
        
        if success and 'scenario' in response:
            print(f"   Scenario generated successfully")
            return True
        return False

    def test_child_complaint(self):
        """Test child complaint submission"""
        if not self.child_token or not self.child_user:
            print("❌ Cannot test child complaint - no child authentication")
            return False
            
        complaint_data = {
            "user_id": self.child_user['id'],
            "complaint_type": "Cyberbullying",
            "description": "Someone is sending me threatening messages on social media",
            "evidence": "Screenshots saved on phone"
        }
        
        success, response = self.run_test(
            "Child Complaint Submission",
            "POST",
            "api/complaint/submit",
            200,
            data=complaint_data,
            token=self.child_token
        )
        return success

    def test_parent_get_children(self):
        """Test parent getting children list"""
        if not self.parent_token:
            print("❌ Cannot test get children - no parent authentication")
            return False
            
        success, response = self.run_test(
            "Parent Get Children",
            "GET",
            "api/parent/children",
            200,
            token=self.parent_token
        )
        
        if success and 'children' in response:
            print(f"   Found {len(response['children'])} children")
            return True
        return False

    def test_parent_get_activities(self):
        """Test parent getting child activities"""
        if not self.parent_token or not self.child_user:
            print("❌ Cannot test get activities - missing authentication")
            return False
            
        success, response = self.run_test(
            "Parent Get Child Activities",
            "GET",
            f"api/parent/activities/{self.child_user['id']}",
            200,
            token=self.parent_token
        )
        
        if success and 'child' in response:
            print(f"   Activities retrieved for child")
            return True
        return False

    def test_parent_notifications(self):
        """Test parent notifications"""
        if not self.parent_token:
            print("❌ Cannot test notifications - no parent authentication")
            return False
            
        success, response = self.run_test(
            "Parent Notifications",
            "GET",
            "api/parent/notifications",
            200,
            token=self.parent_token
        )
        
        if success:
            print(f"   Notifications retrieved successfully")
            return True
        return False

    def test_parent_block_user(self):
        """Test parent blocking user"""
        if not self.parent_token or not self.parent_user:
            print("❌ Cannot test block user - no parent authentication")
            return False
            
        block_data = {
            "parent_id": self.parent_user['id'],
            "blocked_username": "suspicious_user123",
            "reason": "Inappropriate messages to my child"
        }
        
        success, response = self.run_test(
            "Parent Block User",
            "POST",
            "api/parent/block-user",
            200,
            data=block_data,
            token=self.parent_token
        )
        return success

    def test_parent_complaint(self):
        """Test parent complaint submission"""
        if not self.parent_token or not self.parent_user:
            print("❌ Cannot test parent complaint - no parent authentication")
            return False
            
        complaint_data = {
            "user_id": self.parent_user['id'],
            "complaint_type": "Online Predator",
            "description": "Someone is trying to groom my child online",
            "evidence": "Chat logs and screenshots"
        }
        
        success, response = self.run_test(
            "Parent Complaint Submission",
            "POST",
            "api/complaint/submit",
            200,
            data=complaint_data,
            token=self.parent_token
        )
        return success

def main():
    print("🚀 Starting CyberSafe API Testing...")
    print("=" * 50)
    
    tester = CyberSafeAPITester()
    
    # Test sequence
    tests = [
        ("Health Check", tester.test_health_check),
        ("Parent Registration", tester.test_parent_registration),
        ("Child Registration", tester.test_child_registration),
        ("Parent Login", tester.test_parent_login),
        ("Child Login", tester.test_child_login),
        ("Chat Scanner", tester.test_chat_scanner),
        ("Fake Profile Detection", tester.test_fake_profile_detection),
        ("SOS Alert", tester.test_sos_alert),
        ("Awareness Quiz", tester.test_awareness_quiz),
        ("Awareness Scenario", tester.test_awareness_scenario),
        ("Child Complaint", tester.test_child_complaint),
        ("Parent Get Children", tester.test_parent_get_children),
        ("Parent Get Activities", tester.test_parent_get_activities),
        ("Parent Notifications", tester.test_parent_notifications),
        ("Parent Block User", tester.test_parent_block_user),
        ("Parent Complaint", tester.test_parent_complaint)
    ]
    
    # Run all tests
    for test_name, test_func in tests:
        try:
            test_func()
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {str(e)}")
            tester.failed_tests.append({
                "test": test_name,
                "error": str(e)
            })
    
    # Print results
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {tester.tests_passed}/{tester.tests_run} passed")
    
    if tester.failed_tests:
        print("\n❌ Failed Tests:")
        for failure in tester.failed_tests:
            error_msg = failure.get('error', f"Expected {failure.get('expected')}, got {failure.get('actual')}")
            print(f"  - {failure['test']}: {error_msg}")
    
    success_rate = (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
    print(f"\n✅ Success Rate: {success_rate:.1f}%")
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())