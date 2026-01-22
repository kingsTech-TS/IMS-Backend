import requests

BASE_URL = "http://127.0.0.1:8000"

def test_user_profile():
    print("Testing User Profile Features")
    try:
        # 1. Login
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        if login_resp.status_code != 200:
            print(f"Login failed: {login_resp.text}")
            return
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Get Profile
        print("\nGetting profile...")
        profile_resp = requests.get(f"{BASE_URL}/users/me/profile", headers=headers)
        print(f"Status: {profile_resp.status_code}")
        profile = profile_resp.json()
        print(f"Initial Profile: {profile}")
        
        # 3. Update Profile
        print("\nUpdating profile...")
        update_data = {
            "firstName": "Super",
            "lastName": "Admin",
            "gender": "Other",
            "phoneNumber": "555-0199",
            "profilePic": "https://example.com/admin.jpg",
            "address": "Admin Tower 1"
        }
        update_resp = requests.put(f"{BASE_URL}/users/me/profile", json=update_data, headers=headers)
        print(f"Update Status: {update_resp.status_code}")
        if update_resp.status_code == 200:
            print(f"Updated Profile: {update_resp.json()}")
            if update_resp.json()["firstName"] == "Super":
                print("PASS: Profile info updated correctly")
            else:
                print("FAIL: Profile info mismatch")
        
        # 4. Change Login Details
        print("\nChanging password...")
        login_update = {
            "newPassword": "newpassword123",
            "currentPassword": "admin123"
        }
        login_update_resp = requests.put(f"{BASE_URL}/users/me/login-details", json=login_update, headers=headers)
        print(f"Login Update Status: {login_update_resp.status_code}")
        print(f"Response: {login_update_resp.json()}")
        
        # 5. Verify Old Password Fails
        print("\nVerifying old password fails...")
        old_login = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        if old_login.status_code != 200:
            print("PASS: Old password rejected")
        else:
            print("FAIL: Old password still works")
            
        # 6. Verify New Password Works
        print("\nVerifying new password works...")
        new_login = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "newpassword123"})
        if new_login.status_code == 200:
            print("PASS: New password accepted")
        else:
            print(f"FAIL: New password rejected: {new_login.text}")
            
        # 7. Restore Password for future tests
        new_token = new_login.json()["access_token"]
        restore_headers = {"Authorization": f"Bearer {new_token}"}
        requests.put(f"{BASE_URL}/users/me/login-details", 
                     json={"newPassword": "admin123", "currentPassword": "newpassword123"}, 
                     headers=restore_headers)
        print("\nPassword restored to admin123")

    except Exception as e:
        print(f"Verification test failed: {e}")

if __name__ == "__main__":
    test_user_profile()
