import requests

BASE_URL = "http://127.0.0.1:8000"

def test_all_features():
    print("=" * 60)
    print("TESTING BUG FIXES AND NEW FEATURES")
    print("=" * 60)
    
    # Login as admin
    print("\n1. Logging in as admin...")
    login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
    if login_resp.status_code != 200:
        print(f"❌ Login failed: {login_resp.text}")
        return
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Login successful")
    
    # Test 1: Create user with auto-login
    print("\n2. Testing auto-login creation...")
    new_user = {
        "username": "temp_user",
        "email": "testuser@example.com",
        "password": "temp",
        "role": "pharmacist",
        "firstName": "Test",
        "lastName": "User",
        "gender": "Other",
        "phoneNumber": "555-0100",
        "profilePic": "",
        "address": ""
    }
    create_resp = requests.post(f"{BASE_URL}/users", json=new_user, headers=headers)
    print(f"Status: {create_resp.status_code}")
    if create_resp.status_code == 200:
        result = create_resp.json()
        print(f"✅ User created: {result}")
        print(f"   Username: {result.get('username')}")
        print(f"   Default Password: {result.get('defaultPassword')}")
    else:
        print(f"❌ Failed: {create_resp.text}")
    
    # Test 2: Edit user (should update, not duplicate)
    print("\n3. Testing edit user (should not create duplicates)...")
    edit_user = new_user.copy()
    edit_user["firstName"] = "Updated"
    edit_user["username"] = "testuser@example.com"  # Use email as username
    edit_resp = requests.put(f"{BASE_URL}/users/testuser@example.com", json=edit_user, headers=headers)
    print(f"Status: {edit_resp.status_code}")
    if edit_resp.status_code == 200:
        print(f"✅ User updated: {edit_resp.json()}")
    else:
        print(f"❌ Failed: {edit_resp.text}")
    
    # Test 3: Delete user
    print("\n4. Testing delete user...")
    delete_resp = requests.delete(f"{BASE_URL}/users/testuser@example.com", headers=headers)
    print(f"Status: {delete_resp.status_code}")
    if delete_resp.status_code == 200:
        print(f"✅ User deleted: {delete_resp.json()}")
    else:
        print(f"❌ Failed: {delete_resp.text}")
    
    # Test 4: Activity logging
    print("\n5. Testing activity logging endpoint...")
    activities_resp = requests.get(f"{BASE_URL}/activities", headers=headers)
    print(f"Status: {activities_resp.status_code}")
    if activities_resp.status_code == 200:
        activities = activities_resp.json()
        print(f"✅ Retrieved {len(activities)} activities")
        if activities:
            print(f"   Latest: {activities[0]}")
    else:
        print(f"❌ Failed: {activities_resp.text}")
    
    # Test 5: Alerts endpoint
    print("\n6. Testing alerts endpoint...")
    alerts_resp = requests.get(f"{BASE_URL}/alerts", headers=headers)
    print(f"Status: {alerts_resp.status_code}")
    if alerts_resp.status_code == 200:
        alerts = alerts_resp.json()
        print(f"✅ Retrieved {len(alerts)} alerts")
        if alerts:
            print(f"   Sample alert: {alerts[0]}")
    else:
        print(f"❌ Failed: {alerts_resp.text}")
    
    # Test 6: Dispense endpoint
    print("\n7. Testing dispense endpoint...")
    meds_resp = requests.get(f"{BASE_URL}/medicines", headers=headers)
    if meds_resp.status_code == 200 and meds_resp.json():
        med_id = meds_resp.json()[0]["id"]
        dispense_resp = requests.put(f"{BASE_URL}/medicines/{med_id}/dispense?amount=1", headers=headers)
        print(f"Status: {dispense_resp.status_code}")
        if dispense_resp.status_code == 200:
            print(f"✅ Dispensed medicine: {dispense_resp.json()}")
        else:
            print(f"❌ Failed: {dispense_resp.text}")
    else:
        print("⚠️  No medicines available to test dispense")
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    test_all_features()
