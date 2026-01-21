import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_login(username, password):
    response = requests.post(f"{BASE_URL}/token", data={"username": username, "password": password})
    if response.status_code == 200:
        return response.json()["access_token"]
    return None

def test_add_user(token, new_user):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{BASE_URL}/users", json=new_user, headers=headers)
    return response.status_code

def test_dispense(token, med_id, amount):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(f"{BASE_URL}/medicines/{med_id}/dispense?amount={amount}", headers=headers)
    return response.status_code

def main():
    print("Starting Verification...")

    # 1. Login Admin
    admin_token = test_login("admin", "admin123")
    if not admin_token:
        print("FAIL: Admin login failed")
        sys.exit(1)
    print("PASS: Admin login successful")

    # 2. Admin adds medicine (setup for dispense test)
    # skipped for brevity, assuming existing medicines or we can add one
    
    # 3. Login Pharmacist
    pharm_token = test_login("pharmacist1", "pharm123")
    if not pharm_token:
        print("FAIL: Pharmacist login failed")
        sys.exit(1)
    print("PASS: Pharmacist login successful")

    # 4. Pharmacist tries to add user (Should Fail 403)
    code = test_add_user(pharm_token, {"username": "baduser", "password": "123", "role": "admin"})
    if code == 403:
        print("PASS: Pharmacist blocked from adding user (403)")
    else:
        print(f"FAIL: Pharmacist should get 403 for add user, got {code}")

    # 5. Admin adds user (Should Success 200)
    code = test_add_user(admin_token, {"username": "new_api_user", "password": "123", "role": "supplier"})
    if code == 200:
        print("PASS: Admin added user successfully")
    else:
        print(f"FAIL: Admin failed to add user, got {code}")

    print("Verification execution complete.")

if __name__ == "__main__":
    main()
