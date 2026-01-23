import requests
import sys

BASE_URL = "https://ims-backend-10r7.onrender.com"

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
    
def test_update_medicine(token, med_id, update_data):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(f"{BASE_URL}/medicines/{med_id}", json=update_data, headers=headers)
    return response.status_code

def test_delete_medicine(token, med_id):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{BASE_URL}/medicines/{med_id}", headers=headers)
    return response.status_code

def test_delete_user(token, username):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.delete(f"{BASE_URL}/users/{username}", headers=headers)
    return response.status_code

def main():
    print("Starting Verification...")

    # 1. Login Admin
    admin_token = test_login("admin", "admin123")
    if not admin_token:
        print("FAIL: Admin login failed")
        sys.exit(1)
    print("PASS: Admin login successful")

    # 2. Add full medicine
    new_med = {
        "name": "FullTestMed",
        "quantity": 100,
        "price": 50.0,
        "category": "Tablets",
        "manufacturer": "PharmaCorp",
        "batchNumber": "B123",
        "minStock": 10,
        "expiryDate": "2025-12-31"
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = requests.post(f"{BASE_URL}/medicines", json=new_med, headers=headers)
    if resp.status_code == 200:
        med_data = resp.json()
        med_id = med_data["id"]
        if med_data["category"] == "Tablets":
             print("PASS: Medicine added with new fields")
        else:
             print("FAIL: Medicine fields missing")
    else:
        print(f"FAIL: Add medicine failed {resp.status_code}")
        sys.exit(1)

    # 3. Update medicine
    update_data = new_med.copy()
    update_data["name"] = "UpdatedTestMed"
    code = test_update_medicine(admin_token, med_id, update_data)
    if code == 200:
        print("PASS: Medicine updated")
    else:
        print(f"FAIL: Medicine update failed {code}")

    # 4. Delete medicine
    code = test_delete_medicine(admin_token, med_id)
    if code == 200:
        print("PASS: Medicine deleted")
    else:
        print(f"FAIL: Medicine delete failed {code}")

    # 5. User CRUD
    # Add
    test_user = {"username": "todelete", "password": "123", "role": "supplier"}
    test_add_user(admin_token, test_user)
    
    # Delete
    code = test_delete_user(admin_token, "todelete")
    if code == 200:
        print("PASS: User deleted")
    else:
        print(f"FAIL: User delete failed {code}")

    print("Verification execution complete.")

if __name__ == "__main__":
    main()