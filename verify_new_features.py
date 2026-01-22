import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

def login(username, password):
    resp = requests.post(f"{BASE_URL}/token", data={"username": username, "password": password})
    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def main():
    print("Starting Feature Verification...")
    token = login("admin", "admin123")
    if not token:
        print("FAIL: Login failed")
        sys.exit(1)
    
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Status Logic
    print("\n--- Testing Status Logic ---")
    med_critical = {
        "name": "StatusTestCritical", "quantity": 10, "price": 10.0,
        "category": "Test", "manufacturer": "Test", "batchNumber": "B1",
        "minStock": 5, "expiryDate": "2025-01-01"
    }
    resp = requests.post(f"{BASE_URL}/medicines", json=med_critical, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        if data["status"] == "Critical":
            print("PASS: Quantity 10 -> Critical")
        else:
            print(f"FAIL: Quantity 10 -> {data['status']}, expected Critical")
    else:
        print(f"FAIL: Add medicine failed {resp.text}")

    med_low = med_critical.copy()
    med_low["name"] = "StatusTestLow"
    med_low["quantity"] = 20
    resp = requests.post(f"{BASE_URL}/medicines", json=med_low, headers=headers)
    if resp.status_code == 200:
        if resp.json()["status"] == "Low Stock":
             print("PASS: Quantity 20 -> Low Stock")
        else:
             print(f"FAIL: Quantity 20 -> {resp.json()['status']}, expected Low Stock")

    # 2. Test Search Substring
    print("\n--- Testing Search ---")
    resp = requests.get(f"{BASE_URL}/medicines/search?name=StatusTest", headers=headers)
    if resp.status_code == 200:
        results = resp.json()
        if len(results) >= 2:
            print(f"PASS: Search found {len(results)} items")
        else:
            print(f"FAIL: Search found {len(results)} items, expected >= 2")

    # 3. Test Export
    print("\n--- Testing Export ---")
    for fmt in ["csv", "pdf", "docx"]:
        resp = requests.get(f"{BASE_URL}/medicines/export?format={fmt}", headers=headers)
        if resp.status_code == 200:
            if fmt == "csv" and "text/csv" in resp.headers["content-type"]:
                print("PASS: Export CSV content-type correct")
            elif fmt == "pdf" and "application/pdf" in resp.headers["content-type"]:
                print("PASS: Export PDF content-type correct")
            elif fmt == "docx" and "application/vnd.openxmlformats" in resp.headers["content-type"]:
                print("PASS: Export DOCX content-type correct")
            else:
                 print(f"WARN: Export {fmt} content-type {resp.headers['content-type']}")
        else:
            print(f"FAIL: Export {fmt} failed {resp.status_code}")

    # 4. Test Status Endpoint
    print("\n--- Testing Status Endpoint ---")
    resp = requests.get(f"{BASE_URL}/medicines/status", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        if "Critical" in data and "Low Stock" in data:
            print("PASS: Status endpoint returned categories")
        else:
            print(f"FAIL: Status endpoint missing keys {data.keys()}")
            
    print("\nVerification Complete.")

if __name__ == "__main__":
    main()
