import requests
import json
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000"

# 1. Login as Admin
def login(username, password):
    response = requests.post(f"{BASE_URL}/token", data={"username": username, "password": password})
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print(f"Login failed: {response.text}")
        return None

admin_token = login("admin@example.com", "healme12") # Assuming this admin exists
if not admin_token:
    # Try default admin if above fails, or just assume user knows creds. 
    # For this script to work, we need a valid admin.
    pass

headers = {"Authorization": f"Bearer {admin_token}"}

def run_tests():
    print("--- Starting Verification ---")
    
    # 2. Get Suppliers
    print("\n[TEST] GET /suppliers")
    res = requests.get(f"{BASE_URL}/suppliers", headers=headers)
    print(f"Status: {res.status_code}")
    suppliers = res.json()
    print(f"Found {len(suppliers)} suppliers: {[s['username'] for s in suppliers]}")
    
    supplier_name = None
    if suppliers:
        supplier_name = suppliers[0]['username']
    else:
        print("No suppliers found. Please add a user with role 'supplier' first.")
        supplier_name = "test_supplier_auto" # Fallback

    # 3. Add Medicine with Supplier and Near Expiry
    print("\n[TEST] POST /medicines (Near Expiry)")
    expiry_date = (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d") # 2 months from now
    
    med_data = {
        "name": f"TestMed_Exp_{datetime.now().timestamp()}",
        "category": "Antibiotics",
        "manufacturer": "HealthCorp",
        "batchNumber": "BATCH001",
        "quantity": 100, # In stock
        "expiryDate": expiry_date,
        "price": 10.5,
        "minStock": 20,
        "supplier": supplier_name
    }
    
    res = requests.post(f"{BASE_URL}/medicines", json=med_data, headers=headers)
    print(f"Status: {res.status_code}")
    if res.status_code == 200:
        med_id = res.json()["id"]
        print(f"Created Medicine ID: {med_id}")
    else:
        print(f"Failed to create medicine: {res.text}")
        return

    # 4. Check Alerts (Should appear due to Expiry < 90 days)
    print("\n[TEST] GET /alerts")
    res = requests.get(f"{BASE_URL}/alerts", headers=headers)
    alerts = res.json()
    
    found_alert = False
    for alert in alerts:
        if alert["medicineId"] == med_id:
            found_alert = True
            print("SUCCESS: Found alert for new medicine.")
            print(f"Days Remaining: {alert.get('daysRemaining')}")
            print(f"Timestamp: {alert.get('timestamp')}")
            print(f"Price: {alert.get('price')}")
            break
            
    if not found_alert:
        print("FAILURE: Did not find alert for near-expiry medicine.")

    # 5. Request Restock
    print("\n[TEST] POST /medicines/{id}/request-restock")
    res = requests.post(f"{BASE_URL}/medicines/{med_id}/request-restock?amount=50", headers=headers)
    print(f"Status: {res.status_code}")
    print(res.json())

if __name__ == "__main__":
    if admin_token:
        run_tests()
    else:
        print("Cannot run tests without admin login.")
