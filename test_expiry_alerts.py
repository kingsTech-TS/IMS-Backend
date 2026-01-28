import requests
from datetime import datetime, timedelta

BASE_URL = "http://127.0.0.1:8000"

def test_expiry_alerts():
    print("Testing expiry alerts...")
    try:
        # Login
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        if login_resp.status_code != 200:
            print(f"Login failed: {login_resp.text}")
            return
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 1. Add a medicine expiring in 60 days
        expiry_60 = (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d")
        med_expiring = {
            "name": "ExpiringSoonMed",
            "category": "Test",
            "manufacturer": "Test",
            "batchNumber": "EXP60",
            "quantity": 100,
            "expiryDate": expiry_60,
            "price": 10.0,
            "minStock": 20
        }
        add_resp = requests.post(f"{BASE_URL}/medicines", json=med_expiring, headers=headers)
        if add_resp.status_code != 200:
            print(f"Failed to add expiring med: {add_resp.text}")
            return
        
        med_id = add_resp.json()["id"]
        status = add_resp.json()["status"]
        print(f"Expiring medicine status: {status}")
        
        if status == "Expiring Soon":
            print("PASS: status is 'Expiring Soon'")
        else:
            print(f"FAIL: status is {status}, expected 'Expiring Soon'")

        # 2. Check /alerts endpoint
        alerts_resp = requests.get(f"{BASE_URL}/alerts", headers=headers)
        alerts = alerts_resp.json()
        found_in_alerts = any(a["medicineId"] == med_id for a in alerts)
        if found_in_alerts:
            print("PASS: Medicine found in /alerts")
        else:
            print("FAIL: Medicine NOT found in /alerts")

        # 3. Check /medicines/expiring endpoint
        expiring_resp = requests.get(f"{BASE_URL}/medicines/expiring", headers=headers)
        expiring_meds = expiring_resp.json()
        found_in_expiring = any(m["id"] == med_id for m in expiring_meds)
        if found_in_expiring:
            print("PASS: Medicine found in /medicines/expiring")
        else:
            print("FAIL: Medicine NOT found in /medicines/expiring")

        # 4. Check /medicines/status endpoint
        status_resp = requests.get(f"{BASE_URL}/medicines/status", headers=headers)
        status_report = status_resp.json()
        if "Expiring Soon" in status_report and any(m["id"] == med_id for m in status_report["Expiring Soon"]):
            print("PASS: Medicine found in /medicines/status report")
        else:
            print("FAIL: Medicine NOT found in status report 'Expiring Soon' category")

        # Clean up
        requests.delete(f"{BASE_URL}/medicines/{med_id}", headers=headers)

    except Exception as e:
        print(f"Test failed with error: {e}")

if __name__ == "__main__":
    test_expiry_alerts()
