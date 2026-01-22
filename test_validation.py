import requests

BASE_URL = "http://127.0.0.1:8000"

def test_validation():
    print("Testing validation for negative values")
    try:
        # Login
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get a medicine ID
        meds_resp = requests.get(f"{BASE_URL}/medicines", headers=headers)
        med_id = meds_resp.json()[0]["id"]
        
        # 1. Update with negative quantity
        bad_data = {
            "name": "Bad Med",
            "category": "N/A",
            "manufacturer": "N/A",
            "batchNumber": "N/A",
            "quantity": -10,
            "expiryDate": "N/A",
            "price": 10.0,
            "minStock": 10
        }
        resp = requests.put(f"{BASE_URL}/medicines/{med_id}", json=bad_data, headers=headers)
        print(f"Negative Quantity Update Status: {resp.status_code}")
        if resp.status_code == 400:
            print(f"PASS: Correctly blocked negative quantity: {resp.json()['detail']}")
        else:
            print("FAIL: Permitted negative quantity")

        # 2. Update with negative price
        bad_data["quantity"] = 10
        bad_data["price"] = -5.0
        resp = requests.put(f"{BASE_URL}/medicines/{med_id}", json=bad_data, headers=headers)
        print(f"Negative Price Update Status: {resp.status_code}")
        if resp.status_code == 400:
            print(f"PASS: Correctly blocked negative price: {resp.json()['detail']}")
        else:
            print("FAIL: Permitted negative price")

    except Exception as e:
        print(f"Validation test failed: {e}")

if __name__ == "__main__":
    test_validation()
