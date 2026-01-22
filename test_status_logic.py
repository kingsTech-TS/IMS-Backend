import requests

BASE_URL = "http://127.0.0.1:8000"

def test_stock_status():
    print("Testing stock status relative to minStock")
    try:
        # Login
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get a medicine ID
        meds_resp = requests.get(f"{BASE_URL}/medicines", headers=headers)
        med_id = meds_resp.json()[0]["id"]
        
        def update_and_check(qty, min_s):
            data = {
                "name": "StatusTest",
                "category": "N/A",
                "manufacturer": "N/A",
                "batchNumber": "N/A",
                "quantity": qty,
                "expiryDate": "N/A",
                "price": 10.0,
                "minStock": min_s
            }
            resp = requests.put(f"{BASE_URL}/medicines/{med_id}", json=data, headers=headers)
            status = resp.json()["status"]
            print(f"Qty: {qty}, MinStock: {min_s} -> Status: {status}")
            return status

        # Case 1: In Stock (qty >= minStock)
        if update_and_check(110, 100) == "In Stock":
            print("PASS: In Stock correctly identified")
        
        # Case 2: Low Stock (qty < minStock but >= minStock/2)
        if update_and_check(90, 100) == "Low Stock":
            print("PASS: Low Stock correctly identified")
            
        # Case 3: Critical (qty < minStock/2)
        if update_and_check(40, 100) == "Critical":
            print("PASS: Critical correctly identified")

    except Exception as e:
        print(f"Stock status test failed: {e}")

if __name__ == "__main__":
    test_stock_status()
