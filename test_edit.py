import requests

BASE_URL = "http://127.0.0.1:8000"

def test_edit():
    print("Testing edit medicine")
    try:
        # Login
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        if login_resp.status_code != 200:
            print(f"Login failed: {login_resp.text}")
            return
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get medicines
        meds_resp = requests.get(f"{BASE_URL}/medicines", headers=headers)
        if meds_resp.status_code != 200:
            print(f"Failed to get medicines: {meds_resp.text}")
            return
        
        meds = meds_resp.json()
        if not meds:
            print("No medicines found")
            return
        
        target_med = meds[0]
        med_id = target_med["id"]
        print(f"Editing medicine ID: {med_id}, Name: {target_med['name']}")
        
        # Update data
        update_data = {
            "name": target_med["name"] + " Updated",
            "category": target_med["category"],
            "manufacturer": target_med["manufacturer"],
            "batchNumber": target_med["batchNumber"],
            "quantity": target_med["quantity"] + 10,
            "expiryDate": target_med["expiryDate"],
            "price": target_med["price"] + 5.0,
            "minStock": target_med["minStock"]
        }
        
        resp = requests.put(f"{BASE_URL}/medicines/{med_id}", json=update_data, headers=headers)
        print(f"Update Status Code: {resp.status_code}")
        if resp.status_code == 200:
            updated_med = resp.json()
            print(f"Updated Medicine: {updated_med}")
            if updated_med["name"].endswith(" Updated"):
                print("SUCCESS: Medicine updated correctly")
            else:
                print("FAILURE: Medicine name not updated as expected")
        else:
            print(f"Error: {resp.text}")
            
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_edit()
