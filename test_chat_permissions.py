import requests

BASE_URL = "http://127.0.0.1:8005"

def test_permissions():
    print("Starting Chat Permission Verification...")
    try:
        # 1. Credentials
        users = {
            "admin": {"username": "admin", "password": "19724212"},
            "pharm": {"username": "agbacist", "password": "1234"},
            "supp1": {"username": "supplier1", "password": "supp123"},
            "supp2": {"username": "supliz@gmail.com", "password": "healme12"}
        }

        tokens = {}
        for key, creds in users.items():
            res = requests.post(f"{BASE_URL}/token", data=creds)
            if res.status_code == 200:
                tokens[key] = res.json()["access_token"]
            else:
                print(f"Failed to login as {key}: {res.text}")
                return

        def get_headers(key):
            return {"Authorization": f"Bearer {tokens[key]}"}

        # --- Test Case 1: Pharmacist can message anyone ---
        print("\n[Pharmacist Permissions]")
        # To Supplier
        res = requests.post(f"{BASE_URL}/messages", 
                            json={"receiver": "supplier1", "content": "Hello Supplier"}, 
                            headers=get_headers("pharm"))
        print(f"Pharm -> Supp: {res.status_code} (Expected 200)")
        
        # To Admin
        res = requests.post(f"{BASE_URL}/messages", 
                            json={"receiver": "admin", "content": "Hello Admin"}, 
                            headers=get_headers("pharm"))
        print(f"Pharm -> Admin: {res.status_code} (Expected 200)")

        # --- Test Case 2: Supplier limitations ---
        print("\n[Supplier Permissions]")
        # To Pharmacist
        res = requests.post(f"{BASE_URL}/messages", 
                            json={"receiver": "agbacist", "content": "Hello Pharmacist"}, 
                            headers=get_headers("supp1"))
        print(f"Supp -> Pharm: {res.status_code} (Expected 200)")

        # To another Supplier (Restricted)
        res = requests.post(f"{BASE_URL}/messages", 
                            json={"receiver": "supliz@gmail.com", "content": "Hello Fellow Supplier"}, 
                            headers=get_headers("supp1"))
        print(f"Supp -> Supp: {res.status_code} (Expected 403)")
        if res.status_code == 403:
             print(f"Details: {res.json()['detail']}")

        # --- Test Case 3: Admin oversight ---
        print("\n[Admin Oversight]")
        # Admin inspecting Pharm <-> Supp1
        res = requests.get(f"{BASE_URL}/admin/messages/inspect/agbacist/supplier1", headers=get_headers("admin"))
        print(f"Admin Inspect (Pharm <-> Supp): {res.status_code} (Expected 200)")
        if res.status_code == 200:
            print(f"Count: {len(res.json())} messages found")

        # Pharmacist trying to inspect (Restricted)
        res = requests.get(f"{BASE_URL}/admin/messages/inspect/supplier1/admin", headers=get_headers("pharm"))
        print(f"Pharm Inspect: {res.status_code} (Expected 403)")

        print("\nVerification Finished.")

    except Exception as e:
        print(f"Verification Error: {e}")

if __name__ == "__main__":
    test_permissions()
