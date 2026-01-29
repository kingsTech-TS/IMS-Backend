import requests

BASE_URL = "http://127.0.0.1:8000" # Adjusted to match default or main.py if known, but let's check common ports

def test_user_list_permissions():
    print("Starting User List Permission Verification...")
    try:
        # 1. Credentials (using existing ones from test_chat_permissions.py or common defaults)
        users = {
            "admin": {"username": "admin", "password": "19724212"},
            "pharm": {"username": "agbacist", "password": "1234"},
            "supp1": {"username": "supplier1", "password": "supp123"}
        }

        tokens = {}
        for key, creds in users.items():
            res = requests.post(f"{BASE_URL}/token", data=creds)
            if res.status_code == 200:
                tokens[key] = res.json()["access_token"]
            else:
                print(f"Failed to login as {key}: {res.text}")
                # Try common fallback if first port fails
                continue

        def get_headers(key):
            return {"Authorization": f"Bearer {tokens[key]}"}

        # --- Test Case 1: Admin can see all users ---
        print("\n[Admin Permissions]")
        res = requests.get(f"{BASE_URL}/users", headers=get_headers("admin"))
        print(f"Admin GET /users: {res.status_code} (Expected 200)")
        if res.status_code == 200:
            print(f"Count: {len(res.json())} users found")

        # --- Test Case 2: Pharmacist can see all users ---
        print("\n[Pharmacist Permissions]")
        res = requests.get(f"{BASE_URL}/users", headers=get_headers("pharm"))
        print(f"Pharm GET /users: {res.status_code} (Expected 200)")
        if res.status_code == 200:
            print(f"Count: {len(res.json())} users found")

        # --- Test Case 3: Supplier can see only admins and pharmacists ---
        print("\n[Supplier Permissions]")
        res = requests.get(f"{BASE_URL}/users", headers=get_headers("supp1"))
        print(f"Supp GET /users: {res.status_code} (Expected 200)")
        if res.status_code == 200:
            users_list = res.json()
            roles = set(u['role'].strip().lower() for u in users_list)
            print(f"Count: {len(users_list)} users found")
            print(f"Roles found: {roles}")
            if "supplier" in roles:
                print("FAILURE: Supplier should NOT see other suppliers in this list!")
            else:
                print("SUCCESS: Supplier sees only permitted roles.")

        print("\nVerification Finished.")

    except Exception as e:
        print(f"Verification Error: {e}")

if __name__ == "__main__":
    test_user_list_permissions()
