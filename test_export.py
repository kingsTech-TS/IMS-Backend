import requests

BASE_URL = "http://127.0.0.1:8000"

def test_export(fmt):
    print(f"Testing export for format: {fmt}")
    # We need a token. Using 'admin' with 'admin123' as per previous setup.
    try:
        login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
        if login_resp.status_code != 200:
            print(f"Login failed: {login_resp.text}")
            return
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        resp = requests.get(f"{BASE_URL}/medicines/export", params={"format": fmt}, headers=headers)
        print(f"Status Code: {resp.status_code}")
        if resp.status_code == 200:
            print(f"Content-Type: {resp.headers.get('Content-Type')}")
            print(f"Content-Disposition: {resp.headers.get('Content-Disposition')}")
            print(f"Size: {len(resp.content)} bytes")
        else:
            print(f"Error: {resp.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    for f in ["csv", "pdf", "docx"]:
        test_export(f)
        print("-" * 20)
