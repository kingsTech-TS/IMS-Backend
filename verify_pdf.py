import requests

BASE_URL = "http://127.0.0.1:8000"

def verify_pdf():
    login_resp = requests.post(f"{BASE_URL}/token", data={"username": "admin", "password": "admin123"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    resp = requests.get(f"{BASE_URL}/medicines/export", params={"format": "pdf"}, headers=headers)
    if resp.status_code == 200:
        content = resp.content
        print(f"PDF Header: {content[:5]}")
        if content.startswith(b"%PDF-"):
            print("PDF header is correct")
        else:
            print("PDF header is INVALID")
    else:
        print(f"Error: {resp.status_code} {resp.text}")

if __name__ == "__main__":
    verify_pdf()
