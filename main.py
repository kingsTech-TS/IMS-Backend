from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import csv
import os
from datetime import datetime

app = FastAPI()

# Files
MEDICINE_FILE = "medicines.txt"
USER_FILE = "user.txt"
LOG_FILE = "log.txt"

# Models
class Medicine(BaseModel):
    id: int
    name: str
    quantity: int
    price: float

class User(BaseModel):
    username: str
    password: str
    role: str

class UserPublic(BaseModel):
    username: str
    role: str

class MedicineCreate(BaseModel):
    name: str
    quantity: int
    price: float

# Helpers
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_activity(activity: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{get_timestamp()}] {activity}\n")

def load_medicines() -> List[Medicine]:
    meds = []
    if not os.path.exists(MEDICINE_FILE):
        return meds
    with open(MEDICINE_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 4:
                meds.append(Medicine(id=int(parts[0]), name=parts[1], quantity=int(parts[2]), price=float(parts[3])))
    return meds

def save_medicines(meds: List[Medicine]):
    with open(MEDICINE_FILE, "w") as f:
        for med in meds:
            f.write(f"{med.id},{med.name},{med.quantity},{med.price}\n")

def load_users() -> List[User]:
    users = []
    if not os.path.exists(USER_FILE):
        return users
    with open(USER_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 3:
                users.append(User(username=parts[0], password=parts[1], role=parts[2]))
    return users

def save_users(users: List[User]):
    with open(USER_FILE, "w") as f:
        for user in users:
            f.write(f"{user.username},{user.password},{user.role}\n")

# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    # In a real app, 'token' would be a JWT. 
    # For this port maintaining simple file compat, we'll use "username:password" as a simple bearer token mechanism 
    # or just assume the token IS the username for simplicity in this file-based demo context, 
    # BUT since we used OAuth2PasswordRequestForm, we get a token.
    # Let's keep it simple: The token returned is just the username.
    users = load_users()
    for user in users:
        if user.username == token:
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

def require_role(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Operation not permitted for this user role")
        return current_user
    return role_checker

# Endpoints

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = load_users()
    for user in users:
        if user.username == form_data.username and user.password == form_data.password:
            # Check role specific logic if needed, but for login just return token
            log_activity(f"User {user.username} logged in as {user.role}")
            return {"access_token": user.username, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/users/me", response_model=UserPublic)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserPublic(username=current_user.username, role=current_user.role)

@app.get("/medicines", response_model=List[Medicine])
async def get_medicines(current_user: User = Depends(get_current_user)):
    # All roles can view
    return load_medicines()

@app.get("/medicines/search")
async def search_medicine(name: str, current_user: User = Depends(get_current_user)):
    meds = load_medicines()
    return [m for m in meds if m.name.lower() == name.lower()]

@app.post("/medicines", dependencies=[Depends(require_role(["admin"]))])
async def add_medicine(med: MedicineCreate, current_user: User = Depends(get_current_user)):
    meds = load_medicines()
    next_id = 1
    if meds:
        next_id = max(m.id for m in meds) + 1
    
    new_med = Medicine(id=next_id, name=med.name, quantity=med.quantity, price=med.price)
    meds.append(new_med)
    save_medicines(meds)
    log_activity(f"Added medicine: {med.name}")
    return new_med

@app.put("/medicines/{med_id}/restock", dependencies=[Depends(require_role(["admin", "supplier"]))])
async def restock_medicine(med_id: int, amount: int, current_user: User = Depends(get_current_user)):
    meds = load_medicines()
    for m in meds:
        if m.id == med_id:
            m.quantity += amount
            save_medicines(meds)
            log_activity(f"Restocked medicine ID {med_id} by {amount}")
            return m
    raise HTTPException(status_code=404, detail="Medicine not found")

@app.put("/medicines/{med_id}/dispense", dependencies=[Depends(require_role(["admin", "pharmacist"]))])
async def dispense_medicine(med_id: int, amount: int, current_user: User = Depends(get_current_user)):
    meds = load_medicines()
    for m in meds:
        if m.id == med_id:
            if m.quantity < amount:
                raise HTTPException(status_code=400, detail="Insufficient stock")
            m.quantity -= amount
            save_medicines(meds)
            log_activity(f"Dispensed medicine ID {med_id} amount {amount}")
            return m
    raise HTTPException(status_code=404, detail="Medicine not found")

@app.get("/users", dependencies=[Depends(require_role(["admin"]))], response_model=List[UserPublic])
async def read_users(current_user: User = Depends(get_current_user)):
    users = load_users()
    # Filter to show only pharmacists as per C++ logic "View pharmacists", but let's show all for admin
    return [UserPublic(username=u.username, role=u.role) for u in users]

@app.post("/users", dependencies=[Depends(require_role(["admin"]))])
async def create_user(user: User, current_user: User = Depends(get_current_user)):
    users = load_users()
    if any(u.username == user.username for u in users):
        raise HTTPException(status_code=400, detail="Username already exists")
    users.append(user)
    save_users(users)
    log_activity(f"Admin added new user: {user.username} ({user.role})")
    return {"message": "User added successfully"}
