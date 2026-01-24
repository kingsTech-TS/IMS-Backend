from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
import os

async def test_mongo():
    uri = "mongodb://localhost:27017"
    print(f"Connecting to {uri}...")
    try:
        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        db = client.get_database("inventory_db")
        print("Checking users collection...")
        count = await db.users.count_documents({})
        print(f"Connection Successful! Found {count} users.")
    except Exception as e:
        print(f"Connection Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_mongo())
