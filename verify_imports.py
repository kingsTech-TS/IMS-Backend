try:
    import motor
    import motor.motor_asyncio
    import pymongo
    import dns.resolver
    print("SUCCESS: motor, motor.motor_asyncio, pymongo, and dns.resolver imported correctly.")
    print(f"Motor version: {motor.version if hasattr(motor, 'version') else 'unknown'}")
    print(f"PyMongo version: {pymongo.version}")
except ImportError as e:
    print(f"FAILURE: {e}")
except Exception as e:
    print(f"ERROR: {e}")
