import jwt
import datetime
import time

# --- Configuration ---
SECRET_KEY = "your-super-secret-key-that-should-be-long-and-random"
ALGORITHM = "HS256"

# In a real application, this would be a persistent store (DB, Redis)
# and tokens would ideally be identified by a unique ID (JTI) rather than the full token string.
token_blacklist = set()

def create_jwt_token(user_id: int, expires_in_seconds: int) -> str:
    """
    Creates a JWT token for a given user ID with a specified expiration time in seconds.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in_seconds),
        "iat": datetime.datetime.utcnow(),
        "jti": f"{user_id}-{datetime.datetime.utcnow().timestamp()}" # Unique ID for potential revocation
    }
    # Inline comment: This is where the JWT is signed with the secret key and expiration time.
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_jwt_token(token: str) -> dict | None:
    """
    Verifies a JWT token and returns its payload if valid, None otherwise.
    Checks for expiration and if the token is blacklisted.
    """
    if token in token_blacklist:
        print(f"  [SECURITY] Token is blacklisted. Access denied.")
        return None
    try:
        # Inline comment: This is where the JWT signature is verified and expiration checked.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"  [INFO] Token verified successfully. User ID: {payload['user_id']}")
        return payload
    except jwt.ExpiredSignatureError:
        print("  [ERROR] Token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"  [ERROR] Invalid token: {e}")
        return None

def revoke_jwt_token(token: str):
    """
    Simulates revoking a token by adding it to a blacklist.
    In a real system, you'd revoke by JTI (JWT ID) for efficiency and flexibility.
    For this demo, we're blacklisting the full token string.
    """
    if token not in token_blacklist:
        token_blacklist.add(token)
        print(f"  [ACTION] Token added to blacklist (revoked).")
    else:
        print(f"  [INFO] Token already blacklisted.")

def access_protected_resource(token: str, resource_name: str):
    """
    Simulates accessing a protected resource using a JWT token.
    """
    print(f"\n--- Attempting to access '{resource_name}' ---")
    payload = verify_jwt_token(token)
    if payload:
        print(f"  [SUCCESS] User {payload['user_id']} accessed '{resource_name}'.")
    else:
        print(f"  [FAILURE] Access to '{resource_name}' denied.")

# --- Main Demonstration ---
if __name__ == "__main__":
    user_id = 123
    long_lived_token_seconds = 7 * 24 * 60 * 60 # 7 days in seconds
    short_lived_token_seconds = 5

    print(f"--- Scenario 1: Long-lived JWT ({long_lived_token_seconds / (24*60*60):.0f} days) and Revocation ---")

    # 1. User logs in and gets a long-lived token
    print(f"\n[STEP 1] User {user_id} logs in, receives a {long_lived_token_seconds / (24*60*60):.0f}-day JWT.")
    user_token_7day = create_jwt_token(user_id, long_lived_token_seconds)
    print(f"  Generated Token: {user_token_7day[:60]}...")

    # 2. User successfully accesses a resource
    access_protected_resource(user_token_7day, "User Profile (initial access)")

    # 3. Simulate token theft: an attacker gets a copy of the token
    stolen_token = user_token_7day
    print(f"\n[STEP 3] ATTACKER STEALS THE TOKEN: {stolen_token[:60]}...")

    # 4. User "logs out" or changes password, which should invalidate their session
    print(f"\n[STEP 4] User {user_id} logs out/changes password. Server revokes their token.")
    revoke_jwt_token(user_token_7day)

    # 5. Attacker tries to use the stolen token AFTER the user has logged out
    print(f"\n[STEP 5] Attacker attempts to use the stolen token AFTER revocation.")
    access_protected_resource(stolen_token, "Confidential Data (attacker attempt)")
    # Inline comment: This demonstrates how server-side revocation (blacklist) prevents a stolen token from being used,
    # even if its original expiration time is far in the future (e.g., 7 days).
    # Without this mechanism, the stolen token would grant access for the full 7 days.

    print("\n--- Scenario 2: Short-lived JWT (5 seconds) and Automatic Expiration ---")

    # 1. Create a short-lived token
    print(f"\n[STEP 1] User {user_id} logs in, receives a {short_lived_token_seconds}-second JWT.")
    user_token_short = create_jwt_token(user_id, short_lived_token_seconds)
    print(f"  Generated Token: {user_token_short[:60]}...")

    # 2. User successfully accesses a resource
    access_protected_resource(user_token_short, "Temporary Resource (initial access)")

    # 3. Wait for the token to expire
    print(f"\n[STEP 3] Waiting for {short_lived_token_seconds} seconds for the token to expire...")
    time.sleep(short_lived_token_seconds + 1) # Wait a bit longer to ensure expiration

    # 4. User tries to access the resource again with the expired token
    print(f"\n[STEP 4] User attempts to access resource with the now EXPIRED token.")
    access_protected_resource(user_token_short, "Temporary Resource (after expiration)")
    # Inline comment: This shows how JWTs automatically become invalid after their 'exp' claim is passed.
    # Shorter expiration times reduce the window of opportunity for stolen tokens.

    print("\n--- Demonstration Complete ---")
