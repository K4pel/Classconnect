import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Test password hashing and verification
def test_password():
    # Test password
    password = "test1234"
    
    # Hash the password
    hashed = generate_password_hash(password)
    print(f"Original password: {password}")
    print(f"Hashed password: {hashed}")
    
    # Verify the password
    result = check_password_hash(hashed, password)
    print(f"Password verification result: {result}")
    
    # Test with wrong password
    wrong_result = check_password_hash(hashed, "wrongpassword")
    print(f"Wrong password verification result: {wrong_result}")

if __name__ == "__main__":
    test_password()