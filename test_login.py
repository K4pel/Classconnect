import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash

# Test login functionality
def test_login(username, password):
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        print(f"Login successful for user: {username}")
        print(f"User ID: {user['id']}")
        print(f"Approved: {user['approved']}")
        print(f"Is Admin: {user['is_admin']}")
        return True
    else:
        print(f"Login failed for user: {username}")
        if user:
            print("Password incorrect")
        else:
            print("User not found")
        return False

# Test with existing users
print("Testing login functionality:")
print("=" * 40)

# Test with user 'L5bruno'
test_login('L5bruno', 'testpassword')  # You'll need to use the actual password

# Test with user 'admin'
test_login('admin', 'adminpassword')  # You'll need to use the actual password

# Test with non-existent user
test_login('nonexistent', 'password')