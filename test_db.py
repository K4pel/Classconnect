import sqlite3
import os

# Test database connection and initialization
def test_database():
    db_path = os.path.join(os.path.dirname(__file__), 'app.db')
    print(f"Database path: {db_path}")
    
    try:
        # Test connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("Tables in database:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # Test users table
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"Number of users: {user_count}")
        
        conn.close()
        print("Database test successful!")
        return True
        
    except Exception as e:
        print(f"Database test failed: {e}")
        return False

if __name__ == "__main__":
    test_database()