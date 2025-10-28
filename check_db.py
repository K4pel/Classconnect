import sqlite3

# Check database structure
def check_database():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print("Tables in database:")
    for table in tables:
        print(f"  - {table[0]}")
    
    # Check if users table exists and has data
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"\nNumber of users: {user_count}")
        
        if user_count > 0:
            cursor.execute("SELECT id, username, is_admin, approved FROM users LIMIT 5")
            users = cursor.fetchall()
            print("\nSample users:")
            for user in users:
                print(f"  ID: {user[0]}, Username: {user[1]}, Admin: {user[2]}, Approved: {user[3]}")
    except Exception as e:
        print(f"Error accessing users table: {e}")
    
    # Check if messages table exists
    try:
        cursor.execute("SELECT COUNT(*) FROM messages")
        message_count = cursor.fetchone()[0]
        print(f"\nNumber of messages: {message_count}")
    except Exception as e:
        print(f"Error accessing messages table: {e}")
    
    # Check if meta table exists
    try:
        cursor.execute("SELECT COUNT(*) FROM meta")
        meta_count = cursor.fetchone()[0]
        print(f"\nNumber of meta entries: {meta_count}")
        
        if meta_count > 0:
            cursor.execute("SELECT key, value FROM meta")
            meta_entries = cursor.fetchall()
            print("\nMeta entries:")
            for entry in meta_entries:
                print(f"  {entry[0]}: {entry[1]}")
    except Exception as e:
        print(f"Error accessing meta table: {e}")
    
    conn.close()

if __name__ == "__main__":
    check_database()