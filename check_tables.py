import sqlite3

# Check database schema
def check_tables():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    print("Current tables in the database:")
    for table in tables:
        print(f"  - {table[0]}")
    
    conn.close()

if __name__ == "__main__":
    check_tables()