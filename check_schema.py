import sqlite3

# Check database schema
def check_schema():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Check study_groups table
    print("study_groups table:")
    cursor.execute('PRAGMA table_info(study_groups)')
    for col in cursor.fetchall():
        print(f"  {col[1]} ({col[2]})")
    
    print("\nstudy_group_members table:")
    cursor.execute('PRAGMA table_info(study_group_members)')
    for col in cursor.fetchall():
        print(f"  {col[1]} ({col[2]})")
    
    print("\nstudy_group_messages table:")
    cursor.execute('PRAGMA table_info(study_group_messages)')
    for col in cursor.fetchall():
        print(f"  {col[1]} ({col[2]})")
    
    conn.close()

if __name__ == "__main__":
    check_schema()