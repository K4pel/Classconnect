import sqlite3

# Check database indexes
def check_indexes():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Check indexes for study_group_messages table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='study_group_messages'")
    indexes = cursor.fetchall()
    print("Indexes on study_group_messages table:")
    for index in indexes:
        print(f"  - {index[0]}")
    
    # Check indexes for study_groups table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='study_groups'")
    indexes = cursor.fetchall()
    print("\nIndexes on study_groups table:")
    for index in indexes:
        print(f"  - {index[0]}")
    
    # Check indexes for study_group_members table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='study_group_members'")
    indexes = cursor.fetchall()
    print("\nIndexes on study_group_members table:")
    for index in indexes:
        print(f"  - {index[0]}")
    
    conn.close()

if __name__ == "__main__":
    check_indexes()