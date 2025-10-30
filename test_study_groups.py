import sqlite3
from datetime import datetime, timezone

# Test study group functionality
def test_study_groups():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Test creating a study group
        print("Testing study group creation...")
        
        # Insert a test study group
        cursor.execute('''
            INSERT INTO study_groups (name, description, created_by, created_at) 
            VALUES (?, ?, ?, ?)
        ''', ('Test Group', 'A test study group', 2, datetime.now(timezone.utc).isoformat()))
        
        group_id = cursor.lastrowid
        print(f"Created study group with ID: {group_id}")
        
        # Insert a test member
        cursor.execute('''
            INSERT INTO study_group_members (group_id, user_id, role, joined_at) 
            VALUES (?, ?, ?, ?)
        ''', (group_id, 2, 'admin', datetime.now(timezone.utc).isoformat()))
        
        print("Added user as admin member")
        
        # Insert a test message
        cursor.execute('''
            INSERT INTO study_group_messages (group_id, user_id, username, content, timestamp) 
            VALUES (?, ?, ?, ?, ?)
        ''', (group_id, 2, 'testuser', 'Hello, this is a test message!', datetime.now(timezone.utc).isoformat()))
        
        message_id = cursor.lastrowid
        print(f"Created test message with ID: {message_id}")
        
        conn.commit()
        print("All operations completed successfully!")
        
        # Test querying the data
        print("\nTesting data retrieval...")
        
        # Get the study group
        cursor.execute('SELECT * FROM study_groups WHERE id = ?', (group_id,))
        group = cursor.fetchone()
        if group:
            print(f"Group: {group['name']} - {group['description']}")
        
        # Get the members
        cursor.execute('SELECT * FROM study_group_members WHERE group_id = ?', (group_id,))
        members = cursor.fetchall()
        print(f"Members count: {len(members)}")
        for member in members:
            print(f"  - User {member['user_id']} as {member['role']}")
        
        # Get the messages
        cursor.execute('SELECT * FROM study_group_messages WHERE group_id = ?', (group_id,))
        messages = cursor.fetchall()
        print(f"Messages count: {len(messages)}")
        for message in messages:
            print(f"  - {message['username']}: {message['content']}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
    finally:
        # Clean up test data
        try:
            cursor.execute('DELETE FROM study_group_messages WHERE group_id = ?', (group_id,))
            cursor.execute('DELETE FROM study_group_members WHERE group_id = ?', (group_id,))
            cursor.execute('DELETE FROM study_groups WHERE id = ?', (group_id,))
            conn.commit()
            print("\nCleaned up test data")
        except Exception as e:
            print(f"Error cleaning up: {e}")
        conn.close()

if __name__ == "__main__":
    test_study_groups()