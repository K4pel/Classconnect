from app import app, get_db

def reset_study_groups():
    """Reset study groups by clearing all data from study group tables"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        
        try:
            # Delete all study group messages
            cur.execute('DELETE FROM study_group_messages')
            
            # Delete all study group members
            cur.execute('DELETE FROM study_group_members')
            
            # Delete all study groups
            cur.execute('DELETE FROM study_groups')
            
            db.commit()
            print("All study group data has been cleared successfully!")
            
        except Exception as e:
            db.rollback()
            print(f"Error resetting study groups: {e}")

if __name__ == "__main__":
    reset_study_groups()