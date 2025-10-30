from app import app, get_db

def update_study_groups_schema():
    """Add image_url column to study_groups table if it doesn't exist"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        
        try:
            # Check if image_url column exists
            cur.execute("PRAGMA table_info(study_groups)")
            columns = [column[1] for column in cur.fetchall()]
            
            if 'image_url' not in columns:
                # Add image_url column to study_groups table
                cur.execute("ALTER TABLE study_groups ADD COLUMN image_url TEXT DEFAULT ''")
                print("Added image_url column to study_groups table")
            else:
                print("image_url column already exists in study_groups table")
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            print(f"Error updating study groups schema: {e}")

if __name__ == "__main__":
    update_study_groups_schema()