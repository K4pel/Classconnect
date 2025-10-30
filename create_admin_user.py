from app import app, get_db
from werkzeug.security import generate_password_hash

def create_admin_user():
    """Create an admin user with username Admin1 and password Admin123"""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        
        username = "Admin1"
        password = "Admin123"
        password_hash = generate_password_hash(password)
        
        try:
            cur.execute('''
                INSERT INTO users (username, password_hash, is_admin, approved) 
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, 1, 1))
            
            db.commit()
            print(f"Admin user '{username}' created successfully!")
            print("IMPORTANT: Remember to change the default password after first login!")
            
        except Exception as e:
            db.rollback()
            print(f"Error creating admin user: {e}")

if __name__ == "__main__":
    create_admin_user()