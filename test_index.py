import sys
import os
sys.path.append(os.path.dirname(__file__))

# Test the index route
def test_index():
    try:
        from app import app, admin_exists
        with app.app_context():
            # Test admin_exists function
            result = admin_exists()
            print(f"Admin exists: {result}")
            
            # Test database connection
            from app import get_db
            db = get_db()
            print("Database connection successful")
            
            # Test CLASS_CODE
            from app import CLASS_CODE
            print(f"Class code: {CLASS_CODE}")
            
        print("Index route test successful!")
        return True
        
    except Exception as e:
        print(f"Index route test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_index()