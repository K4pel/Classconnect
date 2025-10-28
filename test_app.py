import sys
import os
sys.path.append(os.path.dirname(__file__))

def test_app():
    try:
        from app import app
        print("App imported successfully")
        
        with app.app_context():
            from app import admin_exists
            result = admin_exists()
            print(f"Admin exists: {result}")
            
            # Test index route
            with app.test_client() as client:
                response = client.get('/')
                print(f"Index route status code: {response.status_code}")
                print(f"Index route data length: {len(response.data)}")
                
        return True
    except Exception as e:
        print(f"App test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_app()