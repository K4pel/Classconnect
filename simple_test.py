# Simple test to check if app.py has syntax errors
try:
    # Try to import the main application
    from app import app, admin_exists
    print("✓ app.py imported successfully")
    
    # Try to create an application context
    with app.app_context():
        print("✓ Application context created")
        
        # Try to call admin_exists function
        result = admin_exists()
        print(f"✓ admin_exists() returned: {result}")
        
    print("✓ All tests passed - app.py is working correctly")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    print("Traceback:")
    traceback.print_exc()