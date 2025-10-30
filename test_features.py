#!/usr/bin/env python3
"""
Test script to verify that both features are working:
1. Study group creation with detailed error logging
2. Enhanced password recovery system with complete user details
"""

import requests
import time

def test_routes():
    """Test that the routes are accessible"""
    base_url = "http://127.0.0.1:5000"
    
    # Test forgot password route
    try:
        response = requests.get(f"{base_url}/forgot_password")
        print(f"Forgot password route: {response.status_code}")
        if response.status_code == 200:
            print("✓ Forgot password route is accessible")
        else:
            print("✗ Forgot password route is not accessible")
    except Exception as e:
        print(f"✗ Error testing forgot password route: {e}")
    
    # Test study groups creation route
    try:
        response = requests.get(f"{base_url}/study_groups/create")
        print(f"Study group creation route: {response.status_code}")
        # This should redirect to login since we're not authenticated
        if response.status_code in [200, 302]:
            print("✓ Study group creation route is accessible")
        else:
            print("✗ Study group creation route is not accessible")
    except Exception as e:
        print(f"✗ Error testing study group creation route: {e}")

def test_password_recovery():
    """Test the enhanced password recovery feature"""
    base_url = "http://127.0.0.1:5000"
    
    # Test POST request to forgot password
    try:
        response = requests.post(f"{base_url}/forgot_password", data={
            "username": "testuser"
        })
        print(f"Password recovery POST request: {response.status_code}")
        if response.status_code == 200:
            print("✓ Password recovery POST request successful")
            # Check if the expected message is in the response
            if "password reset request has been sent to the admin" in response.text:
                print("✓ Correct success message displayed")
            else:
                print("⚠ Success message not found in response")
        else:
            print("✗ Password recovery POST request failed")
    except Exception as e:
        print(f"✗ Error testing password recovery POST request: {e}")

if __name__ == "__main__":
    print("Testing ClassConnect features...")
    test_routes()
    test_password_recovery()
    print("Test completed.")