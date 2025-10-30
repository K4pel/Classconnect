# Secret Admin Signup

## Overview
This document explains how to use the secret admin signup feature in ClassConnect.

## Accessing the Secret Admin Signup Page

The secret admin signup page can be accessed at:
```
/admin/signup/secret-7d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e
```

This is a hidden URL that is not linked anywhere in the application for security purposes.

## Creating an Admin Account

1. Navigate to the secret signup URL
2. Enter a username for the admin account
3. Enter a password (must be at least 12 characters for security)
4. Click "Create Admin Account"
5. You will be redirected to the login page

## Security Notes

- This URL should be kept secret and only shared with trusted administrators
- After creating an admin account, consider removing this route from the application for additional security
- Always use strong passwords for admin accounts
- The first admin account should change their password after initial login

## Removing the Secret Signup Route

For production deployments, it's recommended to remove this route entirely:
1. Delete the `secret_admin_signup()` function in `app.py`
2. Remove the route decorator above it
3. Delete the `templates/secret_admin_signup.html` file

This will completely remove the ability to create new admin accounts through this method.