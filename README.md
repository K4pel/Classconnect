ClassConnect - Mini/Heavy Chat for L5 Software Development

This is a minimal Flask app for classroom chat with admin approval.

Assumptions:
- Class code prefix is "L5". Usernames starting with "L5" are auto-approved. Others require admin approval.
- A default admin account is created on first run: username `admin`, password `adminpass`.

How to run (Windows PowerShell):

1. Create virtual env and activate:
   python -m venv .venv; .\.venv\Scripts\Activate.ps1
2. Install deps:
   pip install -r requirements.txt
3. Run the app (development):
   python app.py

Notes on async drivers:
- This project supports Socket.IO for real-time heavy chat. On Windows and some Python versions, `eventlet` can cause import/ssl issues (AttributeError: 'ssl' has no attribute 'wrap_socket').
- For development the app is configured to use the `threading` async mode which works without extra packages. If you want high-performance production use, install and configure `eventlet` or `gevent` and adjust `app.py` accordingly.

Open http://127.0.0.1:5000 in your browser.

Notes:
- Pages: /, /register, /login, /dashboard, /admin, /chat/mini, /chat/heavy
- Admin can approve pending users on the /admin page.
- Improvements: use WebSockets for real-time chat, stronger secret key & env configuration, unit tests.
 - Heavy chat now uses Socket.IO (real-time). Requirements include `flask-socketio` and `eventlet`.
 - To override defaults, set environment variables `SECRET_KEY` and `CLASS_CODE` before running.
