from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify, flash
from werkzeug.utils import secure_filename
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from datetime import datetime, timezone, timedelta
import os
import secrets
import uuid
from functools import wraps
from flask_socketio import SocketIO, join_room, leave_room
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
DB_PATH = os.path.join(os.path.dirname(__file__), os.environ.get('DATABASE_PATH', 'app.db'))
CLASS_CODE = os.environ.get('CLASS_CODE', 'L5')

# Use a more secure secret key - in production, this should come from environment variables
DEFAULT_SECRET = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

app = Flask(__name__)
app.config['SECRET_KEY'] = DEFAULT_SECRET
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')

# SocketIO configuration - fixed async_mode
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading', logger=True, engineio_logger=True)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions for avatars
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Extended allowed file extensions for file sharing
ALLOWED_FILE_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg',
    # Videos
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm',
    # Audio
    'mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac',
    # Documents
    'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt',
    # Spreadsheets
    'xls', 'xlsx', 'csv',
    # Presentations
    'ppt', 'pptx',
    # Other
    'zip', 'rar', '7z'
}

def get_db():
    """Get database connection with row factory"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with required tables"""
    db = get_db()
    cur = db.cursor()
    
    # Users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0 CHECK(is_admin IN (0, 1)),
        approved INTEGER DEFAULT 0 CHECK(approved IN (0, 1)),
        avatar TEXT DEFAULT '',
        last_seen TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Add index on username for faster lookups
    cur.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    
    # Messages table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        recipient_id INTEGER DEFAULT NULL,
        attachment_url TEXT DEFAULT '',
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
    ''')
    
    # Add indexes for better query performance
    cur.execute('CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_messages_recipient_id ON messages(recipient_id)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
    
    # Meta table for system configuration
    cur.execute('''
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    
    # Create initial admin token if not exists
    cur.execute('SELECT value FROM meta WHERE key = "admin_token_hash"')
    if not cur.fetchone():
        admin_token = secrets.token_urlsafe(32)
        cur.execute('INSERT INTO meta (key, value) VALUES (?, ?)', 
                   ('admin_token_hash', generate_password_hash(admin_token)))
        print(f"Initial admin token: {admin_token}")  # Remove this in production
    
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of request"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    """Check if file extension is allowed for avatars"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_file_for_sharing(filename):
    """Check if file extension is allowed for file sharing"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS

def save_avatar(file_storage, user_id):
    """Save avatar file and return web path"""
    if not file_storage or file_storage.filename == '':
        return None
    
    if not allowed_file(file_storage.filename):
        return None
    
    # Generate secure filename
    file_ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"avatar_{user_id}_{secrets.token_hex(8)}.{file_ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file_storage.save(filepath)
        return f'/static/uploads/{filename}'
    except Exception as e:
        logger.error(f"Error saving avatar: {e}")
        return None

def save_attachment(file_storage, user_id):
    """Save attachment file and return web path"""
    if not file_storage or file_storage.filename == '':
        return None
    
    if not allowed_file_for_sharing(file_storage.filename):
        return None
    
    # Generate secure filename
    file_ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"attachment_{user_id}_{secrets.token_hex(8)}.{file_ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file_storage.save(filepath)
        return f'/static/uploads/{filename}'
    except Exception as e:
        logger.error(f"Error saving attachment: {e}")
        return None

def get_user_by_id(user_id):
    """Get user by ID"""
    if not user_id:
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cur.fetchone()

def current_user():
    """Get current logged-in user"""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return get_user_by_id(user_id)

def meta_get(key):
    """Get value from meta table"""
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT value FROM meta WHERE key = ?', (key,))
    result = cur.fetchone()
    return result['value'] if result else None

def meta_set(key, value):
    """Set value in meta table"""
    db = get_db()
    cur = db.cursor()
    cur.execute('REPLACE INTO meta (key, value) VALUES (?, ?)', (key, value))
    db.commit()

def admin_exists():
    """Check if admin user exists"""
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT id FROM users WHERE is_admin = 1 LIMIT 1')
        result = cur.fetchone()
        return result is not None
    except Exception as e:
        logger.error(f"Error in admin_exists: {e}")
        return False

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = current_user()
        if not user:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if not user['is_admin']:
            flash('Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def format_timestamp(timestamp_str):
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - dt
        
        if diff < timedelta(minutes=1):
            return 'Just now'
        elif diff < timedelta(hours=1):
            minutes = int(diff.total_seconds() / 60)
            return f'{minutes}m ago'
        elif diff < timedelta(days=1):
            hours = int(diff.total_seconds() / 3600)
            return f'{hours}h ago'
        elif diff < timedelta(days=7):
            days = diff.days
            return f'{days}d ago'
        else:
            return dt.strftime('%b %d, %Y')
    except Exception as e:
        logger.error(f"Error formatting timestamp: {e}")
        return timestamp_str

# Routes
@app.route('/')
def index():
    """Home page"""
    try:
        return render_template('index.html', 
                             class_code=CLASS_CODE, 
                             admin_missing=not admin_exists())
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        import traceback
        logger.error(traceback.format_exc())
        # Return a simple response if template rendering fails
        return "Welcome to ClassConnect! <a href='/login'>Login</a> | <a href='/register'>Register</a>", 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html', class_code=CLASS_CODE)
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return render_template('register.html', class_code=CLASS_CODE)
        
        if len(password) < 8:  # Increased minimum password length for security
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html', class_code=CLASS_CODE)
        
        # Auto-approve class members
        approved = 1 if username.startswith(CLASS_CODE) else 0
        
        db = get_db()
        cur = db.cursor()
        
        try:
            cur.execute('INSERT INTO users (username, password_hash, approved) VALUES (?, ?, ?)',
                       (username, generate_password_hash(password), approved))
            db.commit()
            
            if approved:
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Registration submitted. Waiting for admin approval.', 'info')
                return render_template('register.html', class_code=CLASS_CODE)
                
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
            return render_template('register.html', class_code=CLASS_CODE)
    
    return render_template('register.html', class_code=CLASS_CODE)

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    """One-time admin creation"""
    if admin_exists():
        flash('Admin account already exists.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        token = request.form.get('token', '').strip()
        
        if not username or not password or not token:
            flash('All fields are required.', 'danger')
            return render_template('create_admin.html')
        
        # Validate token
        saved_token_hash = meta_get('admin_token_hash')
        if not saved_token_hash or not check_password_hash(saved_token_hash, token):
            flash('Invalid or expired admin token.', 'danger')
            return render_template('create_admin.html')
        
        # Check password strength for admin
        if len(password) < 12:
            flash('Admin password must be at least 12 characters long for security.', 'danger')
            return render_template('create_admin.html')
        
        db = get_db()
        cur = db.cursor()
        
        try:
            cur.execute('INSERT INTO users (username, password_hash, is_admin, approved) VALUES (?, ?, ?, ?)',
                       (username, generate_password_hash(password), 1, 1))
            db.commit()
            
            # Clean up token
            meta_set('admin_token_hash', '')
            meta_set('admin_created', '1')
            
            flash('Admin account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
            return render_template('create_admin.html')
    
    return render_template('create_admin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html', class_code=CLASS_CODE)
        
        if not user['approved']:
            flash('Your account is pending admin approval.', 'warning')
            return render_template('login.html', class_code=CLASS_CODE)
        
        # Update last seen
        cur.execute('UPDATE users SET last_seen = ? WHERE id = ?', 
                   (datetime.now(timezone.utc).isoformat(), user['id']))
        db.commit()
        
        # Set session
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        flash(f'Welcome back, {user["username"]}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html', class_code=CLASS_CODE)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = current_user()
    
    # Type check to satisfy linter
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    # Get recent conversations
    db = get_db()
    cur = db.cursor()
    
    # Get conversation partners and last messages
    cur.execute('''
        SELECT DISTINCT 
            CASE 
                WHEN user_id = ? THEN recipient_id 
                ELSE user_id 
            END as partner_id,
            MAX(timestamp) as last_timestamp
        FROM messages 
        WHERE (user_id = ? OR recipient_id = ?) AND recipient_id IS NOT NULL
        GROUP BY partner_id
        ORDER BY last_timestamp DESC
        LIMIT 20
    ''', (user['id'], user['id'], user['id']))
    
    conversations = []
    for row in cur.fetchall():
        if row['partner_id']:  # Ensure it's not None
            partner = get_user_by_id(row['partner_id'])
            if partner:
                # Get last message
                cur.execute('''
                    SELECT content, timestamp 
                    FROM messages 
                    WHERE (user_id = ? AND recipient_id = ?) OR (user_id = ? AND recipient_id = ?)
                    ORDER BY timestamp DESC 
                    LIMIT 1
                ''', (user['id'], partner['id'], partner['id'], user['id']))
                
                last_msg = cur.fetchone()
                
                conversations.append({
                    'other_id': partner['id'],
                    'username': partner['username'],
                    'avatar': partner['avatar'] or '/static/img/default-avatar.png',
                    'last_msg': last_msg['content'] if last_msg else 'No messages yet',
                    'timestamp': format_timestamp(last_msg['timestamp']) if last_msg else 'Never'
                })
    
    # Get user statistics
    cur.execute('SELECT COUNT(*) as total FROM messages WHERE user_id = ? OR recipient_id = ?', 
               (user['id'], user['id']))
    total_messages = cur.fetchone()['total']
    
    return render_template('dashboard.html', 
                         user=user, 
                         convs=conversations,
                         total_messages=total_messages)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    user = current_user()
    
    # Type check to satisfy linter
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_username = request.form.get('new_username', '').strip()
        new_password = request.form.get('new_password', '').strip()
        avatar = request.files.get('avatar')
        
        db = get_db()
        cur = db.cursor()
        
        # Verify current password before making changes
        if new_username or new_password or avatar:
            if not current_password:
                flash('Current password is required to make changes.', 'danger')
                return render_template('profile.html', user=user)
            
            if not check_password_hash(user['password_hash'], current_password):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile.html', user=user)
        
        updates = []
        
        # Update username if provided and different
        if new_username and new_username != user['username']:
            # Check if username is already taken
            cur.execute('SELECT id FROM users WHERE username = ? AND id != ?', 
                       (new_username, user['id']))
            if cur.fetchone():
                flash('Username is already taken. Please choose another one.', 'danger')
                return render_template('profile.html', user=user)
            
            cur.execute('UPDATE users SET username = ? WHERE id = ?', 
                       (new_username, user['id']))
            updates.append('username')
            # Update session username
            session['username'] = new_username
        
        if new_password:
            if len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'danger')
                return render_template('profile.html', user=user)
            else:
                cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                           (generate_password_hash(new_password), user['id']))
                updates.append('password')
        
        if avatar and avatar.filename:
            avatar_path = save_avatar(avatar, user['id'])
            if avatar_path:
                cur.execute('UPDATE users SET avatar = ? WHERE id = ?', 
                           (avatar_path, user['id']))
                updates.append('avatar')
        
        db.commit()
        
        if updates:
            flash('Profile updated successfully!', 'success')
            # Refresh user data
            user = get_user_by_id(user['id'])
        elif new_username or new_password or avatar:
            flash('No changes were made due to validation errors.', 'info')
        else:
            flash('No changes were made.', 'info')
    
    return render_template('profile.html', user=user)

@app.route('/users')
@login_required
def users():
    """List of approved users"""
    current_user_data = current_user()
    
    # Type check to satisfy linter
    if not current_user_data:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        SELECT id, username, avatar, last_seen 
        FROM users 
        WHERE approved = 1 AND id != ?
        ORDER BY username
    ''', (current_user_data['id'],))
    
    users_list = []
    for row in cur.fetchall():
        users_list.append({
            'id': row['id'],
            'username': row['username'],
            'avatar': row['avatar'] or '/static/img/default-avatar.png',
            'last_seen': format_timestamp(row['last_seen']) if row['last_seen'] else 'Never'
        })
    
    return render_template('users.html', users=users_list)

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin panel"""
    db = get_db()
    cur = db.cursor()
    
    # Get pending users
    cur.execute('SELECT * FROM users WHERE approved = 0 ORDER BY id DESC')
    pending = cur.fetchall()
    
    # Get recent messages
    cur.execute('''
        SELECT m.*, u.avatar 
        FROM messages m 
        LEFT JOIN users u ON m.user_id = u.id 
        ORDER BY m.id DESC 
        LIMIT 50
    ''')
    messages = cur.fetchall()
    
    # Get statistics
    cur.execute('SELECT COUNT(*) as count FROM users')
    total_users = cur.fetchone()['count']
    
    cur.execute('SELECT COUNT(*) as count FROM users WHERE approved = 1')
    approved_users = cur.fetchone()['count']
    
    cur.execute('SELECT COUNT(*) as count FROM messages')
    total_messages = cur.fetchone()['count']
    
    # Format messages for display
    formatted_messages = []
    for msg in messages:
        formatted_messages.append({
            'id': msg['id'],
            'username': msg['username'],
            'content': msg['content'],
            'timestamp': format_timestamp(msg['timestamp']),
            'avatar': msg['avatar'] or '/static/img/default-avatar.png'
        })
    
    return render_template('admin.html', 
                         pending=pending,
                         messages=formatted_messages,
                         total_users=total_users,
                         approved_users=approved_users,
                         total_messages=total_messages)

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@admin_required
def admin_approve(user_id):
    """Approve pending user"""
    db = get_db()
    cur = db.cursor()
    cur.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
    db.commit()
    flash('User approved successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/reject/<int:user_id>', methods=['POST'])
@admin_required
def admin_reject(user_id):
    """Reject pending user"""
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User rejected successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@admin_required
def admin_delete_message(message_id):
    """Delete message"""
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    db.commit()
    flash('Message deleted successfully.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/chat/<int:other_id>')
@login_required
def chat_with(other_id):
    """Private chat with another user"""
    me = current_user()
    
    # Type check to satisfy linter
    if not me:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    # Ensure the other user exists and is approved
    other_user = get_user_by_id(other_id)
    if not other_user or not other_user['approved']:
        flash('User not available.', 'danger')
        return redirect(url_for('users'))
    
    # Create deterministic room name
    user_ids = sorted([me['id'], other_user['id']])
    room = f'pm_{user_ids[0]}_{user_ids[1]}'
    
    return render_template('chat.html', 
                         me=me, 
                         other=other_user, 
                         room=room)

@app.route('/messages')
@login_required
def get_messages():
    """Get messages (with optional user filter)"""
    current_user_data = current_user()
    
    # Type check to satisfy linter
    if not current_user_data:
        return jsonify({'error': 'User not found'}), 401
    
    other_id = request.args.get('with')
    db = get_db()
    cur = db.cursor()
    
    if other_id:
        try:
            other_id = int(other_id)
            me = current_user_data
            
            # Get private messages between two users
            cur.execute('''
                SELECT m.*, u.avatar 
                FROM messages m 
                LEFT JOIN users u ON m.user_id = u.id 
                WHERE (m.user_id = ? AND m.recipient_id = ?) OR (m.user_id = ? AND m.recipient_id = ?)
                ORDER BY m.timestamp ASC
            ''', (me['id'], other_id, other_id, me['id']))
            
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid user ID'}), 400
    else:
        # Get all messages (for public chats)
        cur.execute('''
            SELECT m.*, u.avatar 
            FROM messages m 
            LEFT JOIN users u ON m.user_id = u.id 
            WHERE m.recipient_id IS NULL
            ORDER BY m.timestamp DESC 
            LIMIT 100
        ''')
    
    messages = []
    for row in cur.fetchall():
        messages.append({
            'id': row['id'],
            'username': row['username'],
            'content': row['content'],
            'timestamp': format_timestamp(row['timestamp']),
            'user_id': row['user_id'],
            'recipient_id': row['recipient_id'],
            'avatar': row['avatar'] or '/static/img/default-avatar.png'
        })
    
    return jsonify(messages)

@app.route('/upload_attachment', methods=['POST'])
@login_required
def upload_attachment():
    """Handle file attachment upload"""
    user = current_user()
    
    # Type check to satisfy linter
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file_for_sharing(file.filename):
        attachment_url = save_attachment(file, user['id'])
        if attachment_url:
            return jsonify({'url': attachment_url}), 200
        else:
            return jsonify({'error': 'Failed to save file'}), 500
    else:
        return jsonify({'error': 'File type not allowed'}), 400

# SocketIO Handlers - FIXED VERSION
@socketio.on('connect')
def handle_connect():
    """Handle user connection"""
    logger.info("Client connected")
    user = current_user()
    if user:
        try:
            # Update last seen
            db = get_db()
            cur = db.cursor()
            cur.execute('UPDATE users SET last_seen = ? WHERE id = ?', 
                       (datetime.now(timezone.utc).isoformat(), user['id']))
            db.commit()
            
            # Emit user online status - FIXED: removed broadcast parameter
            socketio.emit('user_online', {
                'user_id': user['id'],
                'username': user['username']
            })
            logger.info(f"User {user['username']} connected")
        except Exception as e:
            logger.error(f"Error in handle_connect: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnection"""
    logger.info("Client disconnected")
    user = current_user()
    if user:
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute('UPDATE users SET last_seen = ? WHERE id = ?', 
                       (datetime.now(timezone.utc).isoformat(), user['id']))
            db.commit()
            
            # Emit user offline status
            socketio.emit('user_offline', {
                'user_id': user['id'],
                'username': user['username']
            })
            logger.info(f"User {user['username']} disconnected")
        except Exception as e:
            logger.error(f"Error in handle_disconnect: {e}")

@socketio.on('join')
def handle_join(data):
    """Join a chat room"""
    room = data.get('room')
    user = current_user()
    if room and user:
        try:
            join_room(room)
            logger.info(f"User {user['username']} joined room {room}")
            
            # Notify others in the room
            socketio.emit('user_joined', {
                'username': user['username'],
                'room': room
            }, to=room)
        except Exception as e:
            logger.error(f"Error in handle_join: {e}")

@socketio.on('leave')
def handle_leave(data):
    """Leave a chat room"""
    room = data.get('room')
    user = current_user()
    if room and user:
        try:
            leave_room(room)
            logger.info(f"User {user['username']} left room {room}")
            
            # Notify others in the room
            socketio.emit('user_left', {
                'username': user['username'],
                'room': room
            }, to=room)
        except Exception as e:
            logger.error(f"Error in handle_leave: {e}")

@socketio.on('send_message')
def handle_send_message(data):
    """Handle new message"""
    user = current_user()
    if not user or not user['approved']:
        return
    
    content = (data.get('content') or '').strip()
    room = data.get('room')
    recipient_id = data.get('recipient_id')
    attachment_url = data.get('attachment_url', '')
    
    # Either content or attachment must be present
    if not content and not attachment_url:
        return
    
    # Sanitize content to prevent XSS
    import html
    content = html.escape(content) if content else ''
    
    try:
        # Save message to database
        db = get_db()
        cur = db.cursor()
        timestamp = datetime.now(timezone.utc).isoformat()
        
        cur.execute('''
            INSERT INTO messages (user_id, username, content, timestamp, recipient_id, attachment_url) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user['id'], user['username'], content, timestamp, recipient_id, attachment_url))
        
        db.commit()
        
        # Prepare message for broadcasting
        message_data = {
            'id': cur.lastrowid,
            'username': user['username'],
            'content': content,
            'timestamp': format_timestamp(timestamp),
            'user_id': user['id'],
            'recipient_id': recipient_id,
            'avatar': user['avatar'] or '/static/img/default-avatar.png',
            'attachment_url': attachment_url
        }
        
        # Broadcast message - FIXED: proper room broadcasting
        if room:
            socketio.emit('new_message', message_data, to=room)
        else:
            socketio.emit('new_message', message_data)
            
        logger.info(f"Message sent by {user['username']} in room {room}")
        
    except Exception as e:
        logger.error(f"Error in handle_send_message: {e}")

@socketio.on('upload_attachment')
def handle_upload_attachment(data):
    """Handle file attachment upload"""
    user = current_user()
    if not user or not user['approved']:
        return {'error': 'Unauthorized'}
    
    # This handler will be called from the client-side with file data
    # The actual file upload will be handled through a separate HTTP endpoint
    return {'status': 'ready'}

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db = get_db()
    db.rollback()
    error_id = str(uuid.uuid4())
    logger.error(f"500 error [{error_id}]: {error}", exc_info=True)
    return render_template('500.html', request_id=error_id), 500

@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    
    # Handle non-HTTP exceptions
    db = get_db()
    db.rollback()
    error_id = str(uuid.uuid4())
    logger.error(f"Unhandled exception [{error_id}]: {e}", exc_info=True)
    return render_template('500.html', request_id=error_id), 500

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        init_db()
    
    # Run application
    print("Starting ClassConnect server...")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)