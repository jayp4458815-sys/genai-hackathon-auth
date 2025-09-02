from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import hashlib
import sqlite3
import re
from datetime import datetime, timedelta

app = Flask(__name__)

# --- Configuration ---
app.secret_key = 'your-super-secret-key-for-the-hackathon'
DB_NAME = "users.db"
LOCKOUT_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# --- Database Setup ---
def init_db():
    """Initializes the database and creates the users table with new fields."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Updated table with full_name, email, and lockout fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            last_failed_attempt TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# --- Helper Functions ---
def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_strong(password):
    """Checks if password is at least 8 chars with letters and numbers."""
    if len(password) < 8:
        return False
    if not re.search("[a-zA-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    return True

def is_valid_email(email):
    """Performs a basic check for email format."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# --- Routes ---
@app.route('/')
def index():
    """Renders the main HTML page."""
    if 'email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register_user():
    """Handles new user registration with enhanced validation."""
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    # --- Validation ---
    if not all([full_name, email, password, confirm_password]):
        return jsonify({'status': 'error', 'message': 'All fields are required.'}), 400
    if not is_valid_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format.'}), 400
    if password != confirm_password:
        return jsonify({'status': 'error', 'message': 'Passwords do not match.'}), 400
    if not is_password_strong(password):
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long and contain letters and numbers.'}), 400

    hashed_pwd = hash_password(password)

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)", (full_name, email, hashed_pwd))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'User registered successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'An account with this email already exists.'}), 409
    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({'status': 'error', 'message': 'An internal error occurred.'}), 500

@app.route('/login', methods=['POST'])
def login_user():
    """Handles user login with account lockout logic."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password are required.'}), 400

    conn = sqlite3.connect(DB_NAME, detect_types=sqlite3.PARSE_DECLTYPES)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, failed_attempts, last_failed_attempt FROM users WHERE email = ?", (email,))
    user_record = cursor.fetchone()

    if user_record:
        user_id, stored_hash, failed_attempts, last_failed = user_record

        # --- Account Lockout Check ---
        if failed_attempts >= LOCKOUT_ATTEMPTS and last_failed:
            lockout_end_time = last_failed + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            if datetime.now() < lockout_end_time:
                remaining_time = round((lockout_end_time - datetime.now()).total_seconds() / 60)
                return jsonify({'status': 'error', 'message': f'Account locked. Please try again in {remaining_time} minutes.'}), 403

        hashed_pwd_attempt = hash_password(password)
        if stored_hash == hashed_pwd_attempt:
            # --- Successful Login: Reset failed attempts ---
            cursor.execute("UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            session['email'] = email
            return jsonify({'status': 'success', 'redirect': url_for('dashboard')}), 200
        else:
            # --- Failed Login: Increment failed attempts ---
            cursor.execute("UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_attempt = ? WHERE id = ?", (datetime.now(), user_id))
            conn.commit()
            conn.close()
            return jsonify({'status': 'error', 'message': 'Invalid email or password.'}), 401
    else:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid email or password.'}), 401

@app.route('/dashboard')
def dashboard():
    """Displays the user's dashboard, showing their full name."""
    if 'email' in session:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT full_name FROM users WHERE email = ?", (session['email'],))
        user = cursor.fetchone()
        conn.close()
        if user:
            full_name = user[0]
            return render_template('dashboard.html', full_name=full_name)
    
    return redirect(url_for('index')) # Redirect if not in session or user not found

@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db() # Initialize the database when the app starts
    app.run(debug=True)

