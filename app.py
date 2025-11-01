from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, send_file, flash, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_session import Session
from werkzeug.utils import secure_filename
from signature_utils import sign_document as sign_document_util
import os
import io
import pyotp
import qrcode
from datetime import datetime, timedelta
import traceback
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import re
import shutil

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github

from crypto_utils import encrypt_file, decrypt_file, hash_file
from error_handlers import init_error_handlers
from mri_analysis import analyze_mri_image
from PIL import Image, ImageDraw, ImageFont
import io
import zipfile
try:
    from PyPDF2 import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except Exception:
    PdfReader = None
    PdfWriter = None
    canvas = None
    letter = None

# Add imports for cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Session Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'securedocs-secret-key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessions last 7 days
app.config['SESSION_COOKIE_SECURE'] = False  # Set to False for local development
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session on each request

# Initialize Session
Session(app)

# Initialize error handlers
init_error_handlers(app)

# Configure logging to a file
log_file_path = os.path.join(app.root_path, 'application.log')
file_handler = RotatingFileHandler(log_file_path, maxBytes=10240, backupCount=10, delay=True)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)

# Remove any existing handlers to prevent duplicates
for handler in app.logger.handlers[:]:
    app.logger.removeHandler(handler)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Add a stream handler for console output
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
console_handler.setLevel(logging.INFO)
app.logger.addHandler(console_handler)

# Disable werkzeug's default logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# MySQL config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'securedocs_db')

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# Create necessary directories
os.makedirs(os.path.join(os.getcwd(), 'flask_session'), exist_ok=True)
os.makedirs(os.getenv('UPLOAD_FOLDER', 'uploads'), exist_ok=True)

# File upload config
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# OAuth Blueprints
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    redirect_to="google_login",
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    storage=None  # Use default storage
)
app.register_blueprint(google_bp, url_prefix="/login")

github_bp = make_github_blueprint(
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    redirect_to="github_login",
    scope="user:email",
    storage=None  # Use default storage
)
app.register_blueprint(github_bp, url_prefix="/login")

# Add this after the blueprint registration
@app.after_request
def after_request(response):
    """Run after each request to handle session cleanup"""
    if hasattr(google, 'session'):
        try:
            google.session = None
        except:
            pass
    if hasattr(github, 'session'):
        try:
            github.session = None
        except:
            pass
    return response

def is_logged_in():
    """Check if user is logged in and session is valid"""
    return 'username' in session and 'role' in session

def login_required(f):
    """Decorator to require login for routes"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for routes"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in() or session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.before_request
def before_request():
    """Run before each request to check session validity"""
    # If the logging out flag is set, briefly bypass the full session check
    if session.pop('_logging_out', False):
        # This request is likely part of the logout sequence or immediate redirect
        return # Allow the request to proceed without full session check

    # List of endpoints that should NOT trigger the session check
    # These are typically login, registration, and OAuth callback endpoints
    allowed_endpoints = [
        'login', 'register', 'qr_page', 'show_qr', 'two_factor',
        'google.login', 'google.authorized', 'github.login', 'github.authorized',
        'google_login', # Add exemption for the google_login route
        'static' # Allow access to static files (CSS, JS, images)
    ]

    # Check if the requested endpoint is one of the allowed endpoints
    if request.endpoint in allowed_endpoints or request.endpoint is None:
        # If endpoint is None, it might be the favicon or other non-routed request
        return # Allow the request to proceed without session check

    # Now perform the session validity check only for other endpoints
    if 'username' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        if not cur.fetchone():
            session.clear() # Clear the whole session if user not found in DB
            flash('Your session has expired. Please log in again', 'warning')
            return redirect(url_for('login'))
        cur.close()
    # If 'username' is not in session, login_required decorator will handle redirection for protected routes

@app.route('/')
@login_required
def home():
    role = session.get('role')

    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'patient':
        return redirect(url_for('patient_dashboard'))
    elif role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    else:
        flash('Invalid role assigned. Please contact support.', 'danger')
        return redirect(url_for('logout'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirmPassword')
            role = request.form.get('role')
            specialization = request.form.get('specialization') if role == 'doctor' else None
            license_number = request.form.get('license_number') if role == 'doctor' else None
            doctor_id_file = request.files.get('doctor_id_image') if role == 'doctor' else None

            # Server-side validation
            if not username or not email or not password or not confirm_password or not role:
                flash('All fields are required.', 'danger')
                log_action(username or 'anonymous', 'register_failed', 'Registration failed: Missing fields.')
                return redirect(url_for('register'))

            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Passwords do not match.')
                return redirect(url_for('register'))

            # Basic format validation
            if len(username) < 3 or len(username) > 20 or not re.match("^[a-zA-Z0-9_-]+$", username):
                flash('Invalid username format.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Invalid username format.')
                return redirect(url_for('register'))

            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                flash('Invalid email format.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Invalid email format.')
                return redirect(url_for('register'))

            if len(password) < 8 or not re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password):
                flash('Invalid password format.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Invalid password format.')
                return redirect(url_for('register'))

            # Validate role
            if role not in ['patient', 'doctor']:
                flash('Invalid role selected.', 'danger')
                log_action(username, 'register_failed', 'Registration failed: Invalid role selected.')
                return redirect(url_for('register'))

            cur = mysql.connection.cursor()
            try:
                # Check if username or email already exists
                cur.execute("SELECT COUNT(*) FROM users WHERE username = %s OR email = %s", (username, email,))
                if cur.fetchone()[0] > 0:
                    flash('Username or email already exists.', 'danger')
                    log_action(username, 'register_failed', 'Registration failed: Username or email already exists.')
                    return redirect(url_for('register'))

                hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
                totp_secret = pyotp.random_base32()

                if role == 'doctor':
                    # Minimal validation for doctor-specific fields
                    if not specialization or not license_number:
                        flash('Specialization and license number are required for doctors.', 'danger')
                        return redirect(url_for('register'))

                    doctor_id_image_bytes = None
                    if doctor_id_file and doctor_id_file.filename:
                        try:
                            doctor_id_image_bytes = doctor_id_file.read()
                        except Exception:
                            doctor_id_image_bytes = None

                    # Generate RSA key pair for doctor to enable signing
                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    private_pem = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode('utf-8')
                    public_pem = key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')

                    cur.execute(
                        """
                        INSERT INTO users (username, email, password, 2fa_secret, role, specialization, license_number, doctor_id_image, private_key, public_key)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (username, email, hashed_pw, totp_secret, role, specialization, license_number, doctor_id_image_bytes, private_pem, public_pem)
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO users (username, email, password, 2fa_secret, role)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (username, email, hashed_pw, totp_secret, role)
                    )
                mysql.connection.commit()

                log_action(username, 'register_success', f'User registered successfully as {role}.')
                flash('Registration successful! Please set up your two-factor authentication.', 'success')

                # Redirect to QR page
                app.logger.info(f"Redirecting registered user {username} to QR page.")
                return redirect(url_for('qr_page', username=username))

            except Exception as e:
                mysql.connection.rollback()
                app.logger.error(f"Database error during registration for user {username}: {e}\n{traceback.format_exc()}")
                log_action(username, 'register_error', f'Database error during registration: {e}')
                flash('An error occurred during registration. Please try again.', 'danger')
                return redirect(url_for('register'))
            finally:
                cur.close()

        except Exception as e:
            app.logger.error(f"Error in registration process: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash('An unexpected error occurred. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/qr/<username>')
def qr_page(username):
    app.logger.info(f"Accessing QR page for user: {username}")
    # You might want to add a check here to ensure the username exists and is the user who just registered
    # This prevents arbitrary access to the QR page
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    if not user:
        app.logger.warning(f"QR page accessed for non-existent or invalid user: {username}")
        flash('Invalid user or page access.', 'danger')
        return redirect(url_for('register')) # Or login page

    return render_template('qr_page.html', username=username)

@app.route('/qrcode/<username>')
def show_qr(username):
    app.logger.info(f"Generating QR code for user: {username}")
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT 2fa_secret FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        if not result:
            app.logger.error(f"2FA secret not found for user {username} during QR generation.")
            log_action(username, 'qr_code_failed', f'2FA secret not found for user {username}.')
            return "Error generating QR code: User not found or secret missing.", 404

        secret = result[0]

        totp = pyotp.TOTP(secret)
        otp_uri = totp.provisioning_uri(name=username, issuer_name="SecureDocs")
        app.logger.info(f"Generated TOTP URI for {username}: {otp_uri}")

        img = qrcode.make(otp_uri)

        buf = io.BytesIO()
        img.save(buf, 'PNG') # Specify format explicitly
        buf.seek(0)

        log_action(username, 'qr_code_success', f'Generated QR code for 2FA for user {username}')
        app.logger.info(f"Successfully generated and sending QR code image for user {username}.")

        return send_file(buf, mimetype='image/png')

    except Exception as e:
        app.logger.error(f"Error generating or serving QR code for user {username}: {e}\n{traceback.format_exc()}")
        log_action(username, 'qr_code_error', f'Error generating or serving QR code: {e}')
        cur.close() # Ensure cursor is closed even on error
        return "An error occurred while generating the QR code.", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['pre_2fa_user'] = user[1]
            # Log successful password verification, pending 2FA
            log_action(username, 'login_manual_password_success', f'Password verified for user {username}. Proceeding to 2FA.')
            return redirect(url_for('two_factor'))

        # Log failed login attempt
        log_action(username, 'login_manual_failed', f'Failed login attempt for user {username}')
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        username = session['pre_2fa_user']

        cur = mysql.connection.cursor()
        cur.execute("SELECT 2fa_secret, role FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()

        if not result:
            session.clear()
            flash('User not found', 'danger')
            return redirect(url_for('login'))

        secret, role = result
        totp = pyotp.TOTP(secret)

        if totp.verify(token):
            session.pop('pre_2fa_user')
            session['username'] = username
            session['role'] = role
            session.permanent = True  # Make session permanent
            # Load profile fields into session for UI (e.g., first name)
            try:
                cur = mysql.connection.cursor()
                cur.execute("SELECT first_name FROM users WHERE username = %s", (username,))
                name_row = cur.fetchone()
                cur.close()
                if name_row and name_row[0]:
                    session['first_name'] = name_row[0]
            except Exception:
                pass
            log_action(username, 'login_manual_2fa_success', f'User {username} successfully completed 2FA and logged in manually.')
            flash('Successfully logged in', 'success')
            return redirect(url_for('home'))
        else:
            # Log failed 2FA attempt
            log_action(username, 'login_manual_2fa_failed', f'User {username} failed 2FA. Invalid code.')
            flash('Invalid 2FA code. Please try again.', 'danger')
            return render_template('2fa.html')

    return render_template('2fa.html')

@app.route('/google-login')
def google_login():
    # If the user is already logged in, redirect them
    if is_logged_in():
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    # Log initiation of Google login
    log_action(session.get('username', 'anonymous'), 'login_google_initiate', 'Initiated Google login process')
    return redirect(url_for("google.login")) # This redirects to the Google OAuth flow

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        # Log failed Google login
        log_action(session.get('username', 'anonymous'), 'login_google_failed', 'Google login failed or was denied')
        flash('Google login failed.', 'danger')
        return redirect(url_for('login'))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        resp.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        user_info = resp.json()
        google_id = user_info['id']
        email = user_info.get('email')
        username = user_info.get('name', email)

        cur = mysql.connection.cursor()

        # Check if user exists by Google ID
        cur.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        user = cur.fetchone()

        if user:
            # User exists, log them in
            session['username'] = user[1] # username
            session['role'] = user[5] # Assuming role is at index 5
            session.permanent = True
            try:
                # Load first name for navbar display
                session['first_name'] = user[6] if len(user) > 6 else session.get('first_name')
            except Exception:
                pass
            log_action(session['username'], 'login_google_success', f'User {session["username"]} logged in successfully with Google.')
            flash('Successfully logged in with Google', 'success')
        else:
            # New user, register them
            # Check if email already exists for a non-Google user
            cur.execute("SELECT * FROM users WHERE email = %s AND google_id IS NULL", (email,))
            existing_user_with_email = cur.fetchone()

            if existing_user_with_email:
                # Email exists but is not linked to Google, inform user
                flash('An account with this email already exists. Please log in with your existing method or link your Google account in profile settings.', 'warning')
                log_action(username or 'anonymous', 'login_google_failed_email_exists', f'Google login failed for email {email}. Email already registered.')
                return redirect(url_for('login'))

            # Generate a random password (not used for login, just to satisfy DB schema if password is NOT NULL)
            # and a 2FA secret (can be null for OAuth users or generated)
            import secrets
            random_password = secrets.token_urlsafe(16)
            totp_secret = None # Or generate one if 2FA is mandatory

            cur.execute("""
                INSERT INTO users (username, email, password, google_id, 2fa_secret, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, random_password, google_id, totp_secret, 'patient'))
            mysql.connection.commit()

            session['username'] = username
            session['role'] = 'patient'
            session.permanent = True
            session['first_name'] = username
            log_action(username, 'register_google', f'New user {username} registered and logged in with Google.')
            flash('Successfully registered and logged in with Google', 'success')

        cur.close()
        return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Error during Google login: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        log_action(session.get('username', 'anonymous'), 'login_google_error', f'Error during Google login: {str(e)}')
        flash('An error occurred during Google login', 'danger')
        return redirect(url_for('login'))

@app.route('/github-login')
def github_login():
    # If the user is already logged in, redirect them
    if is_logged_in():
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    # Log initiation of GitHub login
    log_action(session.get('username', 'anonymous'), 'login_github_initiate', 'Initiated GitHub login process')
    return redirect(url_for("github.login")) # This redirects to the GitHub OAuth flow

@app.route('/login/github/authorized')
def github_authorized():
    if not github.authorized:
        # Log failed GitHub login
        log_action(session.get('username', 'anonymous'), 'login_github_failed', 'GitHub login failed or was denied')
        flash('GitHub login failed.', 'danger')
        return redirect(url_for('login'))

    try:
        resp = github.get("/user")
        resp.raise_for_status()
        github_user_info = resp.json()
        github_id = str(github_user_info['id'])
        username = github_user_info.get('login')
        email = github_user_info.get('email')

        cur = mysql.connection.cursor()

        # Check if user exists by GitHub ID
        cur.execute("SELECT * FROM users WHERE github_id = %s", (github_id,))
        user = cur.fetchone()

        if user:
            # User exists, log them in
            session['username'] = user[1] # username
            session['role'] = user[5] # Assuming role is at index 5
            session.permanent = True
            try:
                # Load first name for navbar display
                cur = mysql.connection.cursor()
                cur.execute("SELECT first_name FROM users WHERE username = %s", (session['username'],))
                name_row = cur.fetchone()
                cur.close()
                if name_row and name_row[0]:
                    session['first_name'] = name_row[0]
            except Exception:
                pass
            log_action(session['username'], 'login_github_success', f'User {session["username"]} logged in successfully with GitHub.')
            flash('Successfully logged in with GitHub', 'success')
        else:
             # New user, register them
            # Check if email already exists for a non-GitHub user
            if email:
                cur.execute("SELECT * FROM users WHERE email = %s AND github_id IS NULL", (email,))
                existing_user_with_email = cur.fetchone()

                if existing_user_with_email:
                    # Email exists but is not linked to GitHub, inform user
                    flash('An account with this email already exists. Please log in with your existing method or link your GitHub account in profile settings.', 'warning')
                    log_action(username or 'anonymous', 'login_github_failed_email_exists', f'GitHub login failed for email {email}. Email already registered.')
                    return redirect(url_for('login'))

            # Generate a random password and a 2FA secret (can be null for OAuth users)
            import secrets
            random_password = secrets.token_urlsafe(16)
            totp_secret = None # Or generate one if 2FA is mandatory

            cur.execute("""
                INSERT INTO users (username, email, password, github_id, 2fa_secret, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, random_password, github_id, totp_secret, 'patient'))
            mysql.connection.commit()

            session['username'] = username
            session['role'] = 'patient'
            session.permanent = True
            session['first_name'] = username
            log_action(username, 'register_github', f'New user {username} registered and logged in with GitHub.')
            flash('Successfully registered and logged in with GitHub', 'success')

        cur.close()
        return redirect(url_for('home'))

    except Exception as e:
        app.logger.error(f"Error during GitHub login: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        log_action(session.get('username', 'anonymous'), 'login_github_error', f'Error during GitHub login: {str(e)}')
        flash('An error occurred during GitHub login', 'danger')
        return redirect(url_for('login'))

@app.route('/documents')
@login_required
def documents():
    try:
        # Get user_id and role from session
        username = session.get('username')
        role = session.get('role')

        if not username or not role:
            # This case should ideally be caught by @login_required, but as a fallback
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))

        cur = mysql.connection.cursor()

        # Get search, sort, and filter parameters
        search = request.args.get('search', '')
        sort = request.args.get('sort', 'newest')
        filter_type = request.args.get('filter', 'all')

        # Base query
        base_query = """
            SELECT d.*, u.username
            FROM documents d
            JOIN users u ON d.user_id = u.id
        """

        # Add search condition if search term is provided
        search_condition = ""
        if search:
            search_condition = " WHERE d.original_filename LIKE %s"

        # Add user filter for non-admin users
        user_condition = ""
        if role != 'admin':
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                session.clear()
                flash('User not found. Please log in again.', 'danger')
                return redirect(url_for('login'))
            user_id = user[0]
            user_condition = " WHERE d.user_id = %s" if not search_condition else " AND d.user_id = %s"

        # Add date filter
        date_condition = ""
        if filter_type != 'all':
            if filter_type == 'today':
                date_condition = " AND DATE(d.upload_time) = CURDATE()"
            elif filter_type == 'week':
                date_condition = " AND YEARWEEK(d.upload_time) = YEARWEEK(CURDATE())"
            elif filter_type == 'month':
                date_condition = " AND MONTH(d.upload_time) = MONTH(CURDATE()) AND YEAR(d.upload_time) = YEAR(CURDATE())"

        # Add sorting
        sort_condition = ""
        if sort == 'newest':
            sort_condition = " ORDER BY d.upload_time DESC"
        elif sort == 'oldest':
            sort_condition = " ORDER BY d.upload_time ASC"
        elif sort == 'name_asc':
            sort_condition = " ORDER BY d.original_filename ASC"
        elif sort == 'name_desc':
            sort_condition = " ORDER BY d.original_filename DESC"

        # Construct the final query
        query = base_query
        params = []

        if search:
            query += search_condition
            params.append(f'%{search}%')

        if role != 'admin':
            query += user_condition
            params.append(user_id)

        if date_condition:
            query += date_condition

        query += sort_condition

        # Execute the query
        cur.execute(query, tuple(params))
        documents = cur.fetchall()
        cur.close()

        # Convert to list of dictionaries for easier template access
        docs = []
        for doc in documents:
            docs.append({
                'id': doc[0],
                'user_id': doc[1],
                'filename': doc[2],
                'original_filename': doc[3],
                'upload_time': doc[4],
                'file_hash': doc[5],
                'signature': doc[6],
                'username': doc[7]
            })

        return render_template('documents.html', documents=docs)
    except Exception as e:
        app.logger.error(f"Error in documents route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash(f'An error occurred while fetching documents: {str(e)}', 'danger')
        return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        app.logger.info("Upload request received")

        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                app.logger.error("No file part in request")
                flash('No file selected', 'danger')
                return redirect(request.url)

            file = request.files['file']
            app.logger.info(f"File received: {file.filename}")

            # Check if file name is empty
            if file.filename == '':
                app.logger.error("No selected file")
                flash('No file selected', 'danger')
                return redirect(request.url)

            # Check if file type is allowed
            if not allowed_file(file.filename):
                app.logger.error(f"Invalid file type: {file.filename}")
                flash('File type not allowed. Supported formats: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG', 'danger')
                return redirect(request.url)

            # Create uploads directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
                app.logger.info(f"Created uploads directory: {app.config['UPLOAD_FOLDER']}")

            # Secure the filename
            original_filename = file.filename
            filename = secure_filename(file.filename)
            # Add username prefix to filename
            username = session['username']
            filename = f"{username}_{filename}.enc"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            app.logger.info(f"Saving file to: {file_path}")

            # Save the file
            try:
                file.save(file_path)
                app.logger.info("File saved successfully")
            except Exception as e:
                app.logger.error(f"Error saving file: {str(e)}")
                flash('Error saving file. Please try again.', 'danger')
                return redirect(request.url)

            # Calculate file hash
            try:
                file_hash = hash_file(file_path)
                app.logger.info(f"File hash calculated: {file_hash}")
            except Exception as e:
                app.logger.error(f"Error calculating file hash: {str(e)}")
                # Clean up the uploaded file
                try:
                    os.remove(file_path)
                except:
                    pass
                flash('Error processing file. Please try again.', 'danger')
                return redirect(request.url)

            # Get user_id from username
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
            user = cur.fetchone()
            if not user:
                raise Exception("User not found")
            user_id = user[0]

            # Store in database
            try:
                cur.execute("""
                    INSERT INTO documents (user_id, filename, original_filename, file_hash)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, filename, original_filename, file_hash))
                mysql.connection.commit()
                app.logger.info("File information stored in database successfully")
            except Exception as e:
                app.logger.error(f"Database error: {str(e)}")
                app.logger.error(f"Error details: {traceback.format_exc()}")
                # Try to clean up the uploaded file
                try:
                    os.remove(file_path)
                except:
                    pass
                flash(f'Error saving file information: {str(e)}', 'danger')
                return redirect(request.url)
            finally:
                cur.close()

            # Log the action
            try:
                log_action(session['username'], 'upload', f'Uploaded file: {original_filename}')
            except Exception as e:
                app.logger.error(f"Error logging action: {str(e)}")
                # Don't return error for logging failure

            flash('File uploaded successfully', 'success')
            return redirect(url_for('documents'))

        except Exception as e:
            # Log the error
            app.logger.error(f"Upload error: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_action(username, action_type, message):
    try:
        # Log to database
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO logs (username, action_type, message)
            VALUES (%s, %s, %s)
        """, (username, action_type, message))
        mysql.connection.commit()

        # Log to file
        app.logger.info(f'Action: {action_type}, User: {username}, Details: {message}')

    except Exception as e:
        app.logger.error(f"Error logging action to database: {str(e)}")
        # Still attempt to log to file even if DB logging fails
        try:
             app.logger.error(f'Failed DB Log - Action: {action_type}, User: {username}, Details: {message} - Error: {str(e)}')
        except Exception as file_log_error:
             print(f"Critical error: Failed to log to both database and file. {file_log_error}")

    finally:
        if 'cur' in locals() and cur:
            cur.close()

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can download any document
            cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only download their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        doc = cur.fetchone()
        cur.close()

        if not doc:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])

        if not os.path.exists(file_path):
            flash('File not found on server', 'danger')
            return redirect(url_for('documents'))

        # Log the download
        log_action(session['username'], 'download', f'Downloaded file: {document["original_filename"]}')

        return send_file(
            file_path,
            as_attachment=True,
            download_name=document['original_filename']
        )

    except Exception as e:
        app.logger.error(f"Error in download route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while downloading the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/verify/<int:doc_id>')
@login_required
def verify(doc_id):
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can verify any document
             cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only verify their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        doc = cur.fetchone()
        cur.close()

        if not doc:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])

        if not os.path.exists(file_path):
            flash('File not found on server', 'danger')
            return redirect(url_for('documents'))

        # Calculate current hash
        current_hash = hash_file(file_path)

        # Compare with stored hash
        if current_hash == document['file_hash']:
            flash('Document integrity verified successfully', 'success')
            log_action(session['username'], 'verify', f'Verified file: {document["original_filename"]}')
        else:
            flash('Document integrity check failed! File may have been modified.', 'danger')
            log_action(session['username'], 'verify_failed', f'Verification failed for file: {document["original_filename"]}')

        return redirect(url_for('documents'))

    except Exception as e:
        app.logger.error(f"Error in verify route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while verifying the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    cur = None
    try:
        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        if role == 'admin':
            # Admins can delete any document
            cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only delete their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.*, u.username
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        doc = cur.fetchone()

        if not doc:
            flash('Document not found or you do not have permission to delete it.', 'danger')
            return redirect(url_for('documents'))

        # Convert to dictionary for easier access
        document = {
            'id': doc[0],
            'user_id': doc[1],
            'filename': doc[2],
            'original_filename': doc[3],
            'upload_time': doc[4],
            'file_hash': doc[5],
            'signature': doc[6],
            'username': doc[7]
        }

        # Delete file from filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                app.logger.info(f"File deleted from filesystem: {file_path}")
        except Exception as e:
            app.logger.error(f"Error deleting file: {str(e)}")
            # Continue with database deletion even if file deletion fails

        # Delete from database
        try:
            # First delete from logs if any related to this original filename
            # Note: This assumes the original filename is unique enough in logs, which might not always be true.
            # A more robust approach might involve linking logs directly to documents or using doc ID in log messages.
            cur.execute("DELETE FROM logs WHERE message LIKE %s", (f'%{document["original_filename"]}%',))

            # Then delete the document based on role
            if role == 'admin':
                 # Admins can delete any document
                 cur.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
            else:
                 # Regular users can only delete their own documents
                 # We already fetched user_id at the beginning for regular users if needed
                 # Re-fetch user_id just in case session changed (unlikely but safer)
                 cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                 user = cur.fetchone()
                 if not user:
                      # Should not happen with @login_required and initial checks, but as fallback
                      flash('User not found during deletion process.', 'danger')
                      log_action(session['username'], 'delete_document_user_not_found', f'User {username} not found during deletion attempt for doc ID {doc_id}.')
                      return redirect(url_for('documents'))
                 user_id = user[0]
                 cur.execute("DELETE FROM documents WHERE id = %s AND user_id = %s", (doc_id, user_id))

            mysql.connection.commit()
            flash('Document deleted successfully', 'success')
            # Log successful deletion
            log_action(session['username'], 'delete_success', f'Deleted file: {document["original_filename"]}')
        except Exception as e:
            app.logger.error(f"Error deleting document from database: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash('Error deleting document from database', 'danger')
            # Log database deletion failure
            log_action(session['username'], 'delete_db_failed', f'Failed to delete file from database: {document["original_filename"]}')
        finally:
            if cur:
                cur.close()

        return redirect(url_for('documents'))

    except Exception as e:
        app.logger.error(f"Error in delete route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        if cur:
            cur.close()
        flash('An error occurred while deleting the file', 'danger')
        return redirect(url_for('documents'))

@app.route('/logout')
def logout():
    # Set a flag to temporarily disable session check in before_request
    session['_logging_out'] = True

    # Clear only the application-specific session keys
    session.pop('username', None)
    session.pop('role', None)
    session.pop('pre_2fa_user', None)

    # After a short delay (or on the next request), the flag will be removed.
    # For simplicity, we'll handle the flag check in before_request.

    flash('You have been successfully logged out', 'success')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        flash('Please log in to edit your profile', 'danger')
        return redirect(url_for('login'))

    if request.method == 'GET':
        # Get user data
        cursor = mysql.connection.cursor()
        cursor.execute('''
            SELECT username, email, first_name, last_name, phone, date_of_birth,
                   gender, blood_type, emergency_contact, emergency_phone
            FROM users
            WHERE username = %s
        ''', (session['username'],))
        user = cursor.fetchone()
        cursor.close()

        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        # Convert tuple to dictionary for template
        user_dict = {
            'username': user[0],
            'email': user[1],
            'first_name': user[2],
            'last_name': user[3],
            'phone': user[4],
            'date_of_birth': user[5],
            'gender': user[6],
            'blood_type': user[7],
            'emergency_contact': user[8],
            'emergency_phone': user[9]
        }

        return render_template('edit_profile.html', user=user_dict)

    if request.method == 'POST':
        try:
            # Get form data
            username = request.form['username']
            email = request.form['email']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            phone = request.form['phone']
            date_of_birth = request.form['date_of_birth']
            gender = request.form['gender']
            blood_type = request.form['blood_type']
            emergency_contact = request.form['emergency_contact']
            emergency_phone = request.form['emergency_phone']
            current_password = request.form['current_password']
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # Verify current password
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT password FROM users WHERE username = %s', (session['username'],))
            user = cursor.fetchone()

            if not user or not bcrypt.check_password_hash(user[0], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('edit_profile'))

            # Check if username is already taken (if changed)
            if username != session['username']:
                cursor.execute('SELECT id FROM users WHERE username = %s AND username != %s',
                             (username, session['username']))
                if cursor.fetchone():
                    flash('Username is already taken', 'danger')
                    return redirect(url_for('edit_profile'))

            # Check if email is already taken (if changed)
            cursor.execute('SELECT id FROM users WHERE email = %s AND username != %s',
                         (email, session['username']))
            if cursor.fetchone():
                flash('Email is already taken', 'danger')
                return redirect(url_for('edit_profile'))

            # If changing password, validate confirmation server-side
            if new_password:
                if not confirm_password or confirm_password != new_password:
                    flash('New passwords do not match.', 'danger')
                    return redirect(url_for('edit_profile'))

            # Update user data
            update_query = '''
                UPDATE users
                SET username = %s, email = %s, first_name = %s, last_name = %s,
                    phone = %s, date_of_birth = %s, gender = %s, blood_type = %s,
                    emergency_contact = %s, emergency_phone = %s
            '''
            update_params = [
                username, email, first_name, last_name, phone, date_of_birth,
                gender, blood_type, emergency_contact, emergency_phone
            ]

            # Update password if provided
            if new_password:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                update_query += ', password = %s'
                update_params.append(hashed_password)

            update_query += ' WHERE username = %s'
            update_params.append(session['username'])

            cursor.execute(update_query, tuple(update_params))
            mysql.connection.commit()

            # Handle profile photo
            if 'photo' in request.files:
                photo = request.files['photo']
                if photo and photo.filename:
                    # Create profile_photos directory if it doesn't exist
                    profile_photos_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos')
                    os.makedirs(profile_photos_dir, exist_ok=True)

                    # Generate a unique filename
                    filename = secure_filename(f"{username}_{photo.filename}")
                    photo_path = os.path.join(profile_photos_dir, filename)

                    # Save the photo
                    photo.save(photo_path)

                    # Update the database with the new photo filename
                    cursor.execute('''
                        UPDATE users
                        SET profile_photo = %s
                        WHERE username = %s
                    ''', (filename, username))
                    mysql.connection.commit()

            # Handle photo removal
            if request.form.get('remove_photo') == 'true':
                # Get current photo filename
                cursor.execute('SELECT profile_photo FROM users WHERE username = %s', (username,))
                current_photo = cursor.fetchone()

                if current_photo and current_photo[0]:
                    # Delete the file if it exists
                    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos', current_photo[0])
                    if os.path.exists(photo_path):
                        os.remove(photo_path)

                # Update database
                cursor.execute('''
                    UPDATE users
                    SET profile_photo = NULL
                    WHERE username = %s
                ''', (username,))
                mysql.connection.commit()

            # Update session username if changed
            if username != session['username']:
                session['username'] = username

            flash('Profile updated successfully', 'success')
            log_action(session['username'], 'profile_update', 'Updated profile information')
            return redirect(url_for('home'))

        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f"Error updating profile: {str(e)}")
            app.logger.error(f"Error details: {traceback.format_exc()}")
            flash('An error occurred while updating your profile', 'danger')
            log_action(session['username'], 'error', f'Error updating profile: {str(e)}')
            return redirect(url_for('edit_profile'))
        finally:
            cursor.close()



@app.route('/profile-photo/<username>')
def get_profile_photo(username):
    """Serve the user's profile photo"""
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT profile_photo FROM users WHERE username = %s", (username,))
        result = cur.fetchone()

        if result and result[0]:
            # Create a response with the image data
            response = send_file(
                io.BytesIO(result[0]),
                mimetype='image/jpeg'
            )
            return response
        else:
            # Return a default profile photo
            default_photo_path = os.path.join(app.static_folder, 'images', 'default_profile.jpg')
            if os.path.exists(default_photo_path):
                return send_file(default_photo_path)
            else:
                # If default photo doesn't exist, return a 404
                return "Default profile photo not found", 404
    except Exception as e:
        app.logger.error(f"Error serving profile photo for {username}: {e}")
        return "Error serving profile photo", 500
    finally:
        cur.close()

@app.route('/admin')
@admin_required
def admin_dashboard():
    # This is the main admin dashboard route
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get search and filter parameters for users
        user_search = request.args.get('user_search', '')
        user_role = request.args.get('user_role', 'all')

        # Construct user query
        user_query = "SELECT id, username, email, role FROM users"
        user_params = []

        if user_search or user_role != 'all':
            user_query += " WHERE"
            conditions = []

            if user_search:
                conditions.append(" (username LIKE %s OR email LIKE %s)")
                user_params.extend([f'%{user_search}%', f'%{user_search}%'])

            if user_role != 'all':
                conditions.append(" role = %s")
                user_params.append(user_role)

            user_query += " AND ".join(conditions)

        # Execute user query
        cur.execute(user_query, tuple(user_params))
        users = cur.fetchall()

        # Get system statistics
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'patient'")
        patient_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor'")
        doctor_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cur.fetchone()[0]

        # Get recent system logs
        cur.execute("""
            SELECT timestamp, username, action_type, message
            FROM logs
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        recent_logs = cur.fetchall()

        return render_template('admin_dashboard.html',
                             users=users,
                             stats={
                                 'patients': patient_count,
                                 'doctors': doctor_count,
                                 'admins': admin_count
                             },
                             recent_logs=recent_logs)

    except Exception as e:
        app.logger.error(f"Error fetching data for admin dashboard: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the admin dashboard.', 'danger')
        return redirect(url_for('home'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Prevent deleting the last admin user (optional but recommended)
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cur.fetchone()[0]

        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user_role = cur.fetchone()[0]

        if user_role == 'admin' and admin_count <= 1:
            flash('Cannot delete the last admin user.', 'danger')
            log_action(session['username'], 'admin_delete_user_failed', f'Attempted to delete the last admin user with ID {user_id}.')
            return redirect(url_for('admin_dashboard'))

        # Delete user's files first
        cur.execute("SELECT filename FROM documents WHERE user_id = %s", (user_id,))
        user_files = cur.fetchall()
        for file in user_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[0])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    app.logger.info(f"Admin deleted user file from filesystem: {file_path}")
                except Exception as e:
                    app.logger.error(f"Admin error deleting user file {file[0]}: {str(e)}")
                    # Log file deletion failure
                    log_action(session['username'], 'admin_delete_user_file_failed', f'Admin failed to delete file {file[0]} for user ID {user_id}: {str(e)}')

        cur.execute("DELETE FROM documents WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM logs WHERE username = (SELECT username FROM users WHERE id = %s)", (user_id,)) # Delete user's logs
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()

        flash('User and associated files deleted successfully.', 'success')
        log_action(session['username'], 'admin_delete_user_success', f'Admin deleted user with ID {user_id}.')

        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        app.logger.error(f"Error deleting user from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while deleting the user.', 'danger')
        log_action(session['username'], 'admin_delete_user_error', f'An error occurred while deleting user with ID {user_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/file/<int:file_id>/delete', methods=['POST'])
@admin_required
def admin_delete_file(file_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get file information before deleting
        cur.execute("SELECT filename, original_filename FROM documents WHERE id = %s", (file_id,))
        file_info = cur.fetchone()

        if not file_info:
            flash('File not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        stored_filename, original_filename = file_info
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

        # Delete file from filesystem
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                app.logger.info(f"Admin deleted file from filesystem: {file_path}")
            except Exception as e:
                app.logger.error(f"Admin error deleting file from filesystem {stored_filename}: {str(e)}")
                # Log file deletion failure
                log_action(session['username'], 'admin_delete_file_filesystem_failed', f'Admin failed to delete file from filesystem {stored_filename}: {str(e)}')

        # Delete from database
        cur.execute("DELETE FROM logs WHERE message LIKE %s", (f'%{original_filename}%',))
        cur.execute("DELETE FROM documents WHERE id = %s", (file_id,))
        mysql.connection.commit()

        flash('File deleted successfully.', 'success')
        log_action(session['username'], 'admin_delete_file_success', f'Admin deleted file with ID {file_id} ({original_filename}).')

        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        app.logger.error(f"Error deleting file from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while deleting the file.', 'danger')
        log_action(session['username'], 'admin_delete_file_error', f'An error occurred while deleting file with ID {file_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/logs')
@admin_required
def admin_logs():
    cur = None
    try:
        cur = mysql.connection.cursor()
        # Fetch all logs, ordered by timestamp
        cur.execute("SELECT timestamp, username, action_type, message FROM logs ORDER BY timestamp DESC")
        logs = cur.fetchall()

        return render_template('admin_logs.html', logs=logs)

    except Exception as e:
        app.logger.error(f"Error fetching logs for admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the logs.', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/edit_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    app.logger.info(f"Attempting to access edit_document route for doc ID: {doc_id}")
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get user information and role from session
        username = session.get('username')
        role = session.get('role')

        # Get document information
        if role == 'admin':
            # Admins can edit any document
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.upload_time, u.username
                FROM documents d JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            # Regular users can only edit their own documents
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                 flash('User not found', 'danger')
                 return redirect(url_for('home'))
            user_id = user[0]
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.upload_time, u.username
                FROM documents d JOIN users u ON d.user_id = u.id
                WHERE d.id = %s AND d.user_id = %s
            """, (doc_id, user_id))

        document = cur.fetchone()

        if not document:
            flash('Document not found or you do not have permission to edit it.', 'danger')
            log_action(session['username'], 'edit_document_failed', f'Attempted to edit document ID {doc_id} not found or without permission.')
            return redirect(url_for('documents'))

        doc_id, original_filename, stored_filename, upload_time, doc_owner_username = document # Get doc_owner_username

        if request.method == 'POST':
            # Handle file update logic here
            new_file = request.files.get('new_file')
            updated_original_filename = request.form.get('original_filename')

            if not updated_original_filename:
                 flash('Original filename is required.', 'danger')
                 log_action(username, 'edit_document_missing_filename', f'Attempted to update document ID {doc_id} with missing original filename.')
                 return redirect(url_for('edit_document', doc_id=doc_id))


            if new_file and new_file.filename != '':
                # Process the new file
                if not allowed_file(new_file.filename):
                    flash('Invalid file type for new file!', 'danger')
                    log_action(username, 'edit_document_invalid_type', f'Attempted to upload invalid file type for document ID {doc_id}: {new_file.filename}')
                    return redirect(url_for('edit_document', doc_id=doc_id))

                # Secure the filename and create stored filename with timestamp
                # Use the potentially updated original filename for logging and database
                secured_new_original_filename = secure_filename(updated_original_filename)
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                new_stored_filename = f'{timestamp}_{secured_new_original_filename}'
                new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_stored_filename)

                # Save the new file temporarily
                temp_new_file_path = new_file_path + '.temp'
                new_file.save(temp_new_file_path)

                # Calculate hash of the new file
                new_file_hash = hash_file(temp_new_file_path)

                # Encrypt the new file using the document owner's username for the key
                try:
                    with open(temp_new_file_path, 'rb') as f:
                        new_file_bytes = f.read()

                    # Use the document owner's username to derive the encryption key
                    encryption_key = hashlib.sha256(doc_owner_username.encode()).digest()
                    encrypted_bytes = encrypt_file(new_file_bytes, encryption_key)

                    with open(new_file_path, 'wb') as f:
                        f.write(encrypted_bytes)

                    # Remove temporary file
                    os.remove(temp_new_file_path)
                except Exception as e:
                    app.logger.error(f"Error encrypting new file for document ID {doc_id}: {str(e)}")
                    app.logger.error(f"Error details: {traceback.format_exc()}")
                    if os.path.exists(temp_new_file_path):
                        os.remove(temp_new_file_path)
                    flash(f'Error encrypting new file: {str(e)}', 'danger')
                    log_action(username, 'edit_document_encrypt_failed', f'Encryption failed for new file for document ID {doc_id}: {str(e)}')
                    return redirect(url_for('edit_document', doc_id=doc_id))

                # Delete the old file from filesystem
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                if os.path.exists(old_file_path):
                    try:
                        os.remove(old_file_path)
                        app.logger.info(f"Old file deleted during edit: {old_file_path}")
                    except Exception as e:
                        app.logger.error(f"Error deleting old file during edit {stored_filename}: {str(e)}")
                        # Log old file deletion failure (non-critical for the edit process to continue)
                        log_action(username, 'edit_document_old_delete_failed', f'Failed to delete old file {stored_filename} for document ID {doc_id}: {str(e)}')

                # Update database entry with new file info and updated original filename
                cur.execute("""
                    UPDATE documents SET filename = %s, original_filename = %s, file_hash = %s, upload_time = %s
                    WHERE id = %s
                """, (new_stored_filename, updated_original_filename, new_file_hash, datetime.now(), doc_id))
                mysql.connection.commit()

                flash('Document and file updated successfully!', 'success')
                log_action(username, 'edit_document_success_with_file', f'Updated document ID {doc_id} with new file and name: {updated_original_filename}.')
                return redirect(url_for('documents'))

            # If no new file uploaded, only update the original filename
            else:
                # Check if the original filename has actually changed
                if updated_original_filename != original_filename:
                    cur.execute("""
                        UPDATE documents SET original_filename = %s
                        WHERE id = %s
                    """, (updated_original_filename, doc_id))
                    mysql.connection.commit()
                    flash('Document filename updated successfully.', 'success')
                    log_action(username, 'edit_document_success_filename_only', f'Updated filename for document ID {doc_id} to {updated_original_filename}.')
                else:
                    flash('No changes were made.', 'info')
                    log_action(username, 'edit_document_no_changes', f'Attempted to edit document ID {doc_id} but no changes were made.')

                return redirect(url_for('documents'))

        # For GET request, render the edit form
        # Convert document tuple to dictionary for easier template access (excluding stored_filename for template)
        doc_data = {
            'id': document[0],
            'original_filename': document[1],
            'upload_time': document[3], # Use original upload_time for display
            'username': document[4] # Document owner's username
        }
        return render_template('edit_document.html', document=doc_data)

    except Exception as e:
        app.logger.error(f"Error processing edit document for doc ID {doc_id}: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while updating the document.', 'danger')
        log_action(session['username'], 'edit_document_error', f'An error occurred while processing edit for document ID {doc_id}: {str(e)}')
        return redirect(url_for('documents'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    cur = None
    try:
        cur = mysql.connection.cursor()

        # Get user information
        cur.execute("""
            SELECT id, username, email, role, first_name, last_name,
                   phone, date_of_birth, gender, blood_type,
                   emergency_contact, emergency_phone, specialization,
                   license_number
            FROM users
            WHERE id = %s
        """, (user_id,))
        user = cur.fetchone()

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Convert user tuple to dictionary for easier template access
        user_data = {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3],
            'first_name': user[4],
            'last_name': user[5],
            'phone': user[6],
            'date_of_birth': user[7],
            'gender': user[8],
            'blood_type': user[9],
            'emergency_contact': user[10],
            'emergency_phone': user[11],
            'specialization': user[12],
            'license_number': user[13]
        }

        if request.method == 'POST':
            # Get form data
            new_username = request.form.get('username')
            new_email = request.form.get('email')
            new_role = request.form.get('role')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone = request.form.get('phone')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            blood_type = request.form.get('blood_type')
            emergency_contact = request.form.get('emergency_contact')
            emergency_phone = request.form.get('emergency_phone')
            specialization = request.form.get('specialization') if new_role == 'doctor' else None
            license_number = request.form.get('license_number') if new_role == 'doctor' else None

            # Validate required fields
            if not all([new_username, new_email, new_role, first_name, last_name, phone,
                       date_of_birth, gender, blood_type, emergency_contact, emergency_phone]):
                flash('All fields are required.', 'danger')
                return render_template('admin_edit_user.html', user=user_data)

            # Check if username already exists (excluding the current user)
            cur.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
            if cur.fetchone():
                flash('Username already exists.', 'danger')
                return render_template('admin_edit_user.html', user=user_data)

            # Check if email already exists (excluding the current user)
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, user_id))
            if cur.fetchone():
                flash('Email already exists.', 'danger')
                return render_template('admin_edit_user.html', user=user_data)

            # Update user in database
            cur.execute("""
                UPDATE users
                SET username = %s,
                    email = %s,
                    role = %s,
                    first_name = %s,
                    last_name = %s,
                    phone = %s,
                    date_of_birth = %s,
                    gender = %s,
                    blood_type = %s,
                    emergency_contact = %s,
                    emergency_phone = %s,
                    specialization = %s,
                    license_number = %s
                WHERE id = %s
            """, (
                new_username, new_email, new_role,
                first_name, last_name, phone, date_of_birth,
                gender, blood_type, emergency_contact,
                emergency_phone, specialization, license_number,
                user_id
            ))
            mysql.connection.commit()

            flash('User updated successfully.', 'success')
            log_action(session['username'], 'admin_edit_user_success',
                      f'Admin updated user ID {user_id} (Username: {new_username}, Role: {new_role})')

            return redirect(url_for('admin_dashboard'))

        # For GET request, render the edit form
        return render_template('admin_edit_user.html', user=user_data)

    except Exception as e:
        app.logger.error(f"Error editing user ID {user_id} from admin panel: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while editing the user.', 'danger')
        log_action(session['username'], 'admin_edit_user_error',
                  f'An error occurred while editing user ID {user_id}: {str(e)}')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cur:
            cur.close()

@app.route('/admin/user/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone = request.form.get('phone')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            blood_type = request.form.get('blood_type')
            emergency_contact = request.form.get('emergency_contact')
            emergency_phone = request.form.get('emergency_phone')
            specialization = request.form.get('specialization') if role == 'doctor' else None
            license_number = request.form.get('license_number') if role == 'doctor' else None

            # Validate required fields
            if not all([username, email, password, role, first_name, last_name, phone,
                       date_of_birth, gender, blood_type, emergency_contact, emergency_phone]):
                flash('All fields are required', 'danger')
                return redirect(url_for('admin_add_user'))

            # Check if username or email already exists
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
            if cursor.fetchone():
                flash('Username or email already exists', 'danger')
                return redirect(url_for('admin_add_user'))

            # Hash password using Flask-Bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Generate 2FA secret
            twofa_secret = pyotp.random_base32()

            # Insert new user
            cursor.execute('''
                INSERT INTO users (
                    username, email, password, role, first_name, last_name,
                    phone, date_of_birth, gender, blood_type,
                    emergency_contact, emergency_phone, specialization,
                    license_number, 2fa_secret, created_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                )
            ''', (
                username, email, hashed_password, role, first_name, last_name,
                phone, date_of_birth, gender, blood_type,
                emergency_contact, emergency_phone, specialization,
                license_number, twofa_secret
            ))
            mysql.connection.commit()

            # Log the action
            log_action(
                session['username'],
                'user_created',
                f'Created new {role} account: {username}'
            )

            flash(f'Successfully created new {role} account', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            app.logger.error(f"Error creating user: {str(e)}")
            flash('An error occurred while creating the user', 'danger')
            return redirect(url_for('admin_add_user'))

    return render_template('admin_add_user.html')

@app.after_request
def add_security_headers(response):
    # Prevent caching of sensitive pages
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/sign_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def sign_document(doc_id):
    cur = None
    try:
        username = session.get('username')
        role = session.get('role')

        cur = mysql.connection.cursor()

        # Fetch document details and check authorization
        if role == 'admin':
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.user_id, d.signature, d.signature_time, u.username as signed_by_username
                FROM documents d
                LEFT JOIN users u ON d.signed_by = u.id
                WHERE d.id = %s
            """, (doc_id,))
        else:
            cur.execute("""
                SELECT d.id, d.original_filename, d.filename, d.user_id, d.signature, d.signature_time, u.username as signed_by_username
                FROM documents d
                LEFT JOIN users u ON d.signed_by = u.id
                JOIN users doc_owner ON d.user_id = doc_owner.id
                WHERE d.id = %s AND doc_owner.username = %s
            """, (doc_id, username))

        document = cur.fetchone()

        if not document:
            flash('Document not found or you do not have permission to sign it.', 'danger')
            return redirect(url_for('documents'))

        doc_id, original_filename, stored_filename, doc_owner_user_id, existing_signature, signature_time, signed_by_username = document

        # If document is already signed, show signature info
        if existing_signature:
            return render_template('view_signature.html',
                                 document_name=original_filename,
                                 signature={
                                     'signer_name': signed_by_username,
                                     'signed_at': signature_time,
                                     'document_hash': get_document_hash(open(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename), 'rb').read())
                                 })

        if request.method == 'POST':
            # Get the document owner's private key
            cur.execute("SELECT id, private_key FROM users WHERE id = %s", (doc_owner_user_id,))
            owner_info = cur.fetchone()

            if not owner_info:
                flash('Document owner not found.', 'danger')
                return redirect(url_for('documents'))

            owner_id, private_key_pem = owner_info

            if not private_key_pem:
                flash('No private key found for document owner. Cannot sign.', 'danger')
                return redirect(url_for('documents'))

            # Read the file content
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            if not os.path.exists(file_path):
                flash('File not found on server.', 'danger')
                return redirect(url_for('documents'))

            with open(file_path, 'rb') as f:
                file_content = f.read()

            try:
                # Sign the document
                signature = sign_document_util(file_content, private_key_pem)

                # Store the signature in the database
                cur.execute("""
                    UPDATE documents
                    SET signature = %s,
                        signature_time = CURRENT_TIMESTAMP,
                        signed_by = %s
                    WHERE id = %s
                """, (signature, owner_id, doc_id))
                mysql.connection.commit()

                flash('Document signed successfully!', 'success')
                log_action(username, 'sign_document_success',
                          f'Successfully signed document ID {doc_id} ({original_filename}).')
                return redirect(url_for('documents'))

            except Exception as e:
                app.logger.error(f"Error signing document: {str(e)}")
                app.logger.error(f"Error details: {traceback.format_exc()}")
                flash(f'Error signing document: {str(e)}', 'danger')  # Show the real error!
                return redirect(url_for('documents'))

        # For GET request, show signing form
        return render_template('sign_document.html',
                             document_name=original_filename,
                             doc_id=doc_id)

    except Exception as e:
        app.logger.error(f"Error in sign_document route: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred.', 'danger')
        return redirect(url_for('documents'))
    finally:
        if cur:
            cur.close()

@app.route('/remove-profile-photo', methods=['POST'])
@login_required
def remove_profile_photo():
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET profile_photo = NULL WHERE username = %s", (session['username'],))
        mysql.connection.commit()
        flash('Profile photo removed successfully', 'success')
        log_action(session['username'], 'profile_photo_removed', 'Profile photo removed')
    except Exception as e:
        app.logger.error(f"Error removing profile photo: {str(e)}")
        flash('Error removing profile photo', 'danger')
    finally:
        cur.close()
    return redirect(url_for('edit_profile'))

@app.route('/view_signature/<int:doc_id>')
@login_required
def view_signature(doc_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT d.original_filename, d.signature, d.signature_time, u.username as signed_by_username, d.filename, d.file_hash
        FROM documents d
        LEFT JOIN users u ON d.signed_by = u.id
        WHERE d.id = %s
    """, (doc_id,))
    doc = cur.fetchone()
    cur.close()
    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('documents'))

    original_filename, signature, signature_time, signed_by_username, stored_filename, stored_hash = doc

    # Calculate current document hash
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    current_hash = None
    integrity_warning = False

    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            from signature_utils import get_document_hash
            current_hash = get_document_hash(f.read())

            # Compare current hash with stored hash
            if current_hash != stored_hash:
                integrity_warning = True
                flash('WARNING: Document integrity check failed! The document has been modified since it was signed.', 'danger')
                log_action(session['username'], 'document_integrity_violation',
                          f'Document integrity violation detected for {original_filename}. Stored hash: {stored_hash}, Current hash: {current_hash}')

    return render_template('view_signature.html',
                           document_name=original_filename,
                           signature={
                               'signer_name': signed_by_username,
                               'signed_at': signature_time,
                               'document_hash': current_hash,
                               'stored_hash': stored_hash,
                               'integrity_warning': integrity_warning
                           })

@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    try:
        # Debug logging
        app.logger.info(f"Accessing patient dashboard. Session data: {dict(session)}")

        # Check if user is logged in and has patient role
        if not is_logged_in():
            app.logger.warning("User not logged in, redirecting to login")
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))

        if session.get('role') != 'patient':
            app.logger.warning(f"Invalid role access attempt. User role: {session.get('role')}")
            flash('Access denied. Patient role required.', 'danger')
            return redirect(url_for('home'))

        cur = mysql.connection.cursor()

        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()

        if not patient:
            app.logger.error(f"Patient record not found for username: {session['username']}")
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))

        patient_id = patient[0]

        # Get upcoming appointments
        cur.execute("""
            SELECT a.id, a.appointment_date, a.status,
                   CONCAT(u.first_name, ' ', u.last_name) as doctor_name
            FROM appointments a
            JOIN users u ON a.doctor_id = u.id
            WHERE a.patient_id = %s AND a.appointment_date >= NOW()
            ORDER BY a.appointment_date ASC
            LIMIT 5
        """, (patient_id,))
        appointments = cur.fetchall()

        # Format appointments for template
        upcoming_appointments = []
        for appt in appointments:
            status_color = {
                'scheduled': 'primary',
                'completed': 'success',
                'cancelled': 'danger',
                'no_show': 'warning'
            }.get(appt[2], 'secondary')

            upcoming_appointments.append({
                'id': appt[0],
                'appointment_date': appt[1],
                'status': appt[2],
                'status_color': status_color,
                'doctor_name': appt[3]
            })

        # Get recent medical records
        cur.execute("""
            SELECT mr.id, mr.record_date,
                   CONCAT(u.first_name, ' ', u.last_name) as doctor_name , specialization
            FROM medical_records mr
            JOIN users u ON mr.doctor_id = u.id
            WHERE mr.patient_id = %s
            ORDER BY mr.record_date DESC
            LIMIT 5
        """, (patient_id,))
        records = cur.fetchall()

        # Format records for template
        recent_records = []
        for record in records:
            recent_records.append({
                'id': record[0],
                'date': record[1],
                'doctor_name': record[2],
                'specialization': record[3]
            })

        app.logger.info(f"Successfully loaded dashboard for patient: {session['username']}")
        return render_template('patient_dashboard.html',
                             upcoming_appointments=upcoming_appointments,
                             recent_records=recent_records)

    except Exception as e:
        app.logger.error(f"Error in patient dashboard: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('home'))
    finally:
        if 'cur' in locals() and cur:
            cur.close()


@app.route('/patient/appointments')
@login_required
def patient_appointments():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        # Get all appointments
        cur.execute("""
            SELECT a.id, a.appointment_date, a.status, a.reason,
                   CONCAT(u.first_name, ' ', u.last_name) as doctor_name,
                   u.specialization
            FROM appointments a
            JOIN users u ON a.doctor_id = u.id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_date DESC
        """, (patient_id,))
        appointments = cur.fetchall()

        # Transform appointments into a list of dictionaries
        appointments_list = [
            {
                'id': appt[0],
                'appointment_date': appt[1],
                'status': appt[2],
                'reason': appt[3],
                'doctor_name': appt[4],
                'specialization': appt[5]
            } for appt in appointments
        ]

        # Get available doctors for new appointments
        cur.execute("""
            SELECT id, first_name, last_name, specialization
            FROM users
            WHERE role = 'doctor'
            ORDER BY last_name, first_name
        """)
        doctors = cur.fetchall()
        doctors_list = [
            {
                'id': doctor[0],
                'first_name': doctor[1],
                'last_name': doctor[2],
                'specialization': doctor[3]
            } for doctor in doctors
        ]

        return render_template('patient_appointments.html',
                              appointments=appointments_list,
                              doctors=doctors_list)

    except Exception as e:
        app.logger.error(f"Error in patient appointments: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading appointments.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()


# Patient radiology files (upload/list/download)
@app.route('/patient/radiology', methods=['GET', 'POST'])
@login_required
def patient_radiology():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        # Ensure table exists
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS radiology_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                patient_id INT NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                stored_filename VARCHAR(255) NOT NULL,
                file_type VARCHAR(50) NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tumor_detected VARCHAR(50) NULL,
                confidence DECIMAL(5,3) NULL,
                analysis_date TIMESTAMP NULL,
                FOREIGN KEY (patient_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        mysql.connection.commit()
        
        # Add new columns if they don't exist (for existing tables)
        try:
            cur.execute("ALTER TABLE radiology_files ADD COLUMN tumor_detected VARCHAR(50) NULL")
            mysql.connection.commit()
        except:
            pass  # Column already exists
        try:
            cur.execute("ALTER TABLE radiology_files ADD COLUMN confidence DECIMAL(5,3) NULL")
            mysql.connection.commit()
        except:
            pass  # Column already exists
        try:
            cur.execute("ALTER TABLE radiology_files ADD COLUMN analysis_date TIMESTAMP NULL")
            mysql.connection.commit()
        except:
            pass  # Column already exists

        if request.method == 'POST':
            file = request.files.get('file')
            if not file or not file.filename:
                flash('Please choose a file to upload.', 'warning')
                return redirect(url_for('patient_radiology'))

            # Accept images and pdfs
            allowed = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tif', 'tiff', 'pdf'}
            ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
            if ext not in allowed:
                flash('Only images and PDF files are allowed.', 'danger')
                return redirect(url_for('patient_radiology'))

            # Ensure base directory
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
            os.makedirs(user_dir, exist_ok=True)

            # Ensure new DB column 'folder'
            try:
                cur.execute("ALTER TABLE radiology_files ADD COLUMN folder VARCHAR(255) NULL")
                mysql.connection.commit()
            except Exception:
                pass

            # If arriving here via old POST (without folder), just redirect to folders view
            if request.method == 'POST':
                return redirect(url_for('patient_radiology_folders'))
            try:
                cur.execute("SELECT stored_filename FROM radiology_files WHERE patient_id = %s", (patient_id,))
                old_files = [r[0] for r in cur.fetchall()]
                for old_name in old_files:
                    old_path = os.path.join(user_dir, old_name)
                    try:
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    except Exception as e:
                        app.logger.warning(f"Failed to remove old radiology file: {old_path} - {e}")
                if old_files:
                    cur.execute("DELETE FROM radiology_files WHERE patient_id = %s", (patient_id,))
                    mysql.connection.commit()
            except Exception as e:
                app.logger.warning(f"Cleanup of previous radiology files failed: {e}")

            safe_name = secure_filename(file.filename)
            stored_name = f"{int(datetime.now().timestamp())}_{safe_name}"
            stored_path = os.path.join(user_dir, stored_name)
            file.save(stored_path)

            # Analyze MRI images
            tumor_detected = None
            confidence = None
            analysis_date = None
            
            # Check if file is an image (not PDF) for MRI analysis
            image_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tif', 'tiff'}
            if ext in image_extensions:
                try:
                    result, conf = analyze_mri_image(stored_path)
                    tumor_detected = result
                    confidence = conf
                    analysis_date = datetime.now()
                    app.logger.info(f"MRI analysis completed: {result}, confidence: {conf}")
                except FileNotFoundError as e:
                    app.logger.error(f"Model file missing: {e}")
                    app.logger.error(traceback.format_exc())
                    flash('File uploaded successfully. MRI model not found - analysis unavailable. Please contact administrator.', 'warning')
                except Exception as e:
                    app.logger.error(f"Error analyzing MRI image: {e}")
                    app.logger.error(traceback.format_exc())
                    # Continue with upload even if analysis fails
                    flash(f'File uploaded successfully, but analysis failed: {str(e)}', 'warning')

            cur.execute(
                """
                INSERT INTO radiology_files (patient_id, original_filename, stored_filename, file_type, tumor_detected, confidence, analysis_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (patient_id, file.filename, stored_name, ext, tumor_detected, confidence, analysis_date)
            )
            mysql.connection.commit()
            
            if tumor_detected:
                flash(f'Radiology file uploaded and analyzed: {tumor_detected} (confidence: {confidence:.1%})', 'success')
            else:
                flash('Radiology file uploaded successfully.', 'success')
            return redirect(url_for('patient_radiology'))

        # Redirect main radiology page to folders listing
        return redirect(url_for('patient_radiology_folders'))
    except Exception as e:
        app.logger.error(f"Error in patient_radiology: {e}")
        app.logger.error(traceback.format_exc())
        flash('An error occurred while processing radiology files.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()


def _watermark_image(input_path: str, output_path: str, text: str = 'SECURE HEALTH'):
    try:
        with Image.open(input_path).convert('RGBA') as base:
            txt = Image.new('RGBA', base.size, (255, 255, 255, 0))
            draw = ImageDraw.Draw(txt)
            # Font size proportional to image width
            font_size = max(24, base.size[0] // 12)
            try:
                font = ImageFont.truetype('arial.ttf', font_size)
            except Exception:
                font = ImageFont.load_default()
            text_w, text_h = draw.textsize(text, font=font)
            # Center position
            x = (base.size[0] - text_w) // 2
            y = (base.size[1] - text_h) // 2
            draw.text((x, y), text, font=font, fill=(255, 255, 255, 110))
            watermarked = Image.alpha_composite(base, txt).convert('RGB')
            watermarked.save(output_path)
    except Exception as e:
        app.logger.warning(f"Watermarking failed for {input_path}: {e}")


def _watermark_pdf(input_path: str, output_path: str, text: str = 'SECURE HEALTH'):
    if not PdfReader or not PdfWriter or not canvas:
        # Fallback: copy without watermark
        try:
            import shutil
            shutil.copyfile(input_path, output_path)
        except Exception:
            pass
        return
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()
        for page in reader.pages:
            width = float(page.mediabox.width)
            height = float(page.mediabox.height)

            packet = io.BytesIO()
            c = canvas.Canvas(packet, pagesize=(width, height))
            c.setFont("Helvetica", max(18, int(width / 20)))
            c.setFillGray(0.5, alpha=0.3)
            c.saveState()
            c.translate(width/2, height/2)
            c.rotate(30)
            c.drawCentredString(0, 0, text)
            c.restoreState()
            c.save()
            packet.seek(0)

            wm_reader = PdfReader(packet)
            wm_page = wm_reader.pages[0]
            page.merge_page(wm_page)
            writer.add_page(page)

        with open(output_path, 'wb') as f:
            writer.write(f)
    except Exception as e:
        app.logger.warning(f"PDF watermarking failed for {input_path}: {e}")


def _is_file_safe(temp_path: str, ext: str) -> bool:
    ext_l = (ext or '').lower()
    # Basic MIME/structure checks; not a full antivirus
    try:
        if ext_l in {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tif', 'tiff'}:
            with Image.open(temp_path) as im:
                im.verify()  # PIL will raise if corrupted
            return True
        if ext_l == 'pdf':
            # Basic header check tolerant to leading bytes
            with open(temp_path, 'rb') as f:
                head = f.read(2048)
                if b'%PDF-' not in head:
                    return False
            # If library is available, try parsing for extra assurance
            if PdfReader:
                try:
                    reader = PdfReader(temp_path)
                    _ = len(reader.pages)
                except Exception:
                    return False
            return True
        # Other types not allowed here
        return False
    except Exception as e:
        app.logger.warning(f"Security check failed for {temp_path}: {e}")
        return False


@app.route('/patient/radiology/folders')
@login_required
def patient_radiology_folders():
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient_id = cur.fetchone()[0]

        # Ensure column exists
        try:
            cur.execute("ALTER TABLE radiology_files ADD COLUMN folder VARCHAR(255) NULL")
            mysql.connection.commit()
        except Exception:
            pass

        # List folders from DB (distinct), fallback to filesystem
        cur.execute("SELECT DISTINCT COALESCE(folder, '') FROM radiology_files WHERE patient_id = %s", (patient_id,))
        folder_rows = [r[0] for r in cur.fetchall() if r and r[0]]

        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        os.makedirs(base_dir, exist_ok=True)
        fs_folders = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
        folders = sorted(set(folder_rows) | set(fs_folders))

        secured = set()
        for name in folders:
            if os.path.exists(os.path.join(base_dir, name, 'SECURED.marker')):
                secured.add(name)

        return render_template('patient_radiology.html', folders=folders, secured_folders=secured, files=None)
    except Exception as e:
        app.logger.error(f"Error listing radiology folders: {e}")
        flash('An error occurred while listing radiology folders.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()


@app.route('/patient/radiology/folder/create', methods=['POST'])
@login_required
def create_radiology_folder():
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    name = request.form.get('folder_name', '').strip()
    if not name:
        flash('Folder name is required.', 'warning')
        return redirect(url_for('patient_radiology_folders'))

    # sanitize simple
    safe = re.sub(r'[^a-zA-Z0-9_-]+', '_', name)
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient_id = cur.fetchone()[0]
        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        os.makedirs(os.path.join(base_dir, safe), exist_ok=True)
        flash('Folder created.', 'success')
        return redirect(url_for('upload_radiology_in_folder', folder=safe))
    except Exception as e:
        app.logger.error(f"Error creating folder: {e}")
        flash('Could not create folder.', 'danger')
        return redirect(url_for('patient_radiology_folders'))
    finally:
        cur.close()


@app.route('/patient/radiology/folder/<path:folder>/delete', methods=['POST'])
@login_required
def delete_radiology_folder(folder):
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient_id = cur.fetchone()[0]
        
        # Verify folder belongs to this patient
        cur.execute(
            """
            SELECT COUNT(*) FROM radiology_files 
            WHERE patient_id = %s AND folder = %s
            """,
            (patient_id, folder)
        )
        file_count = cur.fetchone()[0]
        
        # Check if folder exists in filesystem even if no files in DB
        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        folder_dir = os.path.join(base_dir, folder)
        
        if not os.path.exists(folder_dir) and file_count == 0:
            flash('Folder not found.', 'danger')
            return redirect(url_for('patient_radiology_folders'))
        
        # Delete all files from database first
        cur.execute(
            "DELETE FROM radiology_files WHERE patient_id = %s AND folder = %s",
            (patient_id, folder)
        )
        mysql.connection.commit()
        
        # Delete folder directory and all its contents (including all files and SECURED.marker)
        # This handles all files in the folder directory
        if os.path.exists(folder_dir):
            try:
                shutil.rmtree(folder_dir)
                app.logger.info(f"Deleted folder directory and all contents: {folder_dir}")
            except Exception as e:
                app.logger.error(f"Error deleting folder directory {folder_dir}: {e}")
                flash('Error deleting folder directory.', 'warning')
        
        flash(f'Folder "{folder}" and all its contents have been deleted successfully.', 'success')
        app.logger.info(f"Deleted radiology folder '{folder}' (Patient ID: {patient_id})")
        
        return redirect(url_for('patient_radiology_folders'))
    except Exception as e:
        app.logger.error(f"Error deleting radiology folder: {e}")
        flash('An error occurred while deleting the folder.', 'danger')
        return redirect(url_for('patient_radiology_folders'))
    finally:
        cur.close()


@app.route('/patient/radiology/folder/<path:folder>', methods=['GET', 'POST'])
@login_required
def upload_radiology_in_folder(folder):
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient_id = cur.fetchone()[0]
        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        user_dir = os.path.join(base_dir, folder)
        os.makedirs(user_dir, exist_ok=True)

        if request.method == 'POST':
            files = request.files.getlist('files')
            image_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tif', 'tiff'}
            for file in files:
                if not file or not file.filename:
                    continue
                safe_name = secure_filename(file.filename)
                ext = safe_name.rsplit('.', 1)[-1].lower() if '.' in safe_name else ''
                stored_name = f"{int(datetime.now().timestamp())}_{safe_name}"
                stored_path = os.path.join(user_dir, stored_name)
                temp_path = stored_path + '.tmp'
                file.save(temp_path)
                # Security check
                if not _is_file_safe(temp_path, ext):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                    flash(f'Upload blocked: {safe_name} failed integrity checks.', 'danger')
                    continue
                # Watermark and save final file
                if ext in image_extensions:
                    _watermark_image(temp_path, stored_path, text='SECURE HEALTH')
                else:
                    # If PDF, pre-watermark the stored copy so previews/downloads are branded
                    if ext == 'pdf':
                        _watermark_pdf(temp_path, stored_path, text='SECURE HEALTH')
                    else:
                        os.replace(temp_path, stored_path)
                try:
                    # Analyze if image
                    tumor_detected = None
                    confidence = None
                    analysis_date = None
                    if ext in image_extensions:
                        try:
                            result, conf = analyze_mri_image(stored_path)
                            tumor_detected = result
                            confidence = conf
                            analysis_date = datetime.now()
                            app.logger.info(f"MRI analysis completed: {result}, confidence: {conf}")
                        except Exception as e:
                            app.logger.error(f"MRI analysis failed: {e}")

                    cur.execute(
                        """
                        INSERT INTO radiology_files (patient_id, original_filename, stored_filename, file_type, tumor_detected, confidence, analysis_date, folder)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (patient_id, file.filename, os.path.join(folder, stored_name), ext, tumor_detected, confidence, analysis_date, folder)
                    )
                    mysql.connection.commit()
                    # Mark folder as secured after successful clean upload
                    try:
                        with open(os.path.join(user_dir, 'SECURED.marker'), 'w', encoding='utf-8') as m:
                            m.write('secured')
                    except Exception:
                        pass
                finally:
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except Exception:
                        pass
            # Redirect back to same folder after uploads
            return redirect(url_for('upload_radiology_in_folder', folder=folder))

        # List files in this folder
        cur.execute(
            """
            SELECT id, original_filename, stored_filename, file_type, uploaded_at, tumor_detected, confidence, analysis_date
            FROM radiology_files
            WHERE patient_id = %s AND folder = %s
            ORDER BY uploaded_at DESC
            """,
            (patient_id, folder)
        )
        rows = cur.fetchall()
        files = [
            {
                'id': r[0],
                'original_filename': r[1],
                'stored_filename': r[2],
                'file_type': r[3],
                'uploaded_at': r[4],
                'tumor_detected': r[5],
                'confidence': float(r[6]) if r[6] else None,
                'analysis_date': r[7]
            } for r in rows
        ]

        return render_template('patient_radiology.html', files=files, folder=folder)
    except Exception as e:
        app.logger.error(f"Error in folder view: {e}")
        flash('An error occurred while processing radiology files.', 'danger')
        return redirect(url_for('patient_radiology_folders'))
    finally:
        cur.close()


@app.route('/patient/radiology/folder/<path:folder>/download')
@login_required
def download_radiology_folder(folder):
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient_id = cur.fetchone()[0]
        base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        folder_dir = os.path.join(base_dir, folder)
        if not os.path.isdir(folder_dir):
            flash('Folder not found.', 'danger')
            return redirect(url_for('patient_radiology_folders'))

        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            cur.execute(
                """
                SELECT original_filename, stored_filename, file_type
                FROM radiology_files
                WHERE patient_id = %s AND folder = %s
                """,
                (patient_id, folder)
            )
            for original_name, stored_name, file_type in cur.fetchall():
                try:
                    full_path = os.path.join(base_dir, stored_name)
                    if not os.path.exists(full_path):
                        continue
                    safe_name = original_name or os.path.basename(stored_name)
                    arcname = os.path.join(folder, safe_name)
                    if (file_type or '').lower() == 'pdf':
                        tmp_out = full_path + '.wm.pdf'
                        _watermark_pdf(full_path, tmp_out, text='SECURE HEALTH')
                        if os.path.exists(tmp_out):
                            zf.write(tmp_out, arcname=arcname)
                            os.remove(tmp_out)
                        else:
                            zf.write(full_path, arcname=arcname)
                    else:
                        zf.write(full_path, arcname=arcname)
                except Exception as e:
                    app.logger.warning(f"Skipping file in zip due to error: {e}")

            # Add marker file if exists
            if os.path.exists(os.path.join(folder_dir, 'SECURED.marker')):
                zf.writestr(os.path.join(folder, 'SECURED.marker'), 'secured')

        mem_zip.seek(0)
        return send_file(mem_zip, as_attachment=True, download_name=f'{folder}.zip', mimetype='application/zip')
    except Exception as e:
        app.logger.error(f"Error zipping folder: {e}")
        flash('Could not download folder.', 'danger')
        return redirect(url_for('patient_radiology_folders'))
    finally:
        cur.close()


@app.route('/patient/radiology/view/<int:file_id>')
@login_required
def view_radiology(file_id):
    """View/display radiology images"""
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            """
            SELECT rf.stored_filename, rf.original_filename, rf.patient_id, rf.file_type
            FROM radiology_files rf
            JOIN users u ON rf.patient_id = u.id
            WHERE rf.id = %s AND u.username = %s
            """,
            (file_id, session['username'])
        )
        row = cur.fetchone()
        if not row:
            flash('File not found.', 'danger')
            return redirect(url_for('patient_radiology'))

        stored_name, original_name, patient_id, file_type = row
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        path = os.path.join(user_dir, stored_name)
        if not os.path.exists(path):
            flash('File missing on server.', 'danger')
            return redirect(url_for('patient_radiology'))

        # Determine MIME type
        mime_types = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'bmp': 'image/bmp',
            'tif': 'image/tiff',
            'tiff': 'image/tiff',
            'pdf': 'application/pdf'
        }
        mimetype = mime_types.get(file_type.lower(), 'application/octet-stream')
        
        # If raw=1, always stream the file itself
        if request.args.get('raw') == '1':
            resp = send_file(path, mimetype=mimetype, as_attachment=False, download_name=original_name, conditional=True)
            # Force inline display for PDF-capable browsers
            try:
                resp.headers['Content-Disposition'] = f'inline; filename="{original_name}"'
                resp.headers['Cache-Control'] = 'private, max-age=0, must-revalidate'
                resp.headers['Pragma'] = 'no-cache'
                resp.headers['Accept-Ranges'] = 'bytes'
            except Exception:
                pass
            return resp

        # For PDFs without raw, render an embedded viewer that loads the raw file
        if (file_type or '').lower() == 'pdf':
            return render_template('radiology_pdf_viewer.html', file_url=url_for('view_radiology', file_id=file_id, raw=1), download_url=url_for('download_radiology', file_id=file_id))
        return send_file(path, mimetype=mimetype)
    finally:
        cur.close()

@app.route('/patient/radiology/download/<int:file_id>')
@login_required
def download_radiology(file_id):
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            """
            SELECT rf.stored_filename, rf.original_filename, rf.patient_id, rf.file_type
            FROM radiology_files rf
            JOIN users u ON rf.patient_id = u.id
            WHERE rf.id = %s AND u.username = %s
            """,
            (file_id, session['username'])
        )
        row = cur.fetchone()
        if not row:
            flash('File not found.', 'danger')
            return redirect(url_for('patient_radiology'))

        stored_name, original_name, patient_id, file_type = row
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        path = os.path.join(user_dir, stored_name)
        if not os.path.exists(path):
            flash('File missing on server.', 'danger')
            return redirect(url_for('patient_radiology'))

        # Watermark PDFs on download
        if (file_type or '').lower() == 'pdf':
            tmp_out = path + '.wm.pdf'
            _watermark_pdf(path, tmp_out, text='SECURED')
            try:
                return send_file(tmp_out, as_attachment=True, download_name=original_name)
            finally:
                try:
                    if os.path.exists(tmp_out):
                        os.remove(tmp_out)
                except Exception:
                    pass
        else:
            return send_file(path, as_attachment=True, download_name=original_name)
    finally:
        cur.close()

@app.route('/patient/radiology/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_radiology_file(file_id):
    if session.get('role') != 'patient':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        cur.execute(
            """
            SELECT rf.stored_filename, rf.original_filename, rf.patient_id, rf.folder
            FROM radiology_files rf
            JOIN users u ON rf.patient_id = u.id
            WHERE rf.id = %s AND u.username = %s
            """,
            (file_id, session['username'])
        )
        row = cur.fetchone()
        if not row:
            flash('File not found or you do not have permission to delete it.', 'danger')
            return redirect(url_for('patient_radiology_folders'))

        stored_name, original_name, patient_id, folder = row
        
        # Delete file from filesystem
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'radiology', str(patient_id))
        path = os.path.join(user_dir, stored_name)
        if os.path.exists(path):
            try:
                os.remove(path)
                app.logger.info(f"Deleted radiology file from filesystem: {path}")
            except Exception as e:
                app.logger.error(f"Error deleting file from filesystem {path}: {e}")
                flash('Error deleting file from filesystem.', 'danger')
                return redirect(url_for('upload_radiology_in_folder', folder=folder) if folder else url_for('patient_radiology_folders'))

        # Delete from database
        cur.execute("DELETE FROM radiology_files WHERE id = %s", (file_id,))
        mysql.connection.commit()
        
        flash('File deleted successfully.', 'success')
        app.logger.info(f"Deleted radiology file {original_name} (ID: {file_id}) from database")
        
        # Redirect back to folder view if folder exists, otherwise to folders list
        if folder:
            return redirect(url_for('upload_radiology_in_folder', folder=folder))
        else:
            return redirect(url_for('patient_radiology_folders'))
    except Exception as e:
        app.logger.error(f"Error deleting radiology file: {e}")
        flash('An error occurred while deleting the file.', 'danger')
        return redirect(url_for('patient_radiology_folders'))
    finally:
        cur.close()

@app.route('/doctor/signed-records')
@login_required
def doctor_signed_records():
    if session.get('role') != 'doctor':
        flash('Access denied. Doctor role required.', 'danger')
        return redirect(url_for('home'))

    # Filters
    patient = request.args.get('patient', '').strip()
    date = request.args.get('date', '').strip()  # YYYY-MM-DD

    cur = mysql.connection.cursor()
    try:
        # Get doctor id
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        row = cur.fetchone()
        if not row:
            flash('Doctor record not found.', 'danger')
            return redirect(url_for('home'))
        doctor_id = row[0]

        query = (
            """
            SELECT mr.id,
                   mr.signature_time,
                   mr.record_date,
                   mr.diagnosis,
                   mr.treatment,
                   mr.record_hash,
                   CONCAT(p.first_name, ' ', p.last_name) AS patient_name
            FROM medical_records mr
            JOIN users p ON mr.patient_id = p.id
            WHERE mr.signed_by = %s
            """
        )
        params = [doctor_id]

        if patient:
            query += " AND (p.first_name LIKE %s OR p.last_name LIKE %s OR CONCAT(p.first_name, ' ', p.last_name) LIKE %s)"
            like = f"%{patient}%"
            params.extend([like, like, like])

        if date:
            query += " AND DATE(mr.signature_time) = %s"
            params.append(date)

        query += " ORDER BY mr.signature_time DESC, mr.id DESC"

        cur.execute(query, tuple(params))
        rows = cur.fetchall()

        # Group by date(signature_time)
        groups = {}
        for r in rows:
            record_id = r[0]
            signed_at = r[1]
            group_key = signed_at.date() if signed_at else None
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append({
                'id': record_id,
                'signed_at': signed_at,
                'record_date': r[2],
                'diagnosis': r[3],
                'treatment': r[4],
                'record_hash': r[5],
                'patient_name': r[6]
            })

        # Sort groups newest first
        sorted_groups = sorted(groups.items(), key=lambda kv: (kv[0] is None, kv[0]), reverse=True)

        return render_template(
            'doctor_signed_records.html',
            groups=sorted_groups,
            patient_filter=patient,
            date_filter=date
        )
    finally:
        cur.close()

@app.route('/view_medical_record/<int:record_id>')
@login_required
def view_medical_record(record_id):
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        # Get medical record details
        cur.execute("""
            SELECT mr.id, mr.record_date, mr.notes, mr.diagnosis, mr.treatment,
                   CONCAT(u.first_name, ' ', u.last_name) as doctor_name,
                   u.specialization
            FROM medical_records mr
            JOIN users u ON mr.doctor_id = u.id
            WHERE mr.id = %s AND mr.patient_id = %s
        """, (record_id, patient_id))
        record = cur.fetchone()

        if not record:
            flash('Medical record not found or you do not have access.', 'danger')
            return redirect(url_for('patient_dashboard'))

        # Transform record tuple into a dictionary
        record_dict = {
            'id': record[0],
            'date': record[1],
            'description': record[2],
            'diagnosis': record[3],
            'treatment': record[4],
            'doctor_name': record[5],
            'specialization': record[6]
        }

        # Log the view action
        log_action(
            session['username'],
            'view_medical_record',
            f"Viewed medical record ID {record_id}"
        )

        return render_template('view_medical_record.html', record=record_dict)

    except Exception as e:
        app.logger.error(f"Error in view_medical_record: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the medical record.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()

@app.route('/view_appointment/<int:appointment_id>')
@login_required
def view_appointment(appointment_id):
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]
        # Get appointment details
        cur.execute("""
            SELECT a.id, a.appointment_date, a.status, a.reason,
                CONCAT(u.first_name, ' ', u.last_name) as doctor_name,
                u.specialization
            FROM appointments a
            JOIN users u ON a.doctor_id = u.id
            WHERE a.id = %s AND a.patient_id = %s
        """, (appointment_id, patient_id))
        appointment = cur.fetchone()

        if not appointment:
            flash('Appointment not found or you do not have access.', 'danger')
            return redirect(url_for('patient_appointments'))

        # Transform appointment tuple into a dictionary
        appointment_dict = {
            'id': appointment[0],
            'appointment_date': appointment[1],
            'status': appointment[2],
            'reason': appointment[3],
            'doctor_name': appointment[4],
            'specialization': appointment[5]
        }

        return render_template('view_appointment.html', appointment=appointment_dict)
    except Exception as e:
        app.logger.error(f"Error in view_appointment: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the appointment.', 'danger')
        return redirect(url_for('patient_appointments'))
    finally:
        cur.close()


@app.route('/cancel_appointment/<int:appointment_id>', methods=['POST','GET'])
@login_required
def cancel_appointment(appointment_id):
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        # Verify appointment exists and belongs to the patient
        cur.execute("""
            SELECT id, status FROM appointments
            WHERE id = %s AND patient_id = %s
        """, (appointment_id, patient_id))
        appointment = cur.fetchone()

        if not appointment:
            flash('Appointment not found or you do not have access.', 'danger')
            return redirect(url_for('patient_appointments'))

        if appointment[1] == 'cancelled':
            flash('Appointment is already cancelled.', 'warning')
            return redirect(url_for('patient_appointments'))

        # Update appointment status to cancelled
        cur.execute("""
            UPDATE appointments
            SET status = 'cancelled'
            WHERE id = %s
        """, (appointment_id,))
        mysql.connection.commit()

        # Log the cancellation
        log_action(
            session['username'],
            'appointment_cancel',
            f"Cancelled appointment ID {appointment_id}"
        )

        flash('Appointment cancelled successfully.', 'success')
        return redirect(url_for('patient_appointments'))

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error in cancel_appointment: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while cancelling the appointment.', 'danger')
        return redirect(url_for('patient_appointments'))
    finally:
        cur.close()


@app.route('/patient/medical-records')
@login_required
def patient_medical_records():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        cur.execute("""
            SELECT mr.id, mr.record_date, mr.diagnosis, mr.treatment,
                   CONCAT(u.first_name, ' ', u.last_name) as doctor_name,
                   u.specialization,
                   (mr.signature IS NOT NULL) AS signed
            FROM medical_records mr
            JOIN users u ON mr.doctor_id = u.id
            WHERE mr.patient_id = %s
            ORDER BY mr.record_date DESC
        """, (patient_id,))
        records = cur.fetchall()

    # Transform records into a list of dictionaries
        records_list = [
            {
                'id': record[0],
                'date': record[1],  # Maps record_date to date for template
                'diagnosis': record[2],
                'treatment': record[3],
                'doctor_name': record[4],
                'specialization': record[5],
                'signed': bool(record[6])
            } for record in records
        ]

        return render_template('patient_medical_records.html', records=records_list)
    except Exception as e:
        app.logger.error(f"Error in patient medical records: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading medical records.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()

@app.route('/patient/profile', methods=['GET', 'POST'])
@login_required
def patient_profile():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()

    try:
        # Get patient information
        cur.execute("""
            SELECT id, username, email, first_name, last_name, phone,
                   date_of_birth, gender, blood_type, emergency_contact,
                   emergency_phone
            FROM users
            WHERE username = %s
        """, (session['username'],))
        patient = cur.fetchone()

        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))

        if request.method == 'POST':
            # Update patient information
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone = request.form.get('phone')
            date_of_birth = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            blood_type = request.form.get('blood_type')
            emergency_contact = request.form.get('emergency_contact')
            emergency_phone = request.form.get('emergency_phone')

            # In patient_profile POST handler, ensure gender is 'M', 'F', or 'O'
            if gender not in ['M', 'F', 'O']:
                flash('Invalid gender selected.', 'danger')
                return redirect(url_for('patient_profile'))

            cur.execute("""
                UPDATE users
                SET first_name = %s,
                    last_name = %s,
                    phone = %s,
                    date_of_birth = %s,
                    gender = %s,
                    blood_type = %s,
                    emergency_contact = %s,
                    emergency_phone = %s
                WHERE id = %s
            """, (first_name, last_name, phone, date_of_birth, gender,
                  blood_type, emergency_contact, emergency_phone, patient[0]))
            mysql.connection.commit()

            flash('Profile updated successfully.', 'success')
            return redirect(url_for('patient_profile'))

        # Format patient data for template
        patient_data = {
            'id': patient[0],
            'username': patient[1],
            'email': patient[2],
            'first_name': patient[3],
            'last_name': patient[4],
            'phone': patient[5],
            'date_of_birth': patient[6],
            'gender': patient[7],
            'blood_type': patient[8],
            'emergency_contact': patient[9],
            'emergency_phone': patient[10]
        }

        return render_template('patient_profile.html',
                             patient=patient_data)

    except Exception as e:
        app.logger.error(f"Error in patient profile: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the profile.', 'danger')
        return redirect(url_for('patient_dashboard'))
    finally:
        cur.close()

@app.route('/patient/schedule-appointment', methods=['POST'])
@login_required
def schedule_appointment():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))

    doctor_id = request.form.get('doctor_id')
    appointment_date = request.form.get('appointment_date')
    reason = request.form.get('reason')

    if not doctor_id or not appointment_date or not reason:
        flash('All fields are required to schedule an appointment.', 'danger')
        return redirect(url_for('patient_appointments'))

    cur = mysql.connection.cursor()
    try:
        # Get patient ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        patient = cur.fetchone()
        if not patient:
            flash('Patient record not found.', 'danger')
            return redirect(url_for('logout'))
        patient_id = patient[0]

        # Insert new appointment
        cur.execute("""
            INSERT INTO appointments (patient_id, doctor_id, appointment_date, status, reason)
            VALUES (%s, %s, %s, 'scheduled', %s)
        """, (patient_id, doctor_id, appointment_date, reason))
        
        # Ensure doctor-patient assignment exists
        try:
            cur.execute(
                """
                INSERT INTO doctor_patient_assignments (doctor_id, patient_id)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE status = VALUES(status)
                """,
                (doctor_id, patient_id)
            )
        except Exception:
            # If table or constraint not present, continue without blocking scheduling
            pass
        mysql.connection.commit()
        flash('Appointment scheduled successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error scheduling appointment: {str(e)}")
        flash('An error occurred while scheduling the appointment.', 'danger')
    finally:
        cur.close()
    return redirect(url_for('patient_appointments'))

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if session.get('role') != 'doctor':
        flash('Access denied. Doctor role required.', 'danger')
        return redirect(url_for('home'))

    cur = mysql.connection.cursor()
    try:
        # Get doctor ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        doctor = cur.fetchone()
        if not doctor:
            flash('Doctor record not found.', 'danger')
            return redirect(url_for('logout'))
        doctor_id = doctor[0]

        # Get today's appointments
        cur.execute("""
            SELECT a.id, a.appointment_date, a.status, a.reason,
                   CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                   p.phone as patient_phone,
                   p.blood_type
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            AND DATE(a.appointment_date) = CURDATE()
            ORDER BY a.appointment_date ASC
        """, (doctor_id,))
        today_appointments = cur.fetchall()

        # Get upcoming appointments
        cur.execute("""
            SELECT a.id, a.appointment_date, a.status, a.reason,
                   CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                   p.phone as patient_phone,
                   p.blood_type
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            AND DATE(a.appointment_date) > CURDATE()
            ORDER BY a.appointment_date ASC
            LIMIT 5
        """, (doctor_id,))
        upcoming_appointments = cur.fetchall()

        # Get recent medical records
        cur.execute("""
            SELECT mr.id, mr.record_date, mr.diagnosis, mr.treatment,
                   CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                   p.blood_type,
                   (mr.signature IS NOT NULL) AS signed
            FROM medical_records mr
            JOIN users p ON mr.patient_id = p.id
            WHERE mr.doctor_id = %s
            ORDER BY mr.record_date DESC
            LIMIT 5
        """, (doctor_id,))
        recent_records = cur.fetchall()

        # Get patient statistics
        cur.execute("""
            SELECT
                COUNT(DISTINCT a.patient_id) as total_patients,
                COUNT(CASE WHEN a.status = 'scheduled' THEN 1 END) as scheduled_appointments,
                COUNT(CASE WHEN a.status = 'completed' THEN 1 END) as completed_appointments
            FROM appointments a
            WHERE a.doctor_id = %s
        """, (doctor_id,))
        stats = cur.fetchone()

        # Get list of all patients for medical record form
        cur.execute("""
            SELECT DISTINCT p.id, CONCAT(p.first_name, ' ', p.last_name) as patient_name
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            ORDER BY p.last_name, p.first_name
        """, (doctor_id,))
        patients = cur.fetchall()

        # Format appointments for template
        def format_appointments(appointments):
            formatted = []
            for appt in appointments:
                status_color = {
                    'scheduled': 'primary',
                    'completed': 'success',
                    'cancelled': 'danger',
                    'no_show': 'warning'
                }.get(appt[2], 'secondary')

                formatted.append({
                    'id': appt[0],
                    'date': appt[1],
                    'status': appt[2],
                    'status_color': status_color,
                    'reason': appt[3],
                    'patient_name': appt[4],
                    'patient_phone': appt[5],
                    'blood_type': appt[6]
                })
            return formatted

        # Format medical records for template
        def format_records(records):
            formatted = []
            for record in records:
                formatted.append({
                    'id': record[0],
                    'date': record[1],
                    'diagnosis': record[2],
                    'treatment': record[3],
                    'patient_name': record[4],
                    'blood_type': record[5],
                    'signed': bool(record[6])
                })
            return formatted

        signed_record_id = session.pop('signed_record_id', None)

        return render_template('doctor_dashboard.html',
                             today_appointments=format_appointments(today_appointments),
                             upcoming_appointments=format_appointments(upcoming_appointments),
                             recent_records=format_records(recent_records),
                             patients=patients,
                             signed_record_id=signed_record_id,
                             stats={
                                 'total_patients': stats[0],
                                 'scheduled_appointments': stats[1],
                                 'completed_appointments': stats[2]
                             })

    except Exception as e:
        app.logger.error(f"Error in doctor dashboard: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('home'))
    finally:
        cur.close()

@app.route('/doctor/appointments')
@login_required
def doctor_appointments():
    if session.get('role') != 'doctor':
        flash('Access denied. Please log in as a doctor.', 'danger')
        return redirect(url_for('home'))

    # Get filter parameters
    status = request.args.get('status', '')
    date = request.args.get('date', '')
    patient = request.args.get('patient', '')

    cur = mysql.connection.cursor()
    try:
        # Get doctor ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        doctor = cur.fetchone()
        if not doctor:
            app.logger.error(f"Doctor not found for username: {session['username']}")
            flash('Doctor record not found.', 'danger')
            return redirect(url_for('logout'))
        doctor_id = doctor[0]
        app.logger.info(f"Found doctor_id: {doctor_id} for username: {session['username']}")

        # Build the query
        query = """
            SELECT a.id, a.appointment_date, a.status, a.reason,
                   CONCAT(u.first_name, ' ', u.last_name) as patient_name,
                   u.phone as patient_phone,
                   u.blood_type
            FROM appointments a
            JOIN users u ON a.patient_id = u.id
            WHERE a.doctor_id = %s
        """
        params = [doctor_id]

        if status:
            query += " AND a.status = %s"
            params.append(status)
        if date:
            query += " AND DATE(a.appointment_date) = %s"
            params.append(date)
        if patient:
            query += " AND (u.first_name LIKE %s OR u.last_name LIKE %s)"
            params.extend([f'%{patient}%', f'%{patient}%'])

        query += " ORDER BY a.appointment_date DESC"
        
        app.logger.info(f"Executing query: {query}")
        app.logger.info(f"With parameters: {params}")

        cur.execute(query, params)
        appointments = cur.fetchall()
        app.logger.info(f"Found {len(appointments)} appointments")

        # Convert appointments to list of dicts with status colors
        appointments_list = []
        for appt in appointments:
            try:
                appt_dict = {
                    'id': appt[0],
                    'date': appt[1],
                    'status': appt[2],
                    'reason': appt[3],
                    'patient_name': appt[4],
                    'patient_phone': appt[5],
                    'blood_type': appt[6]
                }

                # Add status color
                status_colors = {
                    'scheduled': 'primary',
                    'completed': 'success',
                    'cancelled': 'danger',
                    'no_show': 'warning'
                }
                appt_dict['status_color'] = status_colors.get(appt[2], 'secondary')

                appointments_list.append(appt_dict)
            except Exception as e:
                app.logger.error(f"Error processing appointment: {str(e)}")
                app.logger.error(f"Appointment data: {appt}")

        return render_template('doctor_appointments.html', appointments=appointments_list)

    except Exception as e:
        app.logger.error(f"Error in doctor_appointments: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
        app.logger.error(f"Session data: {dict(session)}")
        flash('An error occurred while fetching appointments.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    finally:
        cur.close()

@app.route('/doctor/appointments/<int:appointment_id>/update', methods=['POST'])
def update_appointment(appointment_id):
    if 'username' not in session or session.get('role') != 'doctor':
        # flash('Access denied. Please log in as a doctor.', 'danger')
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    valid_statuses = ['scheduled', 'completed', 'cancelled', 'no_show']
    if not new_status or new_status not in valid_statuses:
        flash('Invalid status value.', 'danger')
        return redirect(url_for('doctor_appointments'))

    cursor = mysql.connection.cursor()

    try:
        # Get doctor ID
        cursor.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        doctor = cursor.fetchone()
        if not doctor:
            flash('Doctor not found.', 'danger')
            return redirect(url_for('logout'))
        doctor_id = doctor[0]

        # Check if appointment exists and belongs to the doctor
        cursor.execute(
            "SELECT COUNT(*) FROM appointments WHERE id = %s AND doctor_id = %s",
            (appointment_id, doctor_id)
        )
        if cursor.fetchone()[0] == 0:
            flash('Appointment not found or you are not authorized to update it.', 'danger')
            return redirect(url_for('doctor_appointments'))

        # Update appointment status
        cursor.execute(
            "UPDATE appointments SET status = %s WHERE id = %s AND doctor_id = %s",
            (new_status, appointment_id, doctor_id)
        )
        if cursor.rowcount == 0:
            flash('No changes made to the appointment.', 'warning')
        else:
            mysql.connection.commit()
            flash('Appointment status updated successfully.', 'success')
            log_action(
                session['username'],
                'update_appointment',
                f"Updated appointment {appointment_id} status to {new_status}"
            )
            app.logger.info(f"Updated appointment ID {appointment_id} to status {new_status} for doctor ID {doctor_id}")

    except Exception as e:
        mysql.connection.rollback()
        flash('An error occurred while updating the appointment.', 'danger')
        app.logger.error(f"Error in update_appointment: {str(e)}")
        app.logger.error(f"Error details: {traceback.format_exc()}")
    finally:
        cursor.close()

    return redirect(url_for('doctor_appointments'))

@app.route('/doctor/add-medical-record', methods=['POST'])
@login_required
def add_medical_record():
    if session.get('role') != 'doctor':
        flash('Access denied. Doctor role required.', 'danger')
        return redirect(url_for('home'))

    patient_id = request.form.get('patient_id')
    diagnosis = request.form.get('diagnosis')
    treatment = request.form.get('treatment')
    action = request.form.get('action')  # normal add or sign_and_add

    if not all([patient_id, diagnosis, treatment]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('doctor_dashboard'))

    cur = mysql.connection.cursor()
    try:
        # Get doctor ID
        cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
        doctor = cur.fetchone()
        if not doctor:
            flash('Doctor record not found.', 'danger')
            return redirect(url_for('logout'))
        doctor_id = doctor[0]

        # Add medical record
        cur.execute(
            """
            INSERT INTO medical_records (patient_id, doctor_id, diagnosis, treatment, record_date)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (patient_id, doctor_id, diagnosis, treatment)
        )
        record_id = cur.lastrowid

        # If requested, sign the newly created record using doctor's private key
        if action == 'sign_and_add':
            # Fetch private key
            cur.execute("SELECT private_key FROM users WHERE id = %s", (doctor_id,))
            row = cur.fetchone()
            private_key_pem = row[0] if row else None

            if not private_key_pem:
                # Auto-generate RSA key pair for the doctor and persist
                try:
                    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    private_pem = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    public_pem = key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    cur.execute(
                        "UPDATE users SET private_key = %s, public_key = %s WHERE id = %s",
                        (private_pem.decode('utf-8'), public_pem.decode('utf-8'), doctor_id)
                    )
                    private_key_pem = private_pem.decode('utf-8')
                except Exception as e:
                    app.logger.error(f"Failed to generate RSA keys for doctor {doctor_id}: {e}")
                    flash('Could not create signing keys for your account.', 'danger')
                    mysql.connection.commit()
                    return redirect(url_for('doctor_dashboard'))
            
            # If we reach here we have a private key
            if private_key_pem:
                # Build deterministic record payload and hash
                payload = f"{patient_id}|{doctor_id}|{diagnosis}|{treatment}"
                record_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

                try:
                    signature_bytes = sign_document_util(record_hash.encode('utf-8'), private_key_pem)
                    cur.execute(
                        """
                        UPDATE medical_records
                        SET signature = %s,
                            signature_time = CURRENT_TIMESTAMP,
                            signed_by = %s,
                            record_hash = %s
                        WHERE id = %s
                        """,
                        (signature_bytes, doctor_id, record_hash, record_id)
                    )
                    session['signed_record_id'] = record_id
                    flash('Record saved and signed successfully.', 'success')
                except Exception as e:
                    app.logger.error(f"Error signing medical record {record_id}: {e}")
                    flash('Record added but signing failed.', 'warning')

        mysql.connection.commit()

        flash('Medical record added successfully.', 'success')
        log_action(session['username'], 'add_medical_record',
                  f'Added medical record for patient ID {patient_id}')

    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error adding medical record: {str(e)}")
        flash('An error occurred while adding the medical record.', 'danger')
    finally:
        cur.close()

    return redirect(url_for('doctor_dashboard'))


# View medical record signature
@app.route('/medical-records/<int:record_id>/signature')
@login_required
def view_medical_record_signature(record_id):
    cur = mysql.connection.cursor()
    try:
        # Doctors can view signatures of their records; patients can view their own
        cur.execute(
            """
            SELECT mr.id, mr.patient_id, mr.doctor_id, mr.record_date, mr.diagnosis, mr.treatment,
                   mr.signature, mr.signature_time, mr.record_hash,
                   du.username as doctor_username, pu.username as patient_username
            FROM medical_records mr
            JOIN users du ON mr.doctor_id = du.id
            JOIN users pu ON mr.patient_id = pu.id
            WHERE mr.id = %s
            """,
            (record_id,)
        )
        row = cur.fetchone()
        if not row:
            flash('Medical record not found.', 'danger')
            return redirect(url_for('home'))

        # Authorization
        username = session.get('username')
        role = session.get('role')
        if role == 'doctor' and username != row[9] and role != 'admin':
            flash('Access denied.', 'danger')
            return redirect(url_for('home'))
        if role == 'patient' and username != row[10] and role != 'admin':
            flash('Access denied.', 'danger')
            return redirect(url_for('home'))

        signature_present = bool(row[6])
        return render_template(
            'view_medical_record_signature.html',
            signed=signature_present,
            record={
                'id': row[0],
                'date': row[3],
                'diagnosis': row[4],
                'treatment': row[5],
                'record_hash': row[8],
                'doctor_username': row[9],
                'patient_username': row[10],
                'signature_time': row[7]
            }
        )
    finally:
        cur.close()


@app.route('/medical-records/<int:record_id>/download-signature')
@login_required
def download_medical_record_signature(record_id):
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT signature FROM medical_records WHERE id = %s", (record_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            flash('Signature not found for this record.', 'danger')
            return redirect(url_for('home'))

        sig_bytes = row[0]
        return send_file(
            io.BytesIO(sig_bytes),
            as_attachment=True,
            download_name=f"medical_record_{record_id}.sig",
            mimetype='application/octet-stream'
        )
    finally:
        cur.close()

if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )
