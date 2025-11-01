"""
Example Integration of Security Module into app.py
Add these imports and initialization code to your app.py
"""

# =====================================================
# ADD TO IMPORTS SECTION (after existing imports)
# =====================================================

from security_module import (
    validator, csrf_protection, rate_limiter, audit_logger,
    access_control, session_security, encryption
)
from security_integration import (
    secure_login_required,
    secure_admin_required,
    secure_patient_access,
    validate_form_input,
    validate_file_upload,
    get_patient_data_safely,
    init_security
)

# =====================================================
# ADD AFTER APP CONFIGURATION (after line 108)
# =====================================================

# Initialize security module
init_security(app, mysql)

# Update session configuration for production
if os.getenv('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Stricter CSRF protection

# =====================================================
# UPDATE BEFORE_REQUEST (replace existing before_request)
# =====================================================

@app.before_request
def before_request():
    """Enhanced security before each request"""
    from flask import g
    g.mysql = mysql
    
    # Allow certain endpoints without full security check
    allowed_endpoints = [
        'login', 'register', 'qr_page', 'show_qr', 'two_factor',
        'google.login', 'google.authorized', 'github.login', 'github.authorized',
        'google_login', 'static'
    ]
    
    if request.endpoint in allowed_endpoints or request.endpoint is None:
        return
    
    # Validate session for authenticated users
    if 'username' in session:
        if not session_security.validate_session(mysql):
            session.clear()
            flash('Your session has expired. Please log in again', 'warning')
            return redirect(url_for('login'))
        
        # Generate CSRF token if missing
        if 'csrf_token' not in session:
            session['csrf_token'] = csrf_protection.generate_token()

# =====================================================
# UPDATE LOGIN ROUTE (add rate limiting and audit logging)
# =====================================================

@app.route('/login', methods=['GET', 'POST'])
@rate_limiter.rate_limit(action='login', max_attempts=5)
def login():
    if is_logged_in():
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        
        # Validate input
        is_valid, error = validator.validate_username(username)
        if not is_valid:
            rate_limiter.record_attempt(ip_address, 'login', False)
            audit_logger.log_security_event(
                user_id=None,
                username=username,
                event_type='login',
                action='invalid_username',
                success=False
            )
            flash(error or 'Invalid username format', 'danger')
            return redirect(url_for('login'))
        
        # Check rate limiting
        allowed, message = rate_limiter.is_allowed(ip_address, 'login')
        if not allowed:
            flash(message, 'danger')
            return redirect(url_for('login'))
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT id, username, email, password, 2fa_secret, role, first_name, last_name FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user and bcrypt.check_password_hash(user[3], password):
                # Password correct - proceed to 2FA
                session['pre_2fa_user'] = user[1]
                rate_limiter.record_attempt(ip_address, 'login', True)
                audit_logger.log_security_event(
                    user_id=user[0],
                    username=username,
                    event_type='login',
                    action='password_verified',
                    success=True
                )
                return redirect(url_for('two_factor'))
            else:
                # Invalid credentials
                rate_limiter.record_attempt(ip_address, 'login', False)
                audit_logger.log_security_event(
                    user_id=None,
                    username=username,
                    event_type='login',
                    action='invalid_credentials',
                    success=False
                )
                flash('Invalid username or password', 'danger')
        finally:
            cur.close()
        
        return redirect(url_for('login'))
    
    # Generate CSRF token for login form
    if 'csrf_token' not in session:
        session['csrf_token'] = csrf_protection.generate_token()
    
    return render_template('login.html', csrf_token=session['csrf_token'])

# =====================================================
# UPDATE TWO_FACTOR ROUTE (add rate limiting)
# =====================================================

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))
    
    username = session['pre_2fa_user']
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        # Check rate limiting for 2FA
        ip_address = request.remote_addr
        allowed, message = rate_limiter.is_allowed(f"{ip_address}:2fa", '2fa')
        if not allowed:
            flash(message, 'danger')
            return render_template('2fa.html')
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT id, username, email, 2fa_secret, role, first_name, last_name FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user:
                totp = pyotp.TOTP(user[3])
                if totp.verify(token, valid_window=1):
                    # 2FA successful - create secure session
                    session_security.create_secure_session(user[0], user[1], user[4])
                    rate_limiter.record_attempt(f"{ip_address}:2fa", '2fa', True)
                    audit_logger.log_security_event(
                        user_id=user[0],
                        username=username,
                        event_type='login',
                        action='2fa_success',
                        success=True
                    )
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    rate_limiter.record_attempt(f"{ip_address}:2fa", '2fa', False)
                    audit_logger.log_security_event(
                        user_id=user[0],
                        username=username,
                        event_type='login',
                        action='2fa_failed',
                        success=False
                    )
                    flash('Invalid verification code', 'danger')
        finally:
            cur.close()
    
    return render_template('2fa.html', csrf_token=session.get('csrf_token', ''))

# =====================================================
# UPDATE REGISTER ROUTE (add enhanced validation)
# =====================================================

@app.route('/register', methods=['GET', 'POST'])
@rate_limiter.rate_limit(action='register', max_attempts=3)
def register():
    if request.method == 'POST':
        # Get and validate inputs
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validate username
        is_valid, error = validator.validate_username(username)
        if not is_valid:
            flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Validate email
        is_valid, error = validator.validate_email(email)
        if not is_valid:
            flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Validate password
        is_valid, error = validator.validate_password(password)
        if not is_valid:
            flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Check for SQL injection in other fields
        for field, value in request.form.items():
            if isinstance(value, str) and validator.contains_sql_injection(value):
                audit_logger.log_security_event(
                    user_id=None,
                    username=username,
                    event_type='security_violation',
                    action='sql_injection_attempt',
                    resource=field,
                    success=False
                )
                flash('Invalid input detected', 'danger')
                return redirect(url_for('register'))
        
        # Continue with registration...
        # (rest of registration code)
        
    return render_template('register.html', csrf_token=session.get('csrf_token', ''))

# =====================================================
# UPDATE FILE UPLOAD ROUTE (add secure file validation)
# =====================================================

@app.route('/patient/radiology', methods=['GET', 'POST'])
@secure_login_required
def patient_radiology():
    if session.get('role') != 'patient':
        flash('Access denied. Patient role required.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('patient_radiology'))
        
        file = request.files['file']
        
        # Validate file upload securely
        is_valid, error = validate_file_upload(file, allowed_extensions={'png', 'jpg', 'jpeg', 'pdf'})
        if not is_valid:
            flash(error, 'danger')
            return redirect(url_for('patient_radiology'))
        
        # Continue with file processing...
        # (rest of upload code)
        
    return render_template('patient_radiology.html', csrf_token=session.get('csrf_token', ''))

# =====================================================
# UPDATE PATIENT PROFILE ROUTE (add access control)
# =====================================================

@app.route('/patient/profile/<int:patient_id>')
@secure_login_required
@secure_patient_access
def patient_profile(patient_id):
    # User can only access their own profile (or doctors can access assigned patients)
    
    # Get patient data securely
    patient_data = get_patient_data_safely(mysql, patient_id)
    
    if not patient_data:
        flash('Patient data not found', 'danger')
        return redirect(url_for('home'))
    
    return render_template('patient_profile.html', patient=patient_data)

# =====================================================
# UPDATE ADMIN ROUTE (use secure decorator)
# =====================================================

@app.route('/admin')
@secure_admin_required
def admin_dashboard():
    # Only admins can access
    # (rest of admin dashboard code)
    pass

# =====================================================
# ADD CSRF TOKEN TO TEMPLATES
# =====================================================

# In your templates (base.html or form templates):
# <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

# Or in Flask-WTF style:
# {{ csrf_token() }}

# =====================================================
# UPDATE LOGOUT (add audit logging)
# =====================================================

@app.route('/logout')
def logout():
    username = session.get('username')
    user_id = session.get('user_id')
    
    # Log logout
    if username:
        audit_logger.log_security_event(
            user_id=user_id,
            username=username,
            event_type='logout',
            action='session_ended',
            success=True
        )
    
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

