"""
Security Integration for app.py
Provides easy-to-use security functions and decorators
"""

from security_module import (
    validator, csrf_protection, rate_limiter, audit_logger,
    access_control, session_security, encryption, InputValidator
)
from security_middleware import (
    add_security_headers, validate_request, monitor_request, log_request_time
)
from functools import wraps
from flask import session, request, abort, jsonify, flash, redirect, url_for
from flask_mysqldb import MySQL
import logging

logger = logging.getLogger(__name__)

# =====================================================
# ENHANCED DECORATORS
# =====================================================

def secure_login_required(f):
    """Enhanced login required with session validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import g
        if not session.get('username'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        
        # Validate session
        mysql_conn = g.mysql if hasattr(g, 'mysql') else None
        if mysql_conn and not session_security.validate_session(mysql_conn):
            session.clear()
            flash('Your session has expired. Please log in again', 'warning')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def secure_admin_required(f):
    """Enhanced admin required with permission checking"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('username') or session.get('role') != 'admin':
            audit_logger.log_security_event(
                user_id=session.get('user_id'),
                username=session.get('username'),
                event_type='unauthorized_access',
                action='admin_access_denied',
                success=False
            )
            flash('Admin access required', 'danger')
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

def secure_patient_access(f):
    """Ensure patient can only access their own data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import g
        # Get patient_id from route or session
        patient_id = kwargs.get('patient_id') or session.get('user_id')
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        mysql_conn = g.mysql if hasattr(g, 'mysql') else None
        if not mysql_conn or not access_control.can_access_patient_data(user_id, user_role, patient_id, mysql_conn):
            audit_logger.log_security_event(
                user_id=user_id,
                username=session.get('username'),
                event_type='unauthorized_access',
                action='patient_data_access_denied',
                resource=f'patient:{patient_id}',
                success=False
            )
            flash('Access denied. You do not have permission to access this data.', 'danger')
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

def validate_form_input(f):
    """Validate all form inputs for security"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        for field, value in request.form.items():
            if isinstance(value, str):
                # Check for SQL injection
                if InputValidator.contains_sql_injection(value):
                    audit_logger.log_security_event(
                        user_id=session.get('user_id'),
                        username=session.get('username'),
                        event_type='security_violation',
                        action='sql_injection_attempt',
                        resource=field,
                        success=False
                    )
                    flash('Invalid input detected', 'danger')
                    return redirect(request.referrer or url_for('home'))
                
                # Check for XSS
                if InputValidator.contains_xss(value):
                    audit_logger.log_security_event(
                        user_id=session.get('user_id'),
                        username=session.get('username'),
                        event_type='security_violation',
                        action='xss_attempt',
                        resource=field,
                        success=False
                    )
                    flash('Invalid input detected', 'danger')
                    return redirect(request.referrer or url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

# =====================================================
# SECURE QUERY HELPERS
# =====================================================

def execute_secure_query(cursor, query: str, params: tuple = None):
    """Execute query with parameterized inputs and logging"""
    try:
        if params:
            # Validate all parameters
            for param in params:
                if isinstance(param, str):
                    if InputValidator.contains_sql_injection(param):
                        logger.error(f"SQL injection attempt detected in query parameters")
                        audit_logger.log_security_event(
                            user_id=session.get('user_id'),
                            username=session.get('username'),
                            event_type='security_violation',
                            action='sql_injection_attempt',
                            success=False
                        )
                        raise ValueError("Invalid query parameters detected")
        
        cursor.execute(query, params or ())
        return cursor.fetchall()
    except Exception as e:
        logger.error(f"Query execution error: {e}")
        raise

# =====================================================
# SECURE FILE UPLOAD
# =====================================================

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}
ALLOWED_DOCUMENT_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
ALLOWED_ALL_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_DOCUMENT_EXTENSIONS
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def validate_file_upload(file, allowed_extensions=None):
    """Validate file upload with security checks"""
    if not file or not file.filename:
        return False, "No file selected"
    
    if allowed_extensions is None:
        allowed_extensions = ALLOWED_ALL_EXTENSIONS
    
    # Validate filename
    is_valid, error = InputValidator.validate_file_upload(
        file.filename,
        allowed_extensions,
        MAX_FILE_SIZE
    )
    
    if not is_valid:
        audit_logger.log_security_event(
            user_id=session.get('user_id'),
            username=session.get('username'),
            event_type='security_violation',
            action='invalid_file_upload',
            resource=file.filename,
            success=False
        )
        return False, error
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset
    
    if size > MAX_FILE_SIZE:
        return False, f"File too large. Maximum size: {MAX_FILE_SIZE / (1024*1024)}MB"
    
    return True, None

# =====================================================
# SECURE DATA ACCESS
# =====================================================

def get_patient_data_safely(mysql_connection, patient_id: int):
    """Safely retrieve patient data with access control"""
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    # Check access
    if not access_control.can_access_patient_data(user_id, user_role, patient_id, mysql_connection):
        audit_logger.log_security_event(
            user_id=user_id,
            username=session.get('username'),
            event_type='unauthorized_access',
            action='patient_data_access_denied',
            resource=f'patient:{patient_id}',
            success=False
        )
        return None
    
    # Log access
    audit_logger.log_data_access(
        user_id=user_id,
        username=session.get('username'),
        resource_type='patient',
        resource_id=patient_id,
        action='read'
    )
    
    # Fetch data
    cursor = mysql_connection.cursor()
    try:
        cursor.execute("""
            SELECT id, username, email, first_name, last_name, phone,
                   date_of_birth, gender, blood_type, emergency_contact,
                   emergency_phone
            FROM users
            WHERE id = %s AND role = 'patient'
        """, (patient_id,))
        return cursor.fetchone()
    finally:
        cursor.close()

# =====================================================
# INITIALIZATION
# =====================================================

def init_security(app, mysql_connection):
    """Initialize security features"""
    
    # Store mysql connection in app context
    @app.before_request
    def before_request_security():
        from flask import g
        g.mysql = mysql_connection
        
        # Validate request
        try:
            validate_request()
        except:
            pass  # Already handled
        
        # Monitor request
        monitor_request()
        
        # Generate CSRF token if not exists
        if 'csrf_token' not in session:
            session['csrf_token'] = csrf_protection.generate_token()
    
    # Add security headers
    app.after_request(add_security_headers)
    
    # Log request time
    @app.after_request
    def after_request_security(response):
        log_request_time()
        return response
    
    logger.info("Security module initialized")

