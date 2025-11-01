"""
Comprehensive Security Module for Healthcare Application
Implements HIPAA-compliant security measures and best practices
"""

import re
import time
import hashlib
import hmac
import secrets
from functools import wraps
from flask import request, session, abort, jsonify, g
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from typing import Optional, Callable, Dict, List, Tuple
from cryptography.fernet import Fernet
import base64
import os

# Configure logging
logger = logging.getLogger(__name__)

# =====================================================
# RATE LIMITING & BRUTE FORCE PROTECTION
# =====================================================

class RateLimiter:
    """Rate limiter to prevent brute force attacks"""
    
    def __init__(self):
        self.attempts = defaultdict(list)
        self.lockout_duration = 3600  # 1 hour
        self.max_attempts = 5
        self.window = 300  # 5 minutes
        
    def is_allowed(self, identifier: str, action: str = 'default') -> Tuple[bool, Optional[str]]:
        """
        Check if action is allowed for identifier
        Returns: (is_allowed, message)
        """
        key = f"{identifier}:{action}"
        now = time.time()
        
        # Clean old attempts
        self.attempts[key] = [t for t in self.attempts[key] if now - t < self.window]
        
        # Check if locked out
        if len(self.attempts[key]) >= self.max_attempts:
            oldest_attempt = min(self.attempts[key])
            if now - oldest_attempt < self.lockout_duration:
                remaining = int(self.lockout_duration - (now - oldest_attempt))
                return False, f"Too many attempts. Please try again in {remaining} seconds."
        
        return True, None
    
    def record_attempt(self, identifier: str, action: str = 'default', success: bool = False):
        """Record an attempt"""
        if success:
            # Clear attempts on success
            key = f"{identifier}:{action}"
            if key in self.attempts:
                del self.attempts[key]
        else:
            key = f"{identifier}:{action}"
            self.attempts[key].append(time.time())

rate_limiter = RateLimiter()

# =====================================================
# INPUT VALIDATION & SANITIZATION
# =====================================================

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|\#|/\*|\*/|;|\|)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\bUNION\s+SELECT\b)",
        r"(\bCONCAT\s*\()",
        r"('|(\\')|(--)|(;)|(/\*)|(\*/))",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<img[^>]*src[^>]*=.*?javascript:",
        r"<style[^>]*>.*?</style>",
        r"<link[^>]*>",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\\\",
        r"\.\.%2f",
        r"\.\.%5c",
    ]
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username"""
        if not username:
            return False, "Username is required"
        
        if len(username) < 3 or len(username) > 50:
            return False, "Username must be between 3 and 50 characters"
        
        if not re.match(r"^[a-zA-Z0-9_-]+$", username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        if InputValidator.contains_sql_injection(username):
            return False, "Invalid username format"
        
        return True, None
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, Optional[str]]:
        """Validate email"""
        if not email:
            return False, "Email is required"
        
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        if len(email) > 255:
            return False, "Email is too long"
        
        if InputValidator.contains_sql_injection(email):
            return False, "Invalid email format"
        
        return True, None
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, Optional[str]]:
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        
        if len(password) < 12:
            return False, "Password must be at least 12 characters"
        
        if len(password) > 128:
            return False, "Password is too long"
        
        # Check for uppercase
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for lowercase
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for number
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        
        # Check for special character
        if not re.search(r"[@$!%*#?&]", password):
            return False, "Password must contain at least one special character (@$!%*#?&)"
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"
        
        return True, None
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 10000) -> str:
        """Sanitize string input"""
        if not value:
            return ""
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Limit length
        if len(value) > max_length:
            value = value[:max_length]
        
        # Remove XSS patterns
        for pattern in InputValidator.XSS_PATTERNS:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        # Remove path traversal
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        return value.strip()
    
    @staticmethod
    def contains_sql_injection(value: str) -> bool:
        """Check if string contains SQL injection patterns"""
        if not value:
            return False
        
        value_upper = value.upper()
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def contains_xss(value: str) -> bool:
        """Check if string contains XSS patterns"""
        if not value:
            return False
        
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def validate_file_upload(filename: str, allowed_extensions: set, max_size: int) -> Tuple[bool, Optional[str]]:
        """Validate file upload"""
        if not filename:
            return False, "No file selected"
        
        # Check for path traversal
        if InputValidator.contains_path_traversal(filename):
            return False, "Invalid filename"
        
        # Check extension
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        if ext not in allowed_extensions:
            return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
        
        # Check filename length
        if len(filename) > 255:
            return False, "Filename too long"
        
        return True, None
    
    @staticmethod
    def contains_path_traversal(value: str) -> bool:
        """Check for path traversal attempts"""
        if not value:
            return False
        
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False

validator = InputValidator()

# =====================================================
# CSRF PROTECTION
# =====================================================

class CSRFProtection:
    """CSRF token generation and validation"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_token(token: str, session_token: str) -> bool:
        """Validate CSRF token"""
        if not token or not session_token:
            return False
        return hmac.compare_digest(token, session_token)
    
    @staticmethod
    def get_token_from_request() -> Optional[str]:
        """Get CSRF token from request"""
        # Check form data first
        token = request.form.get('csrf_token')
        if not token:
            # Check headers
            token = request.headers.get('X-CSRF-Token')
        return token

csrf_protection = CSRFProtection()

# =====================================================
# DATA ENCRYPTION (AT REST)
# =====================================================

class DataEncryption:
    """Encrypt/decrypt sensitive data at rest"""
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize encryption with key from environment or generate new
        """
        if key:
            self.key = key
        else:
            # Get key from environment or use default (NOT for production!)
            key_str = os.getenv('ENCRYPTION_KEY')
            if key_str:
                # Fernet accepts both bytes and base64-encoded strings
                self.key = key_str.encode() if isinstance(key_str, str) else key_str
            else:
                # Generate key (store this securely!)
                self.key = Fernet.generate_key()
                logger.warning("Generated new encryption key. Store this securely in ENCRYPTION_KEY env var!")
        
        # Fernet accepts both bytes and strings, but we'll ensure bytes
        if isinstance(self.key, str):
            self.key = self.key.encode()
        
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return ""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return ""
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return ""
    
    def encrypt_field(self, value: Optional[str]) -> Optional[str]:
        """Encrypt database field"""
        if value is None:
            return None
        return self.encrypt(value)
    
    def decrypt_field(self, value: Optional[str]) -> Optional[str]:
        """Decrypt database field"""
        if value is None:
            return None
        return self.decrypt(value)

# Initialize encryption (key should be set from environment in production)
encryption = DataEncryption()

# =====================================================
# AUDIT LOGGING
# =====================================================

class AuditLogger:
    """Comprehensive audit logging for HIPAA compliance"""
    
    SENSITIVE_FIELDS = [
        'password', 'password_hash', 'ssn', 'credit_card', 
        'private_key', '2fa_secret', 'auth_token'
    ]
    
    @staticmethod
    def log_security_event(
        user_id: Optional[int],
        username: Optional[str],
        event_type: str,
        action: str,
        resource: Optional[str] = None,
        success: bool = True,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict] = None
    ):
        """Log security event with full context"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'username': username or 'anonymous',
            'event_type': event_type,  # login, access, modify, delete, etc.
            'action': action,
            'resource': resource,
            'success': success,
            'ip_address': ip_address or request.remote_addr if request else None,
            'user_agent': user_agent or (request.headers.get('User-Agent') if request else None),
            'details': AuditLogger._sanitize_details(details) if details else None
        }
        
        # Log to file/system
        logger.info(f"AUDIT: {log_data}")
        
        # Could also send to external SIEM system
        
        return log_data
    
    @staticmethod
    def _sanitize_details(details: Dict) -> Dict:
        """Remove sensitive information from log details"""
        sanitized = details.copy()
        for key in sanitized:
            if any(field in key.lower() for field in AuditLogger.SENSITIVE_FIELDS):
                sanitized[key] = '***REDACTED***'
        return sanitized
    
    @staticmethod
    def log_data_access(user_id: int, username: str, resource_type: str, resource_id: int, action: str):
        """Log data access (required for HIPAA)"""
        AuditLogger.log_security_event(
            user_id=user_id,
            username=username,
            event_type='data_access',
            action=action,
            resource=f"{resource_type}:{resource_id}",
            success=True
        )
    
    @staticmethod
    def log_data_modification(user_id: int, username: str, resource_type: str, resource_id: int, changes: Dict):
        """Log data modification"""
        AuditLogger.log_security_event(
            user_id=user_id,
            username=username,
            event_type='data_modification',
            action='modify',
            resource=f"{resource_type}:{resource_id}",
            details={'changes': changes}
        )

audit_logger = AuditLogger()

# =====================================================
# ACCESS CONTROL & PERMISSIONS
# =====================================================

class AccessControl:
    """Role-based access control with fine-grained permissions"""
    
    # Define permissions per role
    PERMISSIONS = {
        'patient': {
            'read_own_records': True,
            'read_own_appointments': True,
            'read_own_prescriptions': True,
            'read_own_scans': True,
            'upload_scans': True,
            'modify_own_profile': True,
            'schedule_appointment': True,
        },
        'doctor': {
            'read_assigned_patients': True,
            'read_patient_records': True,
            'create_medical_records': True,
            'modify_medical_records': True,
            'prescribe_medication': True,
            'view_appointments': True,
            'modify_appointments': True,
        },
        'admin': {
            'read_all_records': True,
            'modify_all_records': True,
            'delete_records': True,
            'manage_users': True,
            'view_audit_logs': True,
            'system_config': True,
        }
    }
    
    @staticmethod
    def has_permission(role: str, permission: str) -> bool:
        """Check if role has permission"""
        return AccessControl.PERMISSIONS.get(role, {}).get(permission, False)
    
    @staticmethod
    def can_access_patient_data(user_id: int, user_role: str, patient_id: int, mysql_connection) -> bool:
        """Check if user can access patient data"""
        # Patients can only access their own data
        if user_role == 'patient':
            return user_id == patient_id
        
        # Doctors can access assigned patients
        if user_role == 'doctor':
            cursor = mysql_connection.cursor()
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM doctor_patient_assignments
                    WHERE doctor_id = %s AND patient_id = %s AND status = 'active'
                """, (user_id, patient_id))
                result = cursor.fetchone()
                return result[0] > 0
            finally:
                cursor.close()
        
        # Admins can access all
        if user_role == 'admin':
            return True
        
        return False
    
    @staticmethod
    def require_permission(permission: str):
        """Decorator to require specific permission"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                role = session.get('role')
                if not role:
                    abort(403)
                
                if not AccessControl.has_permission(role, permission):
                    audit_logger.log_security_event(
                        user_id=session.get('user_id'),
                        username=session.get('username'),
                        event_type='unauthorized_access',
                        action='permission_denied',
                        resource=permission,
                        success=False
                    )
                    abort(403)
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator

access_control = AccessControl()

# =====================================================
# SECURITY DECORATORS
# =====================================================

def require_csrf(f: Callable) -> Callable:
    """Decorator to require CSRF token for POST requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = csrf_protection.get_token_from_request()
            session_token = session.get('csrf_token')
            
            if not csrf_protection.validate_token(token, session_token):
                audit_logger.log_security_event(
                    user_id=session.get('user_id'),
                    username=session.get('username'),
                    event_type='csrf_attack',
                    action='invalid_token',
                    success=False
                )
                abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(action: str = 'default', max_attempts: int = 5):
    """Decorator for rate limiting"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            identifier = request.remote_addr
            if 'username' in session:
                identifier = session.get('username', identifier)
            
            allowed, message = rate_limiter.is_allowed(identifier, action)
            if not allowed:
                return jsonify({'error': message}), 429
            
            result = f(*args, **kwargs)
            
            # Record attempt (assume success if no error)
            rate_limiter.record_attempt(identifier, action, True)
            return result
        return decorated_function
    return decorator

def validate_input(validation_func: Callable):
    """Decorator for input validation"""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Validate all form inputs
            for key, value in request.form.items():
                if isinstance(value, str):
                    is_valid, error = validation_func(key, value)
                    if not is_valid:
                        audit_logger.log_security_event(
                            user_id=session.get('user_id'),
                            username=session.get('username'),
                            event_type='input_validation_failed',
                            action='invalid_input',
                            resource=key,
                            success=False,
                            details={'value': value[:50]}  # Truncate for logging
                        )
                        return jsonify({'error': error}), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# =====================================================
# SESSION SECURITY
# =====================================================

class SessionSecurity:
    """Enhanced session security"""
    
    @staticmethod
    def create_secure_session(user_id: int, username: str, role: str):
        """Create secure session with all security measures"""
        session.clear()
        session['user_id'] = user_id
        session['username'] = username
        session['role'] = role
        session['login_time'] = datetime.utcnow().isoformat()
        session['csrf_token'] = csrf_protection.generate_token()
        session['ip_address'] = request.remote_addr
        session['user_agent'] = request.headers.get('User-Agent', '')[:200]  # Limit length
        session.permanent = True
        
        # Log session creation
        audit_logger.log_security_event(
            user_id=user_id,
            username=username,
            event_type='session_created',
            action='login',
            success=True
        )
    
    @staticmethod
    def validate_session(mysql_connection) -> bool:
        """Validate current session"""
        if 'username' not in session:
            return False
        
        # Check IP address change (potential session hijacking)
        current_ip = request.remote_addr
        stored_ip = session.get('ip_address')
        if stored_ip and current_ip != stored_ip:
            logger.warning(f"IP address changed for session: {stored_ip} -> {current_ip}")
            # Could invalidate session here for stricter security
            # session.clear()
            # return False
        
        # Check user still exists
        cursor = mysql_connection.cursor()
        try:
            cursor.execute("SELECT id, role FROM users WHERE username = %s", (session['username'],))
            user = cursor.fetchone()
            if not user:
                session.clear()
                return False
            
            # Update session with current user_id if missing
            if session.get('user_id') != user[0]:
                session['user_id'] = user[0]
            
            # Check role hasn't changed
            if session.get('role') != user[1]:
                session['role'] = user[1]
            
            return True
        finally:
            cursor.close()

session_security = SessionSecurity()

