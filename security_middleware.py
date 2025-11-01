"""
Security Middleware for Flask Application
Implements security headers, request validation, and monitoring
"""

from flask import request, g, abort
from functools import wraps
import logging
from datetime import datetime
import time

logger = logging.getLogger(__name__)

# =====================================================
# SECURITY HEADERS
# =====================================================

def add_security_headers(response):
    """Add comprehensive security headers to all responses"""
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy (strict)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy (formerly Feature-Policy)
    response.headers['Permissions-Policy'] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=()"
    )
    
    # Strict Transport Security (only if HTTPS)
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Prevent caching of sensitive pages
    if request.endpoint and any(x in request.endpoint for x in ['login', 'register', 'admin', 'patient', 'doctor']):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    # Add request ID for tracking
    if not hasattr(g, 'request_id'):
        g.request_id = generate_request_id()
    response.headers['X-Request-ID'] = g.request_id
    
    return response

# =====================================================
# REQUEST VALIDATION
# =====================================================

def validate_request():
    """Validate incoming request for security issues"""
    
    # Check for suspicious User-Agent
    user_agent = request.headers.get('User-Agent', '')
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        logger.warning(f"Suspicious User-Agent detected: {user_agent} from {request.remote_addr}")
        abort(403)
    
    # Check request size
    if request.content_length and request.content_length > 16 * 1024 * 1024:  # 16MB
        logger.warning(f"Request too large: {request.content_length} bytes from {request.remote_addr}")
        abort(413)
    
    # Check for SQL injection in query parameters
    for key, value in request.args.items():
        if isinstance(value, str):
            sql_patterns = ['UNION', 'SELECT', 'DROP', 'DELETE', 'INSERT', 'UPDATE', '--', ';']
            if any(pattern in value.upper() for pattern in sql_patterns):
                logger.warning(f"Potential SQL injection in query param {key} from {request.remote_addr}")
                # Could abort here or just log
    
    return True

# =====================================================
# REQUEST MONITORING
# =====================================================

def monitor_request():
    """Monitor and log all requests"""
    g.request_start_time = time.time()
    
    # Log request details
    logger.info(
        f"Request: {request.method} {request.path} "
        f"from {request.remote_addr} "
        f"User-Agent: {request.headers.get('User-Agent', 'Unknown')[:100]}"
    )

def log_request_time():
    """Log request processing time"""
    if hasattr(g, 'request_start_time'):
        duration = time.time() - g.request_start_time
        if duration > 1.0:  # Log slow requests
            logger.warning(f"Slow request: {request.path} took {duration:.2f}s")

# =====================================================
# HELPER FUNCTIONS
# =====================================================

def generate_request_id():
    """Generate unique request ID"""
    import uuid
    return str(uuid.uuid4())[:8]

# =====================================================
# ERROR HANDLING
# =====================================================

def handle_security_error(error):
    """Handle security-related errors"""
    logger.error(f"Security error: {error}")
    return {
        'error': 'Security violation detected',
        'message': 'Your request was blocked for security reasons'
    }, 403

