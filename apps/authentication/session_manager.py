"""
Redis Session Manager for SSO
Handles single-session enforcement and session tracking.
"""
from django.core.cache import cache
from django.conf import settings
import json
from datetime import datetime


class SSOSessionManager:
    """
    Manages user sessions in Redis for the SSO system.
    Ensures only one active session per user (single device login).
    """
    
    SESSION_PREFIX = "sso:session:user:"
    SESSION_TIMEOUT = 60 * 60 * 24 * 7  # 7 days (matches refresh token lifetime)
    
    @classmethod
    def get_session_key(cls, user_id):
        """Generate Redis key for user session."""
        return f"{cls.SESSION_PREFIX}{user_id}"
    
    @classmethod
    def create_session(cls, user_id, device_hash=None, ip_address=None):
        """
        Create a new session for a user.
        If a session already exists, it will be replaced (single session enforcement).
        
        Returns the session data.
        """
        session_key = cls.get_session_key(user_id)
        
        session_data = {
            "user_id": str(user_id),
            "device_hash": device_hash,
            "ip_address": ip_address,
            "created_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat(),
        }
        
        # Store in Redis (replaces any existing session)
        cache.set(session_key, json.dumps(session_data), timeout=cls.SESSION_TIMEOUT)
        
        return session_data
    
    @classmethod
    def get_session(cls, user_id):
        """
        Get the current session for a user.
        Returns None if no session exists.
        """
        session_key = cls.get_session_key(user_id)
        session_data = cache.get(session_key)
        
        if session_data:
            return json.loads(session_data)
        return None
    
    @classmethod
    def validate_session(cls, user_id, device_hash=None):
        """
        Validate that a session exists and optionally matches the device hash.
        
        Returns:
            - True if session is valid
            - False if session doesn't exist or device_hash doesn't match
        """
        session = cls.get_session(user_id)
        
        if not session:
            return False
        
        # If device_hash validation is enabled and provided
        if device_hash and session.get("device_hash"):
            if session["device_hash"] != device_hash:
                return False
        
        return True
    
    @classmethod
    def update_activity(cls, user_id):
        """Update the last activity timestamp for a session."""
        session = cls.get_session(user_id)
        
        if session:
            session["last_activity"] = datetime.utcnow().isoformat()
            session_key = cls.get_session_key(user_id)
            cache.set(session_key, json.dumps(session), timeout=cls.SESSION_TIMEOUT)
    
    @classmethod
    def destroy_session(cls, user_id):
        """
        Destroy a user's session (logout).
        This is the core of Single Logout functionality.
        """
        session_key = cls.get_session_key(user_id)
        cache.delete(session_key)
        return True
    
    @classmethod
    def is_logged_in_elsewhere(cls, user_id, current_device_hash=None):
        """
        Check if user is logged in on a different device.
        Useful for displaying warnings or forcing logout.
        """
        session = cls.get_session(user_id)
        
        if not session:
            return False
        
        if current_device_hash and session.get("device_hash"):
            return session["device_hash"] != current_device_hash
        
        return False
