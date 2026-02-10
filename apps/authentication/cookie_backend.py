"""
Cookie-based JWT Authentication Backend for Django REST Framework.
Reads JWT from HttpOnly cookies instead of Authorization header.
"""
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed


class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that reads the access token from an HttpOnly cookie.
    Falls back to header-based authentication for API compatibility.
    """
    
    def authenticate(self, request):
        # First, try to get token from cookie
        access_token = request.COOKIES.get(
            getattr(settings, 'JWT_AUTH_COOKIE', 'sso_access_token')
        )
        
        if access_token:
            # Validate the token from cookie
            try:
                validated_token = self.get_validated_token(access_token)
                user = self.get_user(validated_token)
                return (user, validated_token)
            except InvalidToken:
                # Token is invalid, let it fall through
                pass
        
        # Fall back to header-based authentication
        return super().authenticate(request)
