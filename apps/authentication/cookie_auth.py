"""
Cookie-based JWT Authentication Views for SSO.
These views set JWT tokens as HttpOnly cookies instead of returning them in the response body.
"""
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status

from .serializers import CustomTokenObtainPairSerializer
from .models import AuditLog
from .session_manager import SSOSessionManager


class CookieTokenObtainPairView(TokenObtainPairView):
    """
    Login endpoint that sets JWT tokens as HttpOnly cookies.
    Also creates a Redis session and logs the login event.
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            # Log failed login attempt
            email = request.data.get('email', 'unknown')
            AuditLog.log_event(
                action='LOGIN_FAILED',
                email=email,
                request=request,
                success=False,
                details={'error': str(e)}
            )
            raise
        
        user = serializer.user
        tokens = serializer.validated_data
        
        # Create Redis session
        device_hash = request.META.get('HTTP_X_HARDWARE_SIG', None)
        ip_address = self._get_client_ip(request)
        SSOSessionManager.create_session(user.id, device_hash=device_hash, ip_address=ip_address)
        
        # Log successful login
        AuditLog.log_event(
            action='LOGIN',
            user=user,
            request=request,
            success=True,
            details={'method': 'password', 'device_hash': device_hash}
        )
        
        # Build response with user info and tokens (fallback for frontend)
        response = Response({
            "success": True,
            "message": "Login exitoso",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            "access": tokens['access'],
            "refresh": tokens['refresh']
        }, status=status.HTTP_200_OK)
        
        # Set tokens as HttpOnly cookies
        self._set_jwt_cookies(response, tokens)
        
        return response
    
    def _set_jwt_cookies(self, response, tokens):
        """Set access and refresh tokens as HttpOnly cookies."""
        # Access token cookie
        response.set_cookie(
            key=getattr(settings, 'JWT_AUTH_COOKIE', 'sso_access_token'),
            value=tokens['access'],
            max_age=60 * 5,  # 5 minutes (matches ACCESS_TOKEN_LIFETIME)
            httponly=getattr(settings, 'JWT_AUTH_COOKIE_HTTP_ONLY', True),
            secure=getattr(settings, 'JWT_AUTH_COOKIE_SECURE', False),
            samesite=getattr(settings, 'JWT_AUTH_COOKIE_SAMESITE', 'Lax'),
            domain=getattr(settings, 'JWT_AUTH_COOKIE_DOMAIN', None),
        )
        
        # Refresh token cookie
        response.set_cookie(
            key=getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', 'sso_refresh_token'),
            value=tokens['refresh'],
            max_age=60 * 60 * 24 * 7,  # 7 days (matches REFRESH_TOKEN_LIFETIME)
            httponly=getattr(settings, 'JWT_AUTH_COOKIE_HTTP_ONLY', True),
            secure=getattr(settings, 'JWT_AUTH_COOKIE_SECURE', False),
            samesite=getattr(settings, 'JWT_AUTH_COOKIE_SAMESITE', 'Lax'),
            domain=getattr(settings, 'JWT_AUTH_COOKIE_DOMAIN', None),
        )
    
    def _get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')


class CookieTokenRefreshView(TokenRefreshView):
    """
    Token refresh endpoint that reads refresh token from cookie
    and sets new access token as HttpOnly cookie.
    """
    
    def post(self, request, *args, **kwargs):
        # Get refresh token from cookie
        refresh_token = request.COOKIES.get(
            getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', 'sso_refresh_token')
        )
        
        if not refresh_token:
            return Response(
                {"error": "No refresh token found"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Create new tokens
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            # Log refresh event
            from rest_framework_simplejwt.tokens import AccessToken
            try:
                decoded = AccessToken(access_token)
                user_id = decoded.get('user_id')
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User.objects.get(id=user_id)
                AuditLog.log_event(
                    action='REFRESH',
                    user=user,
                    request=request,
                    success=True
                )
            except Exception:
                pass  # Continue even if audit fails
            
            response = Response({
                "success": True,
                "message": "Token refreshed"
            }, status=status.HTTP_200_OK)
            
            # Set new access token cookie
            response.set_cookie(
                key=getattr(settings, 'JWT_AUTH_COOKIE', 'sso_access_token'),
                value=access_token,
                max_age=60 * 5,  # 5 minutes
                httponly=getattr(settings, 'JWT_AUTH_COOKIE_HTTP_ONLY', True),
                secure=getattr(settings, 'JWT_AUTH_COOKIE_SECURE', False),
                samesite=getattr(settings, 'JWT_AUTH_COOKIE_SAMESITE', 'Lax'),
                domain=getattr(settings, 'JWT_AUTH_COOKIE_DOMAIN', None),
            )
            
            # Rotate refresh token if configured
            if getattr(settings, 'SIMPLE_JWT', {}).get('ROTATE_REFRESH_TOKENS', False):
                new_refresh = str(refresh)
                response.set_cookie(
                    key=getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', 'sso_refresh_token'),
                    value=new_refresh,
                    max_age=60 * 60 * 24 * 7,  # 7 days
                    httponly=getattr(settings, 'JWT_AUTH_COOKIE_HTTP_ONLY', True),
                    secure=getattr(settings, 'JWT_AUTH_COOKIE_SECURE', False),
                    samesite=getattr(settings, 'JWT_AUTH_COOKIE_SAMESITE', 'Lax'),
                    domain=getattr(settings, 'JWT_AUTH_COOKIE_DOMAIN', None),
                )
            
            return response
            
        except Exception as e:
            return Response(
                {"error": "Invalid or expired refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
