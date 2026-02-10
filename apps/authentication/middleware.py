from django.core.cache import cache
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import AccessToken

class DeviceSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 1. Intentar obtener el token del header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('JWT '):
            try:
                token_str = auth_header.split(' ')[1]
                token = AccessToken(token_str)
                user_id = token['user_id']
                device_hash_in_token = token.get('device_hash')

                # 2. Consultar Redis
                redis_key = f"session:user:{user_id}"
                current_active_hash = cache.get(redis_key)

                # 3. Si Redis tiene un hash diferente, invalidar petición
                if current_active_hash and device_hash_in_token != current_active_hash:
                    return JsonResponse({
                        "error": "Sesión cerrada",
                        "message": "Se ha iniciado sesión en otro dispositivo. Esta sesión ha expirado."
                    }, status=401)
            except Exception:
                pass

        return self.get_response(request)