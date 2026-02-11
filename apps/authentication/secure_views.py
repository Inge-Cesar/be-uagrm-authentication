from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_api.views import StandardAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from apps.authentication.models import Device, DeviceFingerprint, UserDevice
from utils.ip_utils import get_client_ip
from django.core.cache import cache
from django.conf import settings
from axes.handlers.proxy import AxesProxyHandler
from core.permissions import HasValidAPIKey

class SecureDeviceLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        device_hash = request.data.get('hash-device')
        componentes = request.data.get('componentes', {})
        
        # 1. Validaciones Básicas
        if not email or not password:
            return self.error("Email y contraseña requeridos.")
        
        if not device_hash:
             return self.error("Este dispositivo no tiene el Agente de Seguridad instalado o ejecutándose.")

        # 2. Autenticación de Credenciales
        user = authenticate(request, email=email, password=password)

        if not user:
            # Registrar intento fallido en Axes (Seguridad)
            credentials = {"username": email, 'ip_address': get_client_ip(request)}
            AxesProxyHandler.user_login_failed(request, credentials)
            return self.error("Credenciales inválidas.", status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
             return self.error("Cuenta desactivada.")

        # 3. Lógica de Dispositivo (Auto-Registro)
        device, created = Device.objects.get_or_create(
            device_hash=device_hash,
            defaults={
                "hostname": componentes.get("nombre_maquina", "Desconocido")
            }
        )

        # 4. Guardar "El Rastro" (Fingerprint)
        # Siempre actualizamos el fingerprint con los datos más recientes
        if componentes:
            DeviceFingerprint.objects.update_or_create(
                device=device,
                defaults={
                    "uuid_sistema": componentes.get("uuid_sistema"),
                    "numero_serie_cpu": componentes.get("numero_serie_cpu"),
                    "numero_serie_disco": componentes.get("numero_serie_disco"),
                    "baseboard_serial": componentes.get("baseboard_serial"),
                    "bios_serial": componentes.get("bios_serial"),
                    "mac_address": componentes.get("mac_address"),
                    "nombre_maquina": componentes.get("nombre_maquina"),
                }
            )

        # 5. Verificar Relación Usuario-Dispositivo
        # get_or_create devuelve (obj, created)
        # defaults={"authorized": False} asegura que si es nuevo, nazca NO AUTORIZADO
        user_device, ud_created = UserDevice.objects.get_or_create(
            user=user,
            device=device,
            defaults={"authorized": False} 
        )

        # 6. Bloqueo si no está autorizado
        if not user_device.authorized:
            return self.error({
                "code": "DEVICE_LOCKED",
                "message": "Dispositivo pendiente de autorización. Contacte al administrador."
            }, status=status.HTTP_403_FORBIDDEN)

        # 7. Gestión de Sesión (Redis - Concurrencia)
        # Solo permitir 1 sesión activa por usuario
        redis_key = f"session:user:{user.id}"
        active_session_hash = cache.get(redis_key)
        force_login = request.data.get('force-login', False)

        if active_session_hash and active_session_hash != device_hash:
            if not force_login:
                 return self.error({
                    "code": "CONCURRENT_SESSION",
                    "message": "Ya existe una sesión activa en otro dispositivo."
                }, status=status.HTTP_409_CONFLICT)
            else:
                # Si fuerza el login, la otra sesión morirá eventualmente o se invalidará aqui
                pass

        # 8. ÉXITO - Generar Tokens
        refresh = RefreshToken.for_user(user)
        refresh['device_hash'] = device_hash # Claim personalizado

        # Actualizar Redis
        refresh_ttl = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME').total_seconds()
        cache.set(redis_key, device_hash, timeout=int(refresh_ttl))

        # Auditoría
        user_device.last_login = timezone.now()
        user_device.last_ip = get_client_ip(request)
        user_device.save()
        
        AxesProxyHandler.user_logged_in(request, user)

        return self.response({
            "access": str(refresh.access_token), 
            "refresh": str(refresh),
            "message": f"Bienvenido {user.first_name}"
        })
