from rest_framework import serializers
from djoser.serializers import UserCreateSerializer
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils import timezone
from django.core.mail import send_mail
from .models import Device, DeviceFingerprint, UserDevice
from utils.ip_utils import get_client_ip

from django.core.cache import cache
import redis

from django.conf import settings

# from apps.media.serializers import MediaSerializer
from apps.user_profile.models import UserProfile


User = get_user_model()


class UserCreateSerializer(UserCreateSerializer):
    qr_code = serializers.URLField(source="get_qr_code")
    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    qr_code = serializers.URLField(source="get_qr_code")
    profile_picture = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = [
            "username",
            "code",
            "first_name",
            "last_name",
            "role",
            "verified",
            "updated_at",
            "two_factor_enabled",
            "otpauth_url",
            "login_otp",
            "login_otp_used",
            "otp_created_at",
            "qr_code",
            "profile_picture",
        ]
    def get_profile_picture(self, obj):
        user_profile = UserProfile.objects.get(user=obj)
        if user_profile and user_profile.profile_picture:
            return MediaSerializer(user_profile.profile_picture).data
        return None

class UserPublicSerializer(serializers.ModelSerializer):
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "username",
            "first_name",
            "last_name",
            "updated_at",
            "role",
            "verified",
            "profile_picture",
        ]

    def get_profile_picture(self, obj):
        user_profile = UserProfile.objects.get(user=obj)
        if user_profile and user_profile.profile_picture:
            return MediaSerializer(user_profile.profile_picture).data
        return None

class SecureDeviceLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data_request = self.context['request'].data
        device_hash = data_request.get('hash-device')
        
        if not device_hash:
            raise serializers.ValidationError({"error": "Firma de hardware ausente."})

        # 1. Validar Email y Password
        token_data = super().validate(attrs)
        user = self.user

        # BYPASS COMPLETO: Superusuarios no requieren validación de dispositivo
        if user.is_superuser:
            # Registrar el dispositivo pero no validar autorización
            device, _ = Device.objects.get_or_create(
                device_hash=device_hash,
                defaults={'hostname': data_request.get('hostname', 'Desconocido')}
            )
            user_device, _ = UserDevice.objects.get_or_create(user=user, device=device)
            # Auto-autorizar
            if not user_device.authorized:
                user_device.authorized = True
                user_device.save()
            
            # Actualizar último login
            user_device.last_login = timezone.now()
            user_device.last_ip = get_client_ip(self.context['request'])
            user_device.save()
            
            # Retornar token directamente sin más validaciones
            token_data['device_hash'] = device_hash
            return token_data

        # 2. Verificar o Registrar Dispositivo en DB SQL (usuarios normales)
        device, _ = Device.objects.get_or_create(
            device_hash=device_hash,
            defaults={'hostname': data_request.get('hostname', 'Desconocido')}
        )

        user_device, _ = UserDevice.objects.get_or_create(user=user, device=device)

        # 3. Verificar Autorización (Lista Blanca) - solo usuarios normales
        if not user_device.authorized:
            self.notify_admin_new_device(user, device)
            self.send_security_email(user, device, status="pendiente")
            raise serializers.ValidationError({
                "code": "DEVICE_LOCKED",
                "message": "Dispositivo no autorizado por administración."
            })

        # --- LÓGICA DE REDIS: CONTROL DE CONCURRENCIA ---
        redis_key = f"session:user:{user.id}"
        active_session_hash = cache.get(redis_key)
        
        # Capturamos si el usuario envió el parámetro para forzar la entrada
        force_login = data_request.get('force-login', False)

        if active_session_hash and active_session_hash != device_hash:
            # Si hay una sesión activa en otro hardware diferente
            if not force_login:
                # Si hay sesión y NO pidió forzar, bloqueamos
                raise serializers.ValidationError({
                    "code": "CONCURRENT_SESSION",
                    "message": "Ya existe una sesión activa en otro dispositivo."
                })
            else:
                # Si pidió forzar, borramos la vieja antes de seguir
                cache.delete(redis_key)

        # 4. Generar/Actualizar sesión en Redis (TTL 8 horas)
        # 8 horas = 28800 segundos
        # En tu Serializer
        refresh_lifetime = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME').total_seconds()
        cache.set(redis_key, device_hash, timeout=int(refresh_lifetime))
        

        # 5. Auditoría en SQL
        user_device.last_login = timezone.now()
        user_device.last_ip = get_client_ip(self.context['request'])
        user_device.save()
        
        # 6. ENVIAR CORREO DE ÉXITO Y RETORNAR TOKEN
        self.send_security_email(user, device, status="exitoso")
        
        # Agregamos el hash al payload del token por seguridad extra
        token_data['device_hash'] = device_hash
        return token_data

    def notify_admin_new_device(self, user, device):
        # Lógica para enviar mensaje (puedes usar Django Mail)
        try:
            send_mail(
                'ALERTA: Nuevo Dispositivo Pendiente',
                f'El usuario {user.email} intenta entrar desde {device.hostname} ({device.device_hash}). Por favor autorícelo en el panel.',
                'sistema@tuapp.com',
                ['admin@tuapp.com'], # Tu correo
                fail_silently=True,
            )
        except:
            pass
        
    def send_security_email(self, user, device, status):

        if status == "pendiente":
            subject = "⚠️ Intento de acceso desde un nuevo dispositivo"
            message = f"Hola {user.first_name}, alguien intentó entrar a tu cuenta desde el dispositivo: {device.hostname} ({device.os}). El acceso ha sido bloqueado hasta que un administrador lo valide."
        else:
            subject = "✅ Nuevo inicio de sesión detectado"
            message = f"Hola {user.first_name}, se ha iniciado sesión correctamente en tu cuenta desde el dispositivo autorizado: {device.hostname}."

        try:
            send_mail(
                subject,
                message,
                'seguridad@tuempresa.com',
                [user.email],
                fail_silently=True,
            )
        except:
            pass                

# ============================================
# ADMIN: Device Management Serializers
# ============================================

class DeviceFingerprintSerializer(serializers.ModelSerializer):
    """Serializer for hardware fingerprint details"""
    class Meta:
        model = DeviceFingerprint
        fields = [
            'uuid_sistema',
            'numero_serie_cpu',
            'numero_serie_disco',
            'baseboard_serial',
            'bios_serial',
            'mac_address',
            'nombre_maquina'
        ]

class DeviceSerializer(serializers.ModelSerializer):
    """Serializer for device information"""
    class Meta:
        model = Device
        fields = ['id', 'device_hash', 'hostname', 'os', 'created_at']

class UserDeviceListSerializer(serializers.ModelSerializer):
    """Serializer for listing user devices with full details"""
    user = UserPublicSerializer(read_only=True)
    device = DeviceSerializer(read_only=True)
    fingerprint = serializers.SerializerMethodField()
    
    class Meta:
        model = UserDevice
        fields = [
            'id',
            'user',
            'device',
            'fingerprint',
            'authorized',
            'last_login',
            'last_ip'
        ]
    
    def get_fingerprint(self, obj):
        try:
            fingerprint = DeviceFingerprint.objects.get(device=obj.device)
            return DeviceFingerprintSerializer(fingerprint).data
        except DeviceFingerprint.DoesNotExist:
            return None
