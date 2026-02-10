from io import BytesIO
from datetime import timedelta

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework import permissions
from django.contrib.auth.models import Permission
from rest_framework_api.views import StandardAPIView
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.files.base import ContentFile
from apps.authentication.models import Device, DeviceFingerprint, UserAccount, UserDevice, RolUniversal, Sistema
from django.contrib.auth import authenticate

from django.utils.crypto import get_random_string
from django.utils import timezone
from django.utils.timezone import now
from django.core.mail import send_mail
from django.contrib.sites.models import Site

from django.core.cache import cache
from django.conf import settings

import pyotp
import qrcode

from axes.handlers.proxy import AxesProxyHandler


from core.permissions import HasValidAPIKey
from utils.ip_utils import get_client_ip
from utils.string_utils import sanitize_string, sanitize_username


User = get_user_model()


class UpdateUserInformationView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def put(self, request):
        user = request.user

        username = request.data.get("username", None)
        first_name = request.data.get("first_name", None)
        last_name = request.data.get("last_name", None)

        if username:
            user.username = sanitize_username(username)
        if first_name:
            user.first_name = sanitize_string(first_name)
        if last_name:
            user.last_name = sanitize_string(last_name)

        user.save()

        return self.response("User information updated successfully")
    

class GenerateQRCodeView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def get(self,request):
        user = request.user
        email = user.email

        print(f'user:{user}')
        print(f'email:{email}')

        otp_base32 = pyotp.random_base32()

        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="Uridium"
        )

        stream = BytesIO()
        image = qrcode.make(f"{otp_auth_url}")
        image.save(stream)

        user.otp_base32 = otp_base32
        user.qr_code = ContentFile(
            stream.getvalue(), name=f"qr{get_random_string(10)}.png"
        )

        user.save()
        qr_code = user.qr_code
        return self.response(qr_code.url)


class OTPLoginResetView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request):
        user = request.user

        new_ip = get_client_ip(request)

        if user.login_ip and user.login_ip != new_ip:
            print(f"New login IP for user: {user.email}")
            # TODO: Send user email

        user.login_ip = new_ip

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")
        
        try:
            totp = pyotp.TOTP(user.otp_base32).now()
        except Exception as e:
            return self.error(f"Error generating TOPT: {str(e)}")
        
        user.login_otp = make_password(totp)
        user.otp_created_at = timezone.now()
        user.login_otp_used = False

        user.save()

        return self.response("OTP Reset Successfully for user")
    

class VerifyOTPView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self,request):
        user = request.user

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")

        # Get TOTP
        totp = pyotp.TOTP(user.otp_base32)
        otp = request.data.get("otp")
        verified = totp.verify(otp)

        if verified:
            user.login_otp_used = True
            user.save()
            return self.response("OTP Verified")
        else:
            return self.error("Error Verifying One Time Password")
        

class DisableOTPView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self,request):
        user = request.user

        if user.qr_code is None or user.otp_base32 is None:
            return self.error("QR Code or OTP Base32 not found for user")
        
        # Get TOTP
        totp = pyotp.TOTP(user.otp_base32)
        otp = request.data.get("otp")
        verified = totp.verify(otp)

        if verified:
            user.two_factor_enabled = False
            user.otpauth_url = None
            user.otp_base32 = None
            user.qr_code = None
            user.login_otp = None
            user.login_otp_used = False
            user.otp_created_at = None
            user.save()

            return self.response("Two Factor Authentication Disabled")
        else:
            return self.error("Error Verifying One Time Password")
        

class Set2FAView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def post(self, request, *args, **kwargs):
        user = request.user

        if user.qr_code is None:
            return self.error(
                "QR Code not found for the user."
            )

        boolean = bool(request.data.get("bool"))

        if boolean:
            user.two_factor_enabled = True
            user.save()
            return self.response("2FA Activated")
        else:
            user.two_factor_enabled = False
            user.save()
            return self.response("2FA Disabled")
        

class OTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp')
        
        print(f"OTP Login attempt for email: {email} with OTP: {otp_code}")

        if not email or not otp_code:
            return self.error("Se requieren tanto el correo electrónico como el código OTP.")
        
        try:
            user = User.objects.get(email=email)
            
            if not user.otp_base32:
                return self.error("El usuario no tiene 2FA configurado.")
                
            # Verificar que el OTP es válido
            totp = pyotp.TOTP(user.otp_base32)
            if not totp.verify(otp_code):
                return self.error("Código OTP inválido.")
            
            # Actualizar el estado del OTP
            user.login_otp_used = True
            user.save()

            # Generar tokens JWT
            refresh = RefreshToken.for_user(user)
            return self.response({
                "access": str(refresh.access_token), 
                "refresh": str(refresh)
            })

        except User.DoesNotExist:
            print(f"OTP Login failed: User with email {email} does not exist.")
            return self.response("El usuario no existe.", status=status.HTTP_404_NOT_FOUND)
        

class SendOTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')

        # Verificar que existe un suario con ese email y que eestaa activo
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return self.error("El usuario no existe o no está activo.")
        
        # Generar OTP
        secret = pyotp.random_base32()
        user.otp_secret = secret
        user.save()

        totp = pyotp.TOTP(secret)
        otp = totp.now()

        # Enviar correo con OTP
        # Obtener el dominio del sitio configurado
        site = Site.objects.get_current()
        domain = site.domain

        send_mail(
            'Su código OTP',
            f'Su código OTP es {otp}',
            f'noreply@{domain}',
            [email],
            fail_silently=False,
        )

        return self.response("OTP enviado con éxito. Verifique su correo electrónico.")


#class VerifyOTPLoginView(StandardAPIView):
#    permission_classes = [HasValidAPIKey]
#
#    def post(self, request):
#        email = request.data.get('email')
#        otp_code = request.data.get('otp')
#        device_hash = request.data.get('hash-device')
#        hostname = request.data.get('hostname', 'Desconocido')
#        force_login = request.data.get('force-login', False)
#
#        # 1. Validaciones Básicas
#        if not email or not otp_code:
#            return self.error("Email y OTP son requeridos.")
#        
#        #if not device_hash:
#        #    return self.error("Firma de hardware ausente.")
#
#        try:
#            user = User.objects.get(email=email, is_active=True)
#        except User.DoesNotExist:
#            return self.error("Usuario no encontrado.", status=status.HTTP_404_NOT_FOUND)
#        
#        # 2. Verificar Código OTP
#        if not user.otp_secret:
#            return self.error("2FA no configurado.")
#
#        totp = pyotp.TOTP(user.otp_secret)
#        if not totp.verify(otp_code):
#            # ESTO ACTIVA A AXES: Registra el fallo para bloquear la IP/Usuario
#            # Lógica manual para disparar el contador de Axes
#            credentials = {"username": email, 'ip_address': get_client_ip(request)}
#            AxesProxyHandler.user_login_failed(request, credentials)
#            return self.error("Código OTP incorrecto.")
#
#        # --- INICIO LÓGICA DE HARDWARE ---
#
#        # 3. Registrar/Verificar Dispositivo SQL
#        device, _ = Device.objects.get_or_create(
#            device_hash=device_hash,
#            defaults={'hostname': hostname, 'is_active': True}
#        )
#        user_device, _ = UserDevice.objects.get_or_create(user=user, device=device)
#
#        # 4. Verificar Autorización (Admin)
#        if not user_device.authorized:
#            # Reutilizamos la lógica de notificación que definimos antes
#            self.notify_admin_new_device(user, device) 
#            self.send_security_email(user, device, status="pendiente")
#            return self.error({
#                "code": "DEVICE_LOCKED",
#                "message": "Dispositivo pendiente de autorización por el administrador."
#            }, status=status.HTTP_403_FORBIDDEN)
#
#        # 5. Lógica de Redis (Concurrencia)
#        redis_key = f"session:user:{user.id}"
#        active_session_hash = cache.get(redis_key)
#
#        if active_session_hash and active_session_hash != device_hash:
#            if not force_login:
#                return self.error({
#                    "code": "CONCURRENT_SESSION",
#                    "message": "Ya existe una sesión activa en otro dispositivo."
#                }, status=status.HTTP_409_CONFLICT)
#            else:
#                cache.delete(redis_key)
#        
#        # 5. ÉXITO: Limpiar Axes, Actualizar Redis y Generar Tokens
#        AxesProxyHandler.user_logged_in(request, user)  # Limpiar intentos fallidos en Axes al lograr un login exitoso
#
#        # --- SESIÓN APROBADA ---
#
#        # 6. Actualizar Redis y Auditoría
#        refresh_ttl = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME').total_seconds()
#        cache.set(redis_key, device_hash, timeout=int(refresh_ttl))
#
#        user_device.last_login = timezone.now()
#        user_device.last_ip = get_client_ip(request)
#        user_device.save()
#
#        # 7. Generar Tokens con Claims de Hardware
#        refresh = RefreshToken.for_user(user)
#        # Inyectamos el hash en el token para el Middleware
#        refresh['device_hash'] = device_hash # Payload para el Middleware
#
#        return self.response({
#            "access": str(refresh.access_token), 
#            "refresh": str(refresh)
#        })
#    def notify_admin_new_device(self, user, device):
#        # Lógica para enviar mensaje (puedes usar Django Mail)
#        try:
#            send_mail(
#                'ALERTA: Nuevo Dispositivo Pendiente',
#                f'El usuario {user.email} intenta entrar desde {device.hostname} ({device.device_hash}). Por favor autorícelo en el panel.',
#                'sistema@tuapp.com',
#                ['admin@tuapp.com'], # Tu correo
#                fail_silently=True,
#            )
#        except:
#            pass
#        
#    def send_security_email(self, user, device, status):
#
#        if status == "pendiente":
#            subject = "⚠️ Intento de acceso desde un nuevo dispositivo"
#            message = f"Hola {user.first_name}, alguien intentó entrar a tu cuenta desde el dispositivo: {device.hostname} ({device.os}). El acceso ha sido bloqueado hasta que un administrador lo valide."
#        else:
#            subject = "✅ Nuevo inicio de sesión detectado"
#            message = f"Hola {user.first_name}, se ha iniciado sesión correctamente en tu cuenta desde el dispositivo autorizado: {device.hostname}."
#
#        try:
#            send_mail(
#                subject,
#                message,
#                'seguridad@tuempresa.com',
#                [user.email],
#                fail_silently=True,
#            )
#        except:
#            pass
        
class VerifyOTPLoginView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp')

        if not email or not otp_code:
            return self.error("Se requieren tanto el correo electrónico como el código OTP.")

        # Verificar que existe un suario con ese email y que eestaa activo
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return self.error("El usuario no existe o no está activo.")
    
        if not user.otp_secret and not user.otp_base32:
            return self.error("El usuario no tiene 2FA configurado.")

        # Generar OTP
        verified = False
        
        # 1. Try Authenticator App (TOTP)
        if user.otp_base32:
            totp = pyotp.TOTP(user.otp_base32)
            if totp.verify(otp_code):
                verified = True

        # 2. Try Email OTP (Fallback)
        if not verified and user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp_code):
                verified = True

        if verified:
            # Generar tokens JWT
            refresh = RefreshToken.for_user(user)
            return self.response({
                "access": str(refresh.access_token), 
                "refresh": str(refresh)
            })

        return self.error("Error verificando código OTP.")



class RegistrarDispositivoView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        codigo = request.data.get('codigo')
        correo = request.data.get('correo')
        contrasenia = request.data.get('contrasenia')
        device_hash = request.data.get('hash')
        componentes = request.data.get('componentes')

        if not codigo or not correo or not device_hash or not contrasenia or not componentes:
            return self.error("correo, codigo, contraseña, hash y componentes requeridos.")

        # ✅ Autenticar usuario
        user = authenticate(request, email=correo, password=contrasenia)
        if not user or not user.is_active:
            return self.error("Credenciales inválidas.")

        if str(user.code) != str(codigo):
            return self.error("Código de usuario inválido.")

        # ✅ Crear u obtener el Device
        device, created = Device.objects.get_or_create(
            device_hash=device_hash,
            defaults={
                "hostname": componentes.get("nombre_maquina"),
            }
        )

        # ✅ Crear o actualizar el fingerprint (CLAVE DE ESCALABILIDAD)
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

        # 🔴 VALIDACIÓN CRÍTICA
        other_authorized = UserDevice.objects.filter(
            device=device,
            authorized=True
        ).exclude(user=user).exists()

        if other_authorized:
            return self.error(
                "Este equipo ya está autorizado para otro usuario. Contacte al administrador."
            )

        # ✅ Relación usuario-dispositivo
        user_device, ud_created = UserDevice.objects.get_or_create(
            user=user,
            device=device,
            defaults={"authorized": False}
        )

        if ud_created:
            return self.response("Dispositivo registrado. Pendiente de autorización.")

        if not user_device.authorized:
            return self.error("Dispositivo aún no autorizado.")

        # Registrar último login del dispositivo
        user_device.last_login = timezone.now()
        user_device.last_ip = request.META.get("REMOTE_ADDR")
        user_device.save()

        return self.response(f"Este dispositivo ya fue autorizado a {user.username}")


class PermissionsView(StandardAPIView):
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def get(self, request):
        user = request.user

        permissions = Permission.objects.filter(user=user) | Permission.objects.filter(group__user=user)
        permissions = permissions.distinct()

        permissions_data = [
            {
                "id": perm.id,
                "codename": perm.codename,
                "name": perm.name,
                "app": perm.content_type.app_label,
                "model": perm.content_type.model,
            }
            for perm in permissions
        ]

        groups = list(user.groups.values_list("name", flat=True))

        return self.response({
            "user": user.email,
            "groups": groups,
            "permissions": permissions_data,
        })
        
            
            
import time
import logging
from django.utils import timezone

logger = logging.getLogger("security")

class VerificarDispositivoView(StandardAPIView):
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        start_time = time.time()

        codigo = request.data.get("codigo")
        device_hash = request.data.get("hash")
        ip = request.META.get("REMOTE_ADDR")
    
        response_data = {
            "status": "UNAUTHORIZED",
            "message": "Acceso denegado."
        }

        if not codigo or not device_hash:
            self._log_attempt("Missing data", codigo, device_hash, ip)
            return self._constant_response(start_time, response_data)

        user = UserAccount.objects.filter(code=codigo, is_active=True).first()
        device = Device.objects.filter(device_hash=device_hash).first()

        if not user or not device:
            self._log_attempt("User or device not found", codigo, device_hash, ip)
            return self._constant_response(start_time, response_data)

        user_device = UserDevice.objects.filter(user=user, device=device).first()

        if not user_device:
            self._log_attempt("Device not linked to user", codigo, device_hash, ip)
            return self._constant_response(start_time, response_data)

        if not user_device.authorized:
            self._log_attempt("Device not authorized", codigo, device_hash, ip)
            return self._constant_response(start_time, response_data)

        #  Dispositivo autorizado
        user_device.last_login = timezone.now()
        user_device.last_ip = ip
        user_device.save()

        response_data = {
            "status": "AUTHORIZED",
            "message": "Dispositivo autorizado."
        }

        self._log_attempt("Authorized access", codigo, device_hash, ip)
        return self._constant_response(start_time, response_data)

    # -------------------------------------

    def _log_attempt(self, reason, codigo, device_hash, ip):
        logger.warning(
            f"[DEVICE CHECK] {reason} | code={codigo} | hash={device_hash} | ip={ip}"
        )

    def _constant_response(self, start_time, data, min_delay=1.2):
        """
        Evita timing attacks: siempre tarda lo mismo.
        """
        elapsed = time.time() - start_time
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        return self.response(data)



# ==================== SSO Portal Views ====================

class SSOLoginView(StandardAPIView):
    """
    Standard Email + Password login for SSO Portal.
    Redirects to OTP if 2FA is enabled.
    """
    permission_classes = [HasValidAPIKey]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return self.error("Email y contraseña son requeridos.")

        user = authenticate(request, email=email, password=password)

        if not user:
            return self.error("Credenciales inválidas.", status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return self.error("Tu cuenta está desactivada.")

        # Check for 2FA
        if user.two_factor_enabled:
            # 1. Check for Authenticator App (TOTP)
            if user.otp_base32:
                return self.response({
                    "otp_required": True,
                    "email": email,
                    "message": "Ingrese el código de su aplicación de autenticación."
                })

            # 2. Fallback to Email OTP
            # Need to generate OTP and send it (reusing logic from SendOTPLoginView)
            secret = user.otp_secret or pyotp.random_base32()
            user.otp_secret = secret
            user.save()

            totp = pyotp.TOTP(secret)
            otp = totp.now()

            site = Site.objects.get_current()
            domain = site.domain

            send_mail(
                'Su código de acceso (2FA)',
                f'Su código de acceso es {otp}',
                f'noreply@{domain}',
                [email],
                fail_silently=False,
            )

            return self.response({
                "otp_required": True,
                "email": email,
                "message": "Se requiere autenticación de dos factores (OTP enviado al correo)."
            })

        # No 2FA, return tokens
        refresh = RefreshToken.for_user(user)
        return self.response({
            "otp_required": False,
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        })


class MisSistemasView(StandardAPIView):
    """
    Retorna los sistemas a los que el usuario tiene acceso según sus grupos/roles.
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]

    def get(self, request):
        user = request.user
        
        # Obtener el perfil del usuario para el cargo
        try:
            from apps.user_profile.models import UserProfile
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            profile = None
        
        # Obtener los roles universales asociados a los grupos del usuario
        user_groups = user.groups.all()
        roles = RolUniversal.objects.filter(group__in=user_groups)
        
        if not roles.exists():
            return self.response({
                "usuario": {
                    "id": str(user.id),
                    "nombre": f"{user.first_name} {user.last_name}".strip(),
                    "email": user.email,
                    "rol": None,
                    "cargo": profile.cargo if profile else ""
                },
                "sistemas": [],
                "mensaje": "No tienes un rol/grupo con sistemas asignados."
            })
        
        # Consolidar sistemas de todos los roles del usuario sin duplicados
        sistemas = Sistema.objects.filter(roles__in=roles, activo=True).distinct().order_by('orden', 'nombre')
        
        sistemas_data = [
            {
                "id": str(s.id),
                "nombre": s.nombre,
                "codigo": s.codigo,
                "descripcion": s.descripcion,
                "url": s.url,
                "icono": s.icono,
                "color": s.color
            }
            for s in sistemas
        ]
        
        # Tomamos el primer rol como principal para la info del perfil en el dashboard
        principal_role = roles.order_by('nivel').first()
        
        return self.response({
            "usuario": {
                "id": str(user.id),
                "nombre": f"{user.first_name} {user.last_name}".strip(),
                "email": user.email,
                "rol": {
                    "id": str(principal_role.id),
                    "nombre": principal_role.nombre,
                    "codigo": principal_role.codigo
                },
                "cargo": profile.cargo if profile else ""
            },
            "sistemas": sistemas_data
        })


class SSOLogoutView(StandardAPIView):
    """
    SSO Logout endpoint.
    - Destroys Redis session
    - Blacklists the refresh token
    - Logs the event in AuditLog
    """
    permission_classes = [permissions.IsAuthenticated, HasValidAPIKey]
    
    def post(self, request):
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
        from .session_manager import SSOSessionManager
        from .models import AuditLog
        
        user = request.user
        
        try:
            # 1. Destroy Redis session
            SSOSessionManager.destroy_session(user.id)
            
            # 2. Blacklist all outstanding tokens for this user
            outstanding_tokens = OutstandingToken.objects.filter(user=user)
            for token in outstanding_tokens:
                BlacklistedToken.objects.get_or_create(token=token)
            
            # 3. Log the logout event
            AuditLog.log_event(
                action='LOGOUT',
                user=user,
                request=request,
                success=True,
                details={'method': 'manual'}
            )
            
            return self.response({
                "success": True,
                "message": "Sesión cerrada correctamente en todos los dispositivos."
            })
            
        except Exception as e:
            # Log failed logout attempt
            AuditLog.log_event(
                action='LOGOUT',
                user=user,
                request=request,
                success=False,
                details={'error': str(e)}
            )
            return self.error(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)