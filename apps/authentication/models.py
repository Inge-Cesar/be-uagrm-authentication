import uuid

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager
)

from django.conf import settings
from utils.string_utils import sanitize_username



# ==================== SSO Portal Models ====================

class Sistema(models.Model):
    """
    Representa un sistema/aplicación externa a la que los usuarios pueden acceder.
    Ej: Sistema Académico, RRHH, Financiero, etc.
    """
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    nombre = models.CharField(max_length=100)
    codigo = models.SlugField(unique=True, max_length=50)
    descripcion = models.TextField(blank=True, default='')
    url = models.URLField()
    icono = models.CharField(max_length=50, default='📦')  # Emoji o clase de icono
    color = models.CharField(max_length=7, default='#3498db')  # Color hex
    activo = models.BooleanField(default=True)
    orden = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['orden', 'nombre']
        verbose_name = 'Sistema'
        verbose_name_plural = 'Sistemas'

    def __str__(self):
        return f"{self.icono} {self.nombre}"


class RolUniversal(models.Model):
    """
    Rol institucional que agrupa acceso a múltiples sistemas.
    Ej: Rectorado, Vicerrectorado, Decano, etc.
    """
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    nombre = models.CharField(max_length=100)
    codigo = models.SlugField(unique=True, max_length=50)
    descripcion = models.TextField(blank=True, default='')
    nivel = models.IntegerField(default=10)  # 1 = más alto (Rectorado), 10 = más bajo
    sistemas = models.ManyToManyField(Sistema, blank=True, related_name='roles')
    
    group = models.OneToOneField(
        'auth.Group', 
        on_delete=models.CASCADE, 
        related_name='rol_universal', 
        null=True, 
        blank=True,
        verbose_name="Grupo de Django Relacionado"
    )
    
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['nivel', 'nombre']
        verbose_name = 'Rol Universal'
        verbose_name_plural = 'Roles Universales'

    def __str__(self):
        return self.nombre

    def get_sistemas_count(self):
        return self.sistemas.count()



class UserAccountManager(BaseUserManager):

    RESTRICTED_USERNAMES = ["admin", "undefined", "null", "superuser", "root", "system"]
    
    def create_user(self, email, password=None, **extra_fields):

        if not email:
            raise ValueError("Users must have an email address.")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)

        first_name = extra_fields.get("first_name", None)
        last_name = extra_fields.get("last_name", None)

        # Validar y sanitizar el nombre de usuario
        username = extra_fields.get("username", None)
        if username:
            sanitized_username = sanitize_username(username)

            # Verificar si el nombre de usuario está en la lista de restringidos
            if sanitized_username.lower() in self.RESTRICTED_USERNAMES:
                raise ValueError(f"The username '{sanitized_username}' is not allowed.")
            
            user.username = sanitized_username
        
        user.first_name = first_name
        user.last_name = last_name

        username = extra_fields.get("username", None)
        if username and username.lower() in self.RESTRICTED_USERNAMES:
            raise ValueError(f"The username '{username}' is not allowed.")
        
        user.save(using=self._db)

        return user
    
    def create_superuser(self, email, password, **extra_Fields):
        user = self.create_user(email, password, **extra_Fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.role = 'admin'
        user.save(using=self._db)
        return user
    

class UserAccount(AbstractBaseUser, PermissionsMixin):

    roles = (
        ("customer", "Customer"),
        ("seller", "Seller"),
        ("admin", "Admin"),
        ("moderator", "Moderator"),
        ("helper", "Helper"),
        ("editor", "Editor"),
    )

    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    code = models.BigIntegerField(unique=True, null=True, blank=True)

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    role = models.CharField(max_length=20, choices=roles, default="customer")
    verified = models.BooleanField(default=False)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    two_factor_enabled = models.BooleanField(default=False)
    otpauth_url = models.CharField(max_length=225, blank=True, null=True)
    otp_base32 = models.CharField(max_length=255, null=True)
    otp_secret = models.CharField(max_length=255, null=True)
    qr_code = models.ImageField(upload_to="qrcode/", blank=True, null=True)
    login_otp = models.CharField(max_length=255, null=True, blank=True)
    login_otp_used = models.BooleanField(default=False)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    login_ip = models.CharField(max_length=255, blank=True, null=True)

    objects = UserAccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    def __str__(self):
        return self.username

    def get_qr_code(self):
        if self.qr_code and hasattr(self.qr_code, "url"):
            return self.qr_code.url
        return None
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
    


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    device_hash = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=False)

    hostname = models.CharField(max_length=255, blank=True, null=True)
    os = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.device_hash
    class Meta:
        verbose_name = 'Dispositivo'
        verbose_name_plural = 'Dispositivos'
    

class DeviceFingerprint(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name="fingerprint")

    uuid_sistema = models.CharField(max_length=255, db_index=True)
    numero_serie_cpu = models.CharField(max_length=255, db_index=True)
    numero_serie_disco = models.CharField(max_length=255, db_index=True)
    baseboard_serial = models.CharField(max_length=255, db_index=True)
    bios_serial = models.CharField(max_length=255, db_index=True)
    mac_address = models.CharField(max_length=255, db_index=True)
    nombre_maquina = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)


class UserDevice(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices")
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="users")

    authorized = models.BooleanField(default=False)
    authorized_at = models.DateTimeField(null=True, blank=True)
    authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="devices_authorized"
    )

    last_login = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        unique_together = ("user", "device")
        verbose_name = 'Dispositivo de usuario'
        verbose_name_plural = 'Dispositivos de usuario'

# ==================== Audit Logging ====================

class AuditLog(models.Model):
    """
    SSO Audit Log for tracking authentication events.
    Records LOGIN, LOGOUT, REFRESH, and security-related events.
    """
    ACTION_CHOICES = (
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('REFRESH', 'Token Refresh'),
        ('LOGIN_FAILED', 'Failed Login Attempt'),
        ('SESSION_EXPIRED', 'Session Expired'),
        ('DEVICE_MISMATCH', 'Device Hash Mismatch'),
    )
    
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    user = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name='audit_logs',
        null=True,
        blank=True
    )
    email = models.EmailField(null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    device_hash = models.CharField(max_length=255, null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    success = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]
    
    def __str__(self):
        user_str = self.user.email if self.user else self.email or 'Unknown'
        return f"{self.action} - {user_str} - {self.timestamp}"
    
    @classmethod
    def log_event(cls, action, user=None, email=None, request=None, success=True, details=None):
        """Convenience method to create audit log entries."""
        ip_address = None
        user_agent = None
        device_hash = None
        
        if request:
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            device_hash = request.META.get('HTTP_X_HARDWARE_SIG', None)
        
        return cls.objects.create(
            user=user,
            email=email or (user.email if user else None),
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            device_hash=device_hash,
            success=success,
            details=details or {}
        )

    


    

