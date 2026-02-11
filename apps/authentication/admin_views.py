import time
import logging

from rest_framework import permissions
from rest_framework_api.views import StandardAPIView
from rest_framework import status

from apps.authentication.models import UserDevice
from apps.authentication.serializers import UserDeviceListSerializer

logger = logging.getLogger(__name__)

# ============================================
# ADMIN: Device Management Views
# ============================================

class UserDeviceListView(StandardAPIView):
    """
    GET /api/authentication/user-devices/
    Lista todos los dispositivos de usuarios (solo admin)
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        user_devices = UserDevice.objects.select_related(
            'user', 'device'
        ).order_by('-last_login')
        
        serializer = UserDeviceListSerializer(user_devices, many=True)
        return self.response(serializer.data)


class AuthorizeDeviceView(StandardAPIView):
    """
    PATCH /api/authentication/user-devices/{id}/authorize/
    Autoriza un dispositivo (solo admin)
    """
    permission_classes = [permissions.IsAdminUser]
    
    def patch(self, request, device_id):
        try:
            user_device = UserDevice.objects.get(id=device_id)
            user_device.authorized = True
            user_device.save()
            
            logger.info(
                f"[ADMIN] Device authorized: {user_device.device.device_hash} "
                f"for user {user_device.user.email} by {request.user.email}"
            )
            
            return self.response({
                "message": "Dispositivo autorizado exitosamente",
                "authorized": True
            })
        except UserDevice.DoesNotExist:
            return self.error(
                "Dispositivo no encontrado",
                status=status.HTTP_404_NOT_FOUND
            )


class RevokeDeviceView(StandardAPIView):
    """
    PATCH /api/authentication/user-devices/{id}/revoke/
    Bloquea/revoca un dispositivo (solo admin)
    """
    permission_classes = [permissions.IsAdminUser]
    
    def patch(self, request, device_id):
        try:
            user_device = UserDevice.objects.get(id=device_id)
            user_device.authorized = False
            user_device.save()
            
            logger.warning(
                f"[ADMIN] Device revoked: {user_device.device.device_hash} "
                f"for user {user_device.user.email} by {request.user.email}"
            )
            
            return self.response({
                "message": "Dispositivo bloqueado exitosamente",
                "authorized": False
            })
        except UserDevice.DoesNotExist:
            return self.error(
                "Dispositivo no encontrado",
                status=status.HTTP_404_NOT_FOUND
            )
