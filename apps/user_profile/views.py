from datetime import datetime, timedelta

from rest_framework import permissions, status
from rest_framework_api.views import StandardAPIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils import timezone
from botocore.signers import CloudFrontSigner

from core.permissions import HasValidAPIKey
from .models import UserProfile
# from apps.media.models import Media
from apps.authentication.serializers import UserPublicSerializer
from .serializers import UserProfileSerializer

# ... (Standard imports and standard views)

class MyUserProfileView(StandardAPIView):
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        user_profile = UserProfile.objects.get(user=user)
        serialized_user_profile = UserProfileSerializer(user_profile).data
        return self.response(serialized_user_profile)

# ... (DetailUserProfileView)

# Commenting out views that depend on Media
"""
class GetMyProfilePictureView(StandardAPIView):
    # ...
class GetMyBannerPictureView(StandardAPIView):
    # ...
class UploadProfilePictureView(StandardAPIView):
    # ...
class UploadBannerPictureView(StandardAPIView):
    # ...
"""


class GetMyProfilePicture(StandardAPIView):
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        user = request.user
        profile = UserProfile.objects.get(user=user)


class UpdateUserProfileView(StandardAPIView):
    permission_classes = [HasValidAPIKey, permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request):
        user = request.user
        profile = UserProfile.objects.get(user=user)
        
        biography = request.data.get("biography", None)
        birthday = request.data.get("birthday", None)
        website = request.data.get("website", None)
        instagram = request.data.get("instagram", None)
        facebook = request.data.get("facebook", None)
        threads = request.data.get("threads", None)
        linkedin = request.data.get("linkedin", None)
        youtube = request.data.get("youtube", None)
        tiktok = request.data.get("tiktok", None)
        github = request.data.get("github", None)
        gitlab = request.data.get("gitlab", None)

        try:
            if biography:
                profile.biography = sanitize_html(biography)
            if birthday:
                # Validar y transformar el formato de la fecha
                try:
                    formatted_birthday = datetime.strptime(birthday, "%Y-%m-%d").date()
                    profile.birthday = formatted_birthday
                except ValueError:
                    raise ValidationError("Invalid date format. Use YYYY-MM-DD.")
            if instagram:
                profile.instagram = sanitize_url(instagram)
            if facebook:
                profile.facebook = sanitize_url(facebook)
            if threads:
                profile.threads = sanitize_url(threads)
            if linkedin:
                profile.linkedin = sanitize_url(linkedin)
            if youtube:
                profile.youtube = sanitize_url(youtube)
            if tiktok:
                profile.tiktok = sanitize_url(tiktok)
            if github:
                profile.github = sanitize_url(github)
            if gitlab:
                profile.gitlab = sanitize_url(gitlab)
            if website:
                profile.website = sanitize_url(website)

            profile.save()

            return self.response("Profile has been updated successfully.")
        except ValidationError as e:
            return self.error(str(e))

