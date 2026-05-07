import logging

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError

import django_keycloak.services.oidc_profile

logger = logging.getLogger(__name__)


class KeycloakAuthorizationBase:
    def get_user(self, user_id):
        UserModel = get_user_model()

        try:
            user = UserModel.objects.select_related("oidc_profile__realm").get(
                pk=user_id
            )
        except UserModel.DoesNotExist:
            return None

        profile = getattr(user, "oidc_profile", None)
        if profile is None or profile.refresh_expires_before is None:
            return None

        if profile.refresh_expires_before > timezone.now():
            return user
        return None

    def get_all_permissions(self, user_obj, obj=None):
        return set()

    def has_perm(self, user_obj, perm, obj=None):
        return False


class KeycloakAuthorizationCodeBackend(KeycloakAuthorizationBase):
    """Authenticate against Keycloak via the OAuth2 authorization-code flow."""

    def authenticate(self, request, code, redirect_uri):
        if not hasattr(request, "realm"):
            raise ImproperlyConfigured(
                "Add BaseKeycloakMiddleware to MIDDLEWARE"
            )

        oidc_profile = (
            django_keycloak.services.oidc_profile.update_or_create_from_code(
                client=request.realm.client,
                code=code,
                redirect_uri=redirect_uri,
            )
        )
        return oidc_profile.user


class KeycloakIDTokenAuthorizationBackend(KeycloakAuthorizationBase):
    """Authenticate a request bearing a Keycloak access token."""

    def authenticate(self, request, access_token):
        if not hasattr(request, "realm"):
            raise ImproperlyConfigured(
                "Add BaseKeycloakMiddleware to MIDDLEWARE"
            )

        try:
            oidc_profile = (
                django_keycloak.services.oidc_profile.get_or_create_from_id_token(
                    client=request.realm.client,
                    id_token=access_token,
                )
            )
        except ExpiredSignatureError:
            logger.debug("Bearer auth: access token expired.")
            return None
        except JWTClaimsError as e:
            logger.debug("Bearer auth: claim check failed: %s", e)
            return None
        except JWTError:
            logger.debug("Bearer auth: malformed access token.")
            return None

        return oidc_profile.user
