import re

from django.conf import settings
from django.contrib.auth import authenticate
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject

from django_keycloak.models import Realm
from django_keycloak.response import HttpResponseNotAuthorized


def get_realm(request):
    if not hasattr(request, "_cached_realm"):
        request._cached_realm = Realm.objects.first()
    return request._cached_realm


class BaseKeycloakMiddleware(MiddlewareMixin):
    set_session_state_cookie = True

    def process_request(self, request):
        request.realm = SimpleLazyObject(lambda: get_realm(request))

    def process_response(self, request, response):
        if self.set_session_state_cookie:
            return self._set_session_state_cookie(request, response)
        return response

    def _set_session_state_cookie(self, request, response):
        if not request.user.is_authenticated or not hasattr(
            request.user, "oidc_profile"
        ):
            return response

        jwt = request.user.oidc_profile.jwt
        if not jwt:
            return response

        cookie_name = getattr(
            settings, "KEYCLOAK_SESSION_STATE_COOKIE_NAME", "session_state"
        )
        response.set_cookie(
            cookie_name,
            value=jwt["session_state"],
            expires=request.user.oidc_profile.refresh_expires_before,
            httponly=False,
        )
        return response


class KeycloakStatelessBearerAuthenticationMiddleware(BaseKeycloakMiddleware):
    """Accept a Keycloak access token via ``Authorization: Bearer ...``."""

    set_session_state_cookie = False
    header_key = "HTTP_AUTHORIZATION"

    def process_request(self, request):
        super().process_request(request=request)

        exempt_paths = getattr(
            settings, "KEYCLOAK_BEARER_AUTHENTICATION_EXEMPT_PATHS", None
        )
        if exempt_paths:
            path = request.path_info.lstrip("/")
            if any(re.match(m, path) for m in exempt_paths):
                return

        if self.header_key not in request.META:
            return HttpResponseNotAuthorized(
                attributes={"realm": request.realm.name}
            )

        try:
            scheme, token = request.META[self.header_key].split(" ", 1)
        except ValueError:
            return HttpResponseNotAuthorized(
                attributes={"realm": request.realm.name}
            )
        if scheme.lower() != "bearer":
            return HttpResponseNotAuthorized(
                attributes={"realm": request.realm.name}
            )

        user = authenticate(request=request, access_token=token)
        if user is None:
            return HttpResponseNotAuthorized(
                attributes={"realm": request.realm.name}
            )
        request.user = user
