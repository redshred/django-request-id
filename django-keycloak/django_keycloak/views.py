import logging
import secrets

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http.response import (
    HttpResponseBadRequest,
    HttpResponseRedirect,
    HttpResponseServerError,
)
from django.shortcuts import resolve_url
from django.urls.base import reverse
from django.views.generic.base import RedirectView

logger = logging.getLogger(__name__)


SESSION_STATE_KEY = "oidc_state"
SESSION_NEXT_PATH_KEY = "oidc_next_path"


class Login(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        state = secrets.token_urlsafe(32)
        redirect_uri = self.request.build_absolute_uri(
            location=reverse("keycloak_login_complete")
        )

        self.request.session[SESSION_STATE_KEY] = state
        self.request.session[SESSION_NEXT_PATH_KEY] = self.request.GET.get(
            "next"
        )

        authorization_url = (
            self.request.realm.client.openid_api_client.authorization_url(
                redirect_uri=redirect_uri,
                # See upstream note: 'openid given_name family_name email'
                # produced "invalid_scope" against newer Keycloak releases.
                # https://github.com/oauth2-proxy/oauth2-proxy/issues/1448
                scope="openid profile email",
                state=state,
            )
        )

        if self.request.realm.server.internal_url:
            authorization_url = authorization_url.replace(
                self.request.realm.server.internal_url,
                self.request.realm.server.url,
                1,
            )

        logger.debug(authorization_url)
        return authorization_url


class LoginComplete(RedirectView):
    def get(self, *args, **kwargs):
        request = self.request

        if "error" in request.GET:
            return HttpResponseServerError(request.GET["error"])

        if "code" not in request.GET or "state" not in request.GET:
            return HttpResponseBadRequest()

        expected_state = request.session.pop(SESSION_STATE_KEY, None)
        next_path = request.session.pop(SESSION_NEXT_PATH_KEY, None)

        if not expected_state or request.GET["state"] != expected_state:
            return HttpResponseRedirect(reverse("keycloak_login"))

        redirect_uri = request.build_absolute_uri(
            location=reverse("keycloak_login_complete")
        )

        user = authenticate(
            request=request,
            code=request.GET["code"],
            redirect_uri=redirect_uri,
        )
        if user is None:
            return HttpResponseRedirect(reverse("keycloak_login"))

        login(request, user)

        if settings.LOGIN_REDIRECT_URL:
            return HttpResponseRedirect(
                resolve_url(settings.LOGIN_REDIRECT_URL)
            )
        return HttpResponseRedirect(next_path or "/")


class Logout(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        if hasattr(self.request.user, "oidc_profile"):
            profile = self.request.user.oidc_profile
            self.request.realm.client.openid_api_client.logout(
                profile.refresh_token
            )
            profile.access_token = None
            profile.expires_before = None
            profile.refresh_token = None
            profile.refresh_expires_before = None
            profile.save(
                update_fields=[
                    "access_token",
                    "expires_before",
                    "refresh_token",
                    "refresh_expires_before",
                ]
            )

        logout(self.request)

        if settings.LOGOUT_REDIRECT_URL:
            return resolve_url(settings.LOGOUT_REDIRECT_URL)
        return reverse("keycloak_login")
