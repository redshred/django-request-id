import json
import logging

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property

logger = logging.getLogger(__name__)


class Server(models.Model):
    url = models.CharField(max_length=255)

    internal_url = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="URL on internal network calls. For example when used with "
        "Docker Compose. Only supply when internal calls should go to a "
        "different url than the end-user will communicate with.",
    )

    def __str__(self):
        return self.url


class Realm(models.Model):
    server = models.ForeignKey(
        Server, related_name="realms", on_delete=models.CASCADE
    )

    name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Name as known on the Keycloak server. This name is used in "
        "the API paths of this Realm.",
    )

    _certs = models.TextField()
    _well_known_oidc = models.TextField(blank=True)

    @property
    def certs(self):
        return json.loads(self._certs)

    @certs.setter
    def certs(self, content):
        self._certs = json.dumps(content)

    @property
    def well_known_oidc(self):
        return json.loads(self._well_known_oidc)

    @well_known_oidc.setter
    def well_known_oidc(self, content):
        self._well_known_oidc = json.dumps(content)

    _keycloak_realm = None

    @cached_property
    def realm_api_client(self):
        if self._keycloak_realm is None:
            import django_keycloak.services.realm

            self._keycloak_realm = (
                django_keycloak.services.realm.get_realm_api_client(realm=self)
            )
        return self._keycloak_realm

    def __str__(self):
        return self.name


class Client(models.Model):
    realm = models.OneToOneField(
        Realm, related_name="client", on_delete=models.CASCADE
    )

    client_id = models.CharField(max_length=255)
    secret = models.CharField(max_length=255)

    @cached_property
    def openid_api_client(self):
        import django_keycloak.services.client

        return django_keycloak.services.client.get_openid_client(client=self)

    def __str__(self):
        return self.client_id


class TokenModelAbstract(models.Model):
    access_token = models.TextField(null=True)
    expires_before = models.DateTimeField(null=True)

    refresh_token = models.TextField(null=True)
    refresh_expires_before = models.DateTimeField(null=True)

    class Meta:
        abstract = True

    @property
    def is_active(self):
        if not self.access_token or not self.expires_before:
            return False
        return self.expires_before > timezone.now()


class OpenIdConnectProfile(TokenModelAbstract):
    sub = models.CharField(max_length=255, unique=True)

    realm = models.ForeignKey(
        "django_keycloak.Realm",
        related_name="openid_profiles",
        on_delete=models.CASCADE,
    )

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name="oidc_profile",
        on_delete=models.CASCADE,
    )

    class Meta:
        swappable = "KEYCLOAK_OIDC_PROFILE_MODEL"

    @property
    def jwt(self):
        if not self.is_active:
            return None
        client = self.realm.client
        return client.openid_api_client.decode_token(
            token=self.access_token,
            key=client.realm.certs,
            algorithms=client.openid_api_client.well_known[
                "id_token_signing_alg_values_supported"
            ],
        )
