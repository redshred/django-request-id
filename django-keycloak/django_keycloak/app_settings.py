# Model used to store the OIDC profile (the link between a Keycloak `sub`
# and a Django user). Override via Django's swappable-model setting if you
# need to swap in your own profile model.
KEYCLOAK_OIDC_PROFILE_MODEL = "django_keycloak.OpenIdConnectProfile"
