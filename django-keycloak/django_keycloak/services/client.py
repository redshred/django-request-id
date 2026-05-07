def get_openid_client(client):
    """
    :param django_keycloak.models.Client client:
    :rtype: keycloak.openid_connect.KeycloakOpenidConnect
    """
    openid = client.realm.realm_api_client.open_id_connect(
        client_id=client.client_id, client_secret=client.secret
    )

    if client.realm._well_known_oidc:
        openid.well_known.contents = client.realm.well_known_oidc

    return openid
