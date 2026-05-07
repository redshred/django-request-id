===============
django-keycloak
===============

Async-aware Django integration for Keycloak.

This is a hard fork of `skamansam/django-keycloak`_ (itself a fork of
`Peter-Slump/django-keycloak`_), maintained by Redshred and stripped down to
the OAuth2 / OIDC features we use:

- Authorization-code login that pairs a Django ``User`` with a Keycloak
  account (linked by ``sub``).
- A bearer-token authentication backend so a Keycloak access token can be
  used in place of an application-specific token.

UMA, fine-grained permissions, federation, the remote-user model, and the
upstream example apps have been removed.

Status
======

Pre-alpha. APIs and the data model are unstable while the strip-down and
async conversion are in progress.

License
=======

MIT, retained from upstream. See ``LICENSE``.

.. _skamansam/django-keycloak: https://github.com/skamansam/django-keycloak
.. _Peter-Slump/django-keycloak: https://github.com/Peter-Slump/django-keycloak
