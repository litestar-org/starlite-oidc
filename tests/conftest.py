import time
from unittest.mock import create_autospec

import pytest
from oic.oic.message import AccessTokenResponse, IdToken, OpenIDSchema

from starlite_oidc.provider_configuration import (
    ClientMetadata,
    ClientRegistrationInfo,
    ProviderConfiguration,
    ProviderMetadata,
)
from starlite_oidc.pyoidc_facade import PyoidcFacade

from .custom_types import IdTokenStore
from .util import signed_id_token

CLIENT_ID: str = "client1"
PROVIDER_BASEURL: str = "https://idp.example.com"
REDIRECT_URI: str = "https://client.example.com/redirect"
TIMES_NOW = int(time.time())


@pytest.fixture()
def client_metadata() -> ClientMetadata:
    return ClientMetadata(CLIENT_ID, "secret1")


@pytest.fixture()
def client_registration_info() -> ClientRegistrationInfo:
    return ClientRegistrationInfo(
        redirect_uris=["https://client.example.com/redirect"],
        post_logout_redirect_uris=["https://client.example.com/logout"],
    )


@pytest.fixture()
def provider_metadata() -> ProviderMetadata:
    return ProviderMetadata(
        issuer=PROVIDER_BASEURL,
        authorization_endpoint=PROVIDER_BASEURL + "/auth",
        jwks_uri=PROVIDER_BASEURL + "/jwks",
        token_endpoint=PROVIDER_BASEURL + "/token",
        userinfo_endpoint=PROVIDER_BASEURL + "/userinfo",
        introspection_endpoint=PROVIDER_BASEURL + "/introspect",
        registration_endpoint=PROVIDER_BASEURL + "/register",
        revocation_endpoint=PROVIDER_BASEURL + "/revoke",
    )


@pytest.fixture()
def provider_configuration(
    provider_metadata: ProviderMetadata, client_metadata: ClientMetadata
) -> ProviderConfiguration:
    return ProviderConfiguration(
        provider_metadata=provider_metadata,
        client_metadata=client_metadata,
        token_introspection_cache_config={"maxsize": 1, "ttl": 60},
    )


@pytest.fixture()
def facade(provider_configuration) -> PyoidcFacade:
    return PyoidcFacade(provider_configuration, REDIRECT_URI)


@pytest.fixture()
def client_mock() -> PyoidcFacade:
    return create_autospec(PyoidcFacade, spec_set=True, instance=True)


@pytest.fixture()
def userinfo() -> OpenIDSchema:
    return OpenIDSchema(sub="test-sub")


@pytest.fixture()
def id_token_store() -> IdTokenStore:
    _id_token = IdToken(
        iss=PROVIDER_BASEURL, sub="test-sub", aud=[CLIENT_ID], nonce="test-nonce", iat=TIMES_NOW, exp=TIMES_NOW + 60
    )
    _id_token.jws_header = {"alg": "RS256"}
    id_token_jwt, id_token_signing_key = signed_id_token(_id_token)
    return IdTokenStore(_id_token, id_token_jwt, id_token_signing_key)


@pytest.fixture()
def access_token_response(id_token_store) -> AccessTokenResponse:
    return AccessTokenResponse(
        access_token="test-access-token",
        refresh_token="refresh-token",
        token_type="Bearer",
        id_token=id_token_store.id_token,
        id_token_jwt=id_token_store.id_token_jwt,
        expires_in=TIMES_NOW + 60,
    )
