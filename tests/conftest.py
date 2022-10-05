import time
from typing import Callable, Dict, List, Union

import pytest
from jwkest import jws
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
CLIENT_SECRET: str = "secret1"
PROVIDER_BASE_URL: str = "https://idp.example.com"
CLIENT_BASE_URL: str = "https://client.example.com"
REDIRECT_ENDPOINT: str = "/redirect"
ACCESS_TOKEN = "test-access-token"
USERINFO_SUB = "user1"


@pytest.fixture()
def client_metadata() -> ClientMetadata:
    return ClientMetadata(CLIENT_ID, "secret1")


@pytest.fixture()
def client_registration_info() -> ClientRegistrationInfo:
    return ClientRegistrationInfo(
        client_name="Test Client",
        redirect_uris=[CLIENT_BASE_URL + REDIRECT_ENDPOINT, CLIENT_BASE_URL + "/redirect2"],
        post_logout_redirect_uris=[CLIENT_BASE_URL + "/logout", CLIENT_BASE_URL + "/logout2"],
    )


@pytest.fixture()
def provider_metadata() -> ProviderMetadata:
    return ProviderMetadata(
        issuer=PROVIDER_BASE_URL,
        authorization_endpoint=PROVIDER_BASE_URL + "/auth",
        jwks_uri=PROVIDER_BASE_URL + "/jwks",
        token_endpoint=PROVIDER_BASE_URL + "/token",
        userinfo_endpoint=PROVIDER_BASE_URL + "/userinfo",
        end_session_endpoint=PROVIDER_BASE_URL + "/logout",
        introspection_endpoint=PROVIDER_BASE_URL + "/introspect",
        registration_endpoint=PROVIDER_BASE_URL + "/register",
        revocation_endpoint=PROVIDER_BASE_URL + "/revoke",
    )


@pytest.fixture()
def provider_configuration(
    provider_metadata: ProviderMetadata,
    client_metadata: ClientMetadata,
    client_registration_info: ClientRegistrationInfo,
) -> Callable[..., ProviderConfiguration]:
    def _provider_configuration(
        *, dynamic_provider: bool = False, dynamic_client: bool = False
    ) -> ProviderConfiguration:
        if dynamic_provider:
            provider_config = {"issuer": provider_metadata["issuer"]}
        else:
            provider_config = {"provider_metadata": provider_metadata}

        if dynamic_client:
            client_config = {"client_registration_info": client_registration_info}
        else:
            client_config = {"client_metadata": client_metadata}

        return ProviderConfiguration(
            **provider_config,
            **client_config,
            token_introspection_cache_config={"maxsize": 1, "ttl": 60},
        )

    return _provider_configuration


@pytest.fixture()
def facade(provider_configuration: Callable[..., ProviderConfiguration]) -> PyoidcFacade:
    return PyoidcFacade(provider_configuration(), CLIENT_BASE_URL + REDIRECT_ENDPOINT)


@pytest.fixture()
def userinfo() -> OpenIDSchema:
    return OpenIDSchema(sub=USERINFO_SUB, name="Test User")


@pytest.fixture()
def id_token_store() -> IdTokenStore:
    times_now = int(time.time())
    _id_token = IdToken(
        iss=PROVIDER_BASE_URL,
        sub=USERINFO_SUB,
        aud=[CLIENT_ID],
        nonce="test-nonce",
        iat=times_now - 60,
        exp=times_now + 60,
        at_hash=jws.left_hash(ACCESS_TOKEN),
    )
    _id_token.jws_header = {"alg": "RS256"}
    id_token_jwt, id_token_signing_key = signed_id_token(_id_token)
    return IdTokenStore(_id_token, id_token_jwt, id_token_signing_key)


@pytest.fixture()
def access_token_response(id_token_store) -> AccessTokenResponse:
    return AccessTokenResponse(
        access_token=ACCESS_TOKEN,
        refresh_token="refresh-token",
        token_type="Bearer",
        id_token=id_token_store.id_token,
        id_token_jwt=id_token_store.id_token_jwt,
        expires_in=60,
    )


@pytest.fixture()
def client_registration_response(client_registration_info: ClientRegistrationInfo) -> Dict[str, Union[List[str], str]]:
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_name": client_registration_info["client_name"],
        "redirect_uris": client_registration_info["redirect_uris"],
        "post_logout_redirect_uris": client_registration_info["post_logout_redirect_uris"],
        "registration_client_uri": "https://idp.example.com/register/client1",
        "registration_access_token": "registration_access_token",
    }
