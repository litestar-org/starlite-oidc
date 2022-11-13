import os
import time
from typing import Callable, Dict, List, Union
from urllib.parse import urlparse

import pytest
from jwkest import jws
from oic.oic.message import AccessTokenResponse, IdToken, OpenIDSchema
from pytest import FixtureRequest
from starlite.middleware.session import SessionCookieConfig

from starlite_oidc import OIDCPlugin
from starlite_oidc.config import ClientMetaData, ProviderConfig, ProviderMetaData
from starlite_oidc.facade import OIDCFacade

from .constants import (
    ACCESS_TOKEN,
    CLIENT_BASE_URL,
    CLIENT_ID,
    CLIENT_NAME,
    CLIENT_SECRET,
    DYNAMIC_CLIENT_PROVIDER_NAME,
    NONCE,
    POST_LOGOUT_REDIRECT_PATH,
    PROVIDER_BASE_URL,
    PROVIDER_NAME,
    REDIRECT_URI,
    REFRESH_TOKEN,
    SCOPES,
    USER_INFO_SUB,
    USERNAME,
)
from .custom_types import IdTokenStore
from .util import signing_key

REDIRECT_ENDPOINT = urlparse(REDIRECT_URI).path


@pytest.fixture()
def client_metadata() -> ClientMetaData:
    """

    Returns:

    """
    return ClientMetaData(CLIENT_ID, CLIENT_SECRET)


@pytest.fixture()
def client_registration_info() -> ClientRegistrationInfo:
    """

    Returns:

    """
    return ClientRegistrationInfo(
        client_name=CLIENT_NAME,
        redirect_uris=[CLIENT_BASE_URL + REDIRECT_ENDPOINT, CLIENT_BASE_URL + "/redirect2"],
        post_logout_redirect_uris=[CLIENT_BASE_URL + POST_LOGOUT_REDIRECT_PATH, CLIENT_BASE_URL + "/logout2"],
    )


@pytest.fixture()
def provider_metadata() -> ProviderMetaData:
    """

    Returns:

    """
    return ProviderMetaData(
        issuer=PROVIDER_BASE_URL,
        authorization_endpoint=PROVIDER_BASE_URL + "/auth",
        jwks_uri=PROVIDER_BASE_URL + "/jwks",
        token_endpoint=PROVIDER_BASE_URL + "/token",
        user_info_endpoint=PROVIDER_BASE_URL + "/user_info",
        end_session_endpoint=PROVIDER_BASE_URL + "/logout",
        introspection_endpoint=PROVIDER_BASE_URL + "/introspect",
        registration_endpoint=PROVIDER_BASE_URL + "/register",
        revocation_endpoint=PROVIDER_BASE_URL + "/revoke",
    )


@pytest.fixture()
def provider_configuration(
    provider_metadata: ProviderMetaData,
    client_metadata: ClientMetaData,
    client_registration_info: ClientRegistrationInfo,
) -> Callable[..., ProviderConfig]:
    """

    Args:
        provider_metadata:
        client_metadata:
        client_registration_info:

    Returns:

    """

    def _provider_configuration(*, dynamic_provider: bool = False, dynamic_client: bool = False) -> ProviderConfig:
        if dynamic_provider:
            provider_config = {"issuer": provider_metadata.issuer}
        else:
            provider_config = {"provider_metadata": provider_metadata.copy()}

        if dynamic_client:
            client_config = {"client_registration_info": client_registration_info}
        else:
            client_config = {"client_metadata": client_metadata}

        return ProviderConfig(
            **provider_config,
            **client_config,
        )

    return _provider_configuration


@pytest.fixture()
def facade(request: FixtureRequest, provider_configuration: Callable[..., ProviderConfig]) -> OIDCFacade:
    """

    Args:
        request:
        provider_configuration:

    Returns:

    """
    param = getattr(request, "param", False)
    return OIDCFacade(provider_configuration(dynamic_client=param), CLIENT_BASE_URL + REDIRECT_ENDPOINT)


@pytest.fixture()
def auth(provider_configuration: Callable[..., ProviderConfig]) -> OIDCPlugin:
    """

    Args:
        provider_configuration:

    Returns:

    """
    return OIDCPlugin(
        {
            PROVIDER_NAME: provider_configuration(),
            DYNAMIC_CLIENT_PROVIDER_NAME: provider_configuration(dynamic_client=True),
        }
    )


@pytest.fixture(scope="session")
def session_config() -> SessionCookieConfig:
    """

    Returns:

    """
    # To set up session middleware.
    return SessionCookieConfig(secret=os.urandom(16))


@pytest.fixture()
def user_info() -> OpenIDSchema:
    """

    Returns:

    """
    return OpenIDSchema(sub=USER_INFO_SUB, name=USERNAME)


@pytest.fixture()
def id_token_store() -> IdTokenStore:
    """

    Returns:

    """
    times_now = int(time.time())
    id_token = IdToken(
        iss=PROVIDER_BASE_URL,
        sub=USER_INFO_SUB,
        aud=[CLIENT_ID],
        nonce=NONCE,
        iat=times_now - 60,
        exp=times_now + 60,
        at_hash=jws.left_hash(ACCESS_TOKEN),
    )
    id_token.jws_header = {"alg": signing_key.alg}
    id_token_jwt = id_token.to_jwt(key=[signing_key], algorithm=signing_key.alg)
    return IdTokenStore(id_token, id_token_jwt)


@pytest.fixture()
def access_token_response(id_token_store: IdTokenStore) -> AccessTokenResponse:
    """

    Args:
        id_token_store:

    Returns:

    """
    return AccessTokenResponse(
        access_token=ACCESS_TOKEN,
        refresh_token=REFRESH_TOKEN,
        token_type="Bearer",
        id_token=id_token_store.id_token,
        id_token_jwt=id_token_store.id_token_jwt,
        expires_in=60,
    )


@pytest.fixture()
def client_registration_response(client_registration_info: ClientRegistrationInfo) -> Dict[str, Union[List[str], str]]:
    """

    Args:
        client_registration_info:

    Returns:

    """
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_name": client_registration_info["client_name"],
        "redirect_uris": client_registration_info["redirect_uris"],
        "post_logout_redirect_uris": client_registration_info["post_logout_redirect_uris"],
        "registration_client_uri": PROVIDER_BASE_URL + "/register/client1",
        "registration_access_token": "registration_access_token",
    }


@pytest.fixture()
def signed_access_token(request: FixtureRequest) -> AccessTokenResponse:
    """

    Args:
        request:

    Returns:

    """
    param = getattr(request, "param", {})
    audience = ["starlite", CLIENT_ID, "account"]
    scopes = SCOPES.copy()
    if param.get("aud") is False:
        audience.remove(CLIENT_ID)
    if param.get("scopes") is False:
        scopes.pop()
    access_token = AccessTokenResponse(
        iss=PROVIDER_BASE_URL, exp=int(time.time()) + param.get("expires_in", 60), aud=audience, scope=" ".join(scopes)
    )
    access_token.jws_header = {"alg": signing_key.alg}
    return access_token


@pytest.fixture()
def introspection_result(request: FixtureRequest) -> Dict[str, Union[bool, int, str, List[str]]]:
    """

    Args:
        request:

    Returns:

    """
    kwargs = getattr(request, "param", {})
    active = kwargs.get("active", True)
    audience = ["admin", "user", "client1"]
    scopes = SCOPES.copy()
    if kwargs.get("aud") == "no_client":
        audience.remove("client1")
    if kwargs.get("scope") == "extra":
        scopes.pop()
    exp = 300
    if kwargs.get("short_lived", False):
        exp = 1

    return {"active": active, "aud": audience, "scope": " ".join(scopes), "exp": int(time.time()) + exp}
