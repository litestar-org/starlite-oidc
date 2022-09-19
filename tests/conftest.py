import pytest

from starlite_oidc.provider_configuration import (
    ClientMetadata,
    ClientRegistrationInfo,
    ProviderConfiguration,
    ProviderMetadata,
)
from starlite_oidc.pyoidc_facade import PyoidcFacade

PROVIDER_BASEURL: str = "https://idp.example.com"
REDIRECT_URI: str = "https://client.example.com/redirect"


@pytest.fixture()
def client_metadata() -> ClientMetadata:
    return ClientMetadata("client1", "secret1")


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
def provider_configuration(provider_metadata: ProviderMetadata,
                           client_metadata: ClientMetadata) -> ProviderConfiguration:
    return ProviderConfiguration(
        provider_metadata=provider_metadata,
        client_metadata=client_metadata,
        token_introspection_cache_config={"maxsize": 1, "ttl": 60},
    )


@pytest.fixture()
def facade(provider_configuration) -> PyoidcFacade:
    return PyoidcFacade(provider_configuration, REDIRECT_URI)
