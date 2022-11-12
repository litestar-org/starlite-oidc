from functools import partial
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from anyio.to_thread import run_sync
from oic.oic import Client
from oic.utils.settings import ClientSettings
from pydantic import BaseModel, HttpUrl, root_validator, validator
from requests import Session
from starlite.types import Scopes

from starlite_oidc.types import RetrieveUserHandler

if TYPE_CHECKING:
    from typing import Literal


class ProviderMetaData(BaseModel):
    """Container for an OpenID Connect Provider (OP)."""

    issuer: Optional[str] = None
    """
    OP Issuer Identifier.
    """
    authorization_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's OAuth 2.0 Authorization endpoint.
    """
    jwks_uri: Optional[HttpUrl] = None
    """
    URL of the OP's JSON Web Key Set [JWK] document.
    """
    token_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's OAuth 2.0 Token endpoint.
    """
    user_info_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's user_info endpoint.
    """
    end_session_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's end Session endpoint.
    """
    introspection_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's token introspection endpoint.
    """
    registration_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's Dynamic Client Registration endpoint.
    """
    revocation_endpoint: Optional[HttpUrl] = None
    """
    URL of the OP's token revocation endpoint.
    """
    extra: Optional[Dict[str, Any]] = None
    """
    Extra arguments to OpenID Provider Metadata.

    Notes:
        - see the [openID reference](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
            for further details.
    """


class ClientMetaData(BaseModel):
    """Container for OIC Client meta data."""

    client_id: Optional[str] = None
    """
    Identifier representing the client.
    """
    client_secret: Optional[str] = None
    """
    Secret to authenticate the client with the OP.
    """
    extra: Optional[Dict[str, Any]] = None
    """
    Kwargs to pass to the client on init.
    """


class ProviderConfig(BaseModel):
    """Metadata for communicating with an OpenID Connect Provider (OP)."""

    provider_name: str
    """
    Name of the OP. Must be provided.
    """

    issuer: Optional[str] = None
    """
    OP Issuer Identifier. If this is specified discovery will be used to fetch the provider metadata,
    otherwise `provider_metadata` must be specified.
    """
    provider_metadata: Optional[ProviderMetaData] = None
    """
    OP metadata.
    """
    user_info_http_method: Optional[Literal["GET", "POST"]] = "GET"
    """
    HTTP method to use when sending the user_info Request. If set to `None`, no user_info request will be sent.
    """
    client_registration_info: Dict[str, Any] = {}
    """
    Client metadata to register your app dynamically with the provider.
    Either this or `registered_client_metadata` must be specified.
    """
    client_metadata: Optional[ClientMetaData] = None
    """
    Client metadata if your app is statically registered with the provider.
    Either this or `client_registration_info` must be specified.
    """
    auth_request_params: Dict[str, Any] = {}
    """
    Extra parameters that should be included in the authentication request.
    """
    session_refresh_interval_seconds: Optional[int] = None
    """
    Length of interval (in seconds) between attempted user data refreshes.
    """
    client_settings: ClientSettings = ClientSettings(requests_session=Session())
    """
    OIDC ClientSettings to use.
    """

    @root_validator()
    def validate(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure that the config includes required values.

        Args:
            values: A dictionary of values passed by the user.

        Returns:
            The validates dictionary of values
        """

        if not values.get("issuer") and not values.get("provider_metadata"):
            raise ValueError("either 'issuer' or 'provider_metadata' must be configured")

        if not values.get("client_registration_info") and not values.get("client_metadata"):
            raise ValueError("either 'client_registration_info' or 'client_metadata' must be configured")

        return values

    async def set_provider_metadata(self, client: "Client") -> None:
        """Registers provider's metadata.

        Args:
            client: Pyoidc client instance.

        Returns:
            None
        """

        discovery_response = await run_sync(client.provider_config, self.issuer)
        self.provider_metadata = ProviderMetaData(**discovery_response)

    async def register_client(self, client: "Client") -> None:
        """Register a client dynamically.

        Args:
            client: Pyoidc client instance.

        Returns:
            ClientMetaData
        """
        if not self.provider_metadata or not self.provider_metadata.registration_endpoint:
            raise ValueError(
                "'ProviderConfig.provider_metadata.registration_endpoint' is not set, "
                "cannot dynamically register an OpenID Connect Client"
            )

        registration_response = await run_sync(
            partial(client.register, url=self.provider_metadata.registration_endpoint, **self.client_registration_info)
        )
        self.client_metadata = ClientMetaData(**registration_response)


class OIDCPluginConfig(BaseModel):
    providers: Dict[str, ProviderConfig]
    """
    A dictionary mapping provider names to provider configs.
    """
    exclude: Optional[Union[str, List[str]]] = None
    """
    A pattern or list of patterns to skip in the Allowed Hosts middleware.
    """
    exclude_opt_key: Optional[str] = None
    """
    An identifier to use on routes to disable hosts check for a particular route.
    """
    scopes: Optional[Scopes] = None
    """
    ASGI scopes processed by the middleware, if None both 'http' and 'websocket' will be processed.
    """
    redirect_url: HttpUrl
    """
    A redirect path to redirect to.
    """
    post_logout_redirect_paths: Optional[List[str]]
    """
    A list of paths to redirect to after logout.
    """
    retrieve_user_handler: RetrieveUserHandler
    """
    A callable that receives the connection scope and the dictionary containing the auth result, 
    and returns the data to populate scope["user"].
    """

    @validator("providers")
    def validate(cls, value: Dict[str, ProviderConfig]) -> Dict[str, ProviderConfig]:
        if not value:
            raise ValueError("at least one provider must be configured")
        return value
