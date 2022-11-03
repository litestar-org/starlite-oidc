import collections.abc
import logging
from typing import Any, Dict, Optional

import requests
from oic.oic import Client
from oic.utils.settings import ClientSettings

logger = logging.getLogger(__name__)


class OIDCData(collections.abc.MutableMapping):
    """Basic OIDC data representation providing validation of required
    fields."""

    def __init__(self, *args: Any, **kwargs: Any):
        """
        Args:
            args (List[Tuple[String, String]]): key-value pairs to store
            kwargs (Dict[string, string]): key-value pairs to store
        """
        self.store = dict()
        self.update(dict(*args, **kwargs))

    def __getitem__(self, key: str):
        return self.store[key]

    def __setitem__(self, key: str, value: Any):
        self.store[key] = value

    def __delitem__(self, key: str):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def __str__(self):
        data = self.store.copy()
        if "client_secret" in data:
            data["client_secret"] = "<masked>"
        return str(data)

    def __repr__(self):
        return str(self.store)

    def __bool__(self):
        return True

    def copy(self, **kwargs: Any):
        values = self.to_dict()
        values.update(kwargs)
        return self.__class__(**values)

    def to_dict(self):
        return self.store.copy()


class ProviderMetadata(OIDCData):
    def __init__(
        self,
        issuer: Optional[str] = None,
        authorization_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        introspection_endpoint: Optional[str] = None,
        registration_endpoint: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """OpenID Providers have metadata describing their configuration.

        Args:
            issuer: OP Issuer Identifier.
            authorization_endpoint: URL of the OP's OAuth 2.0 Authorization Endpoint.
            jwks_uri: URL of the OP's JSON Web Key Set [JWK] document.
            token_endpoint: URL of the OP's OAuth 2.0 Token Endpoint.
            userinfo_endpoint: URL of the OP's UserInfo Endpoint.
            introspection_endpoint: URL of the OP's token introspection endpoint.
            registration_endpoint: URL of the OP's Dynamic Client Registration Endpoint.
            **kwargs : Extra arguments to [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
        """
        super().__init__(
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            jwks_uri=jwks_uri,
            introspection_endpoint=introspection_endpoint,
            registration_endpoint=registration_endpoint,
            **kwargs
        )


class ClientRegistrationInfo(OIDCData):
    pass


class ClientMetadata(OIDCData):
    def __init__(self, client_id: str = None, client_secret: str = None, **kwargs: Any):
        """
        Args:
            client_id : client identifier representing the client
            client_secret : client secret to authenticate the client with the OP
            kwargs : key-value pairs
        """
        super().__init__(client_id=client_id, client_secret=client_secret, **kwargs)


class ProviderConfiguration:
    """Metadata for communicating with an OpenID Connect Provider (OP)."""

    DEFAULT_REQUEST_TIMEOUT = 5

    def __init__(
        self,
        issuer: Optional[str] = None,
        provider_metadata: Optional[ProviderMetadata] = None,
        userinfo_http_method: Optional[str] = "GET",
        client_registration_info: Optional[ClientRegistrationInfo] = None,
        client_metadata: Optional[ClientMetadata] = None,
        auth_request_params: Optional[Dict[str, Any]] = None,
        session_refresh_interval_seconds: Optional[int] = None,
        requests_session: Optional[requests.Session] = None,
    ) -> None:
        """
        Args:
            issuer: OP Issuer Identifier. If this is specified discovery will be used to fetch the provider
                metadata, otherwise `provider_metadata` must be specified.
            provider_metadata: OP metadata,
            userinfo_http_method: HTTP method (GET or POST) to use when sending the UserInfo Request.
                If `None` is specified, no userinfo request will be sent.
            client_registration_info: Client metadata to register your app
                dynamically with the provider. Either this or `registered_client_metadata` must be specified.
            client_metadata: Client metadata if your app is statically
                registered with the provider. Either this or `client_registration_info` must be specified.
            auth_request_params: Extra parameters that should be included in the authentication request.
            session_refresh_interval_seconds: Length of interval (in seconds) between attempted user data
                refreshes.
            requests_session: custom requests object to allow for example retry handling, etc.
        """

        if not issuer and not provider_metadata:
            raise ValueError("Specify either 'issuer' or 'provider_metadata'.")

        if not client_registration_info and not client_metadata:
            raise ValueError("Specify either 'client_registration_info' or 'client_metadata'.")

        self._issuer = issuer
        self._provider_metadata = provider_metadata

        self._client_registration_info = client_registration_info
        self._client_metadata = client_metadata

        self.userinfo_endpoint_method = userinfo_http_method
        self.auth_request_params = auth_request_params or {}
        self.session_refresh_interval_seconds = session_refresh_interval_seconds
        # For session persistence
        self.client_settings = ClientSettings(
            timeout=self.DEFAULT_REQUEST_TIMEOUT, requests_session=requests_session or requests.Session()
        )

    def ensure_provider_metadata(self, client: Client):
        if not self._provider_metadata:
            discovery_response = client.provider_config(self._issuer)
            logger.debug("Received discovery response: %s" % discovery_response.to_dict())

            self._provider_metadata = ProviderMetadata(**discovery_response)

        return self._provider_metadata

    @property
    def registered_client_metadata(self):
        return self._client_metadata

    def register_client(self, client: Client):

        if not self._client_metadata:
            if not self._provider_metadata["registration_endpoint"]:
                raise ValueError(
                    "Can't use dynamic client registration, provider metadata is missing " "'registration_endpoint'."
                )

            # Send request to register the client dynamically.
            registration_response = client.register(
                url=self._provider_metadata["registration_endpoint"], **self._client_registration_info
            )
            logger.info("Received registration response.")
            self._client_metadata = ClientMetadata(**registration_response)

        return self._client_metadata
