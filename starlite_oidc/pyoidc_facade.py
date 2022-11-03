import http
import logging
import time
from typing import Any, List, Mapping, Optional, Union

from oic.extension.client import Client as ClientExtension
from oic.extension.message import TokenIntrospectionResponse
from oic.oauth2 import Client as Oauth2Client
from oic.oauth2.message import AccessTokenResponse
from oic.oic import Client, Token
from oic.oic.message import (
    AuthorizationErrorResponse,
    AuthorizationRequest,
    AuthorizationResponse,
    FrontChannelLogoutRequest,
    ProviderConfigurationResponse,
    RegistrationResponse,
    TokenErrorResponse,
)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from .message_factory import CCMessageFactory
from .provider_configuration import ProviderConfiguration

logger = logging.getLogger(__name__)


class PyoidcFacade:
    """Wrapper around pyoidc library, coupled with config for a simplified API
    for starlite-pyoidc."""

    def __init__(self, provider_configuration: ProviderConfiguration, redirect_uri: str) -> None:
        """
        Args:
            provider_configuration
        """
        self._provider_configuration = provider_configuration
        self._client = Client(client_authn_method=CLIENT_AUTHN_METHOD, settings=provider_configuration.client_settings)
        # Token Introspection is implemented under extension sub-package of the client in pyoidc.
        self._client_extension = ClientExtension(
            client_authn_method=CLIENT_AUTHN_METHOD, settings=provider_configuration.client_settings
        )
        # Client Credentials Flow is implemented under oauth2 sub-package of the client in pyoidc.
        self._oauth2_client = Oauth2Client(
            client_authn_method=CLIENT_AUTHN_METHOD,
            message_factory=CCMessageFactory,
            settings=self._provider_configuration.client_settings,
        )

        provider_metadata = provider_configuration.ensure_provider_metadata(self._client)
        self._client.handle_provider_config(
            ProviderConfigurationResponse(**provider_metadata), provider_metadata["issuer"]
        )

        if self._provider_configuration.registered_client_metadata:
            client_metadata = self._provider_configuration.registered_client_metadata.to_dict()
            client_metadata.update(redirect_uris=[redirect_uri])
            self._store_registration_info(client_metadata)

        self._redirect_uri = redirect_uri

    def _store_registration_info(self, client_metadata):
        registration_response = RegistrationResponse(**client_metadata)
        self._client.store_registration_info(registration_response)
        self._client_extension.store_registration_info(registration_response)
        # Set client_id and client_secret for _oauth2_client. This is used
        # by Client Credentials Flow.
        self._oauth2_client.client_id = registration_response["client_id"]
        self._oauth2_client.client_secret = registration_response["client_secret"]

    def is_registered(self):
        return bool(self._provider_configuration.registered_client_metadata)

    def register(self):
        client_metadata = self._provider_configuration.register_client(self._client)
        logger.debug("client registration response: %s" % client_metadata)
        self._store_registration_info(client_metadata)

    def authentication_request(
        self, state: str, nonce: str, extra_auth_params: Mapping[str, str]
    ) -> AuthorizationRequest:
        """
        Args:
            state: authentication request parameter 'state'
            nonce: authentication request parameter 'nonce'
            extra_auth_params: extra authentication request parameters

        Returns:
            AuthorizationRequest: the authentication request
        """
        args = {
            "client_id": self._client.client_id,
            "response_type": "code",
            "scope": ["openid"],
            "redirect_uri": self._redirect_uri,
            "state": state,
            "nonce": nonce,
        }

        args.update(self._provider_configuration.auth_request_params)
        args.update(extra_auth_params)
        auth_request = self._client.construct_AuthorizationRequest(request_args=args)
        logger.debug("sending authentication request: %s", auth_request.to_json())
        return auth_request

    def login_url(self, auth_request: AuthorizationRequest) -> str:
        """
        Args:
            auth_request: authentication request
        Returns:
            Authentication request as a URL to redirect the user to the provider.
        """
        return auth_request.request(self._client.authorization_endpoint)

    def parse_authentication_response(
        self, response_params: Mapping[str, str]
    ) -> Union[AuthorizationResponse, AuthorizationErrorResponse]:
        """
        Args:
            response_params: authentication response parameters.

        Returns:
            The parsed authorization response.
        """
        auth_resp = self._client.parse_response(AuthorizationResponse, info=response_params, sformat="dict")
        if "id_token" in response_params:
            auth_resp["id_token_jwt"] = response_params["id_token"]
        return auth_resp

    def exchange_authorization_code(self, authorization_code: str, state: str):
        """Requests tokens from an authorization code.

        Args:
            authorization_code: authorization code issued to client after user authorization
            state: state is used to keep track of responses to outstanding requests.

        Returns:
            The parsed token response, or None if no token request was performed.
        """
        if not self._client.token_endpoint:
            return None

        request_args = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self._redirect_uri,
        }
        logger.debug("making token request: %s", request_args)
        client_auth_method = self._client.registration_response.get("token_endpoint_auth_method", "client_secret_basic")
        token_response = self._client.do_access_token_request(
            state=state,
            request_args=request_args,
            authn_method=client_auth_method,
            endpoint=self._client.token_endpoint,
        )
        logger.info("Received token response.")
        return token_response

    def verify_id_token(self, id_token: Mapping[str, str], auth_request: Mapping[str, str]):
        """Verifies the ID Token.

        Args:
            id_token: ID token claims
            auth_request: original authentication request parameters to validate against
                (nonce, acr_values, max_age, etc.)

        Raises:
            PyoidcError: If the ID token is invalid.
        """
        self._client.verify_id_token(id_token, auth_request)

    def refresh_token(self, refresh_token: str) -> Union[AccessTokenResponse, TokenErrorResponse, None]:
        """Requests new tokens using a refresh token.

        Args:
            refresh_token: refresh token issued to client after user authorization.

        Returns:
            The parsed token response, or None if no token request was performed.
        """
        request_args = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": self._redirect_uri,
        }
        client_auth_method = self._client.registration_response.get("token_endpoint_auth_method", "client_secret_basic")
        return self._client.do_access_token_refresh(
            request_args=request_args,
            authn_method=client_auth_method,
            token=Token(resp={"refresh_token": refresh_token}),
            endpoint=self._client.token_endpoint,
        )

    def userinfo_request(self, access_token: str):
        """Retrieves ID token.

        Args:
            access_token: Bearer access token to use when fetching userinfo.

        Returns:
            Union[OpenIDSchema, UserInfoErrorResponse, ErrorResponse, None]
        """
        http_method = self._provider_configuration.userinfo_endpoint_method
        if not access_token or http_method is None or not self._client.userinfo_endpoint:
            return None

        logger.debug("making userinfo request")
        userinfo_response = self._client.do_user_info_request(method=http_method, token=access_token)
        logger.debug("received userinfo response: %s", userinfo_response)
        return userinfo_response

    def introspect_token(self, access_token: str) -> TokenIntrospectionResponse:
        """RFC 7662: Token Introspection The Token Introspection extension
        defines a mechanism for resource servers to obtain information about
        access tokens. With this spec, resource servers can check the validity
        of access tokens, and find out other information such as which user and
        which scopes are associated with the token.

        Args:
            access_token: Access token to be validated.

        Returns:
            Response object contains result of the token introspection.
        """
        request_args = {"token": access_token, "token_type_hint": "access_token"}
        client_auth_method = self._client.registration_response.get(
            "introspection_endpoint_auth_method", "client_secret_basic"
        )
        logger.info("making token introspection request")
        token_introspection_response = self._client_extension.do_token_introspection(
            request_args=request_args, authn_method=client_auth_method, endpoint=self._client.introspection_endpoint
        )
        return token_introspection_response

    def _validate_token_info(
        self, token: Union[AccessTokenResponse, TokenIntrospectionResponse], scopes: List[str]
    ) -> bool:
        """Validates expiry, audience and scopes.

        Parameters
        ----------
        token : Union[AccessTokenResponse, TokenIntrospectionResponse]
        scopes : List[str]
            OIDC scopes required by the endpoint.

        Returns
        -------
        bool
            True if the access token is valid or False if invalid.
        """
        logger.debug(token.to_dict())
        # Check if the access token is valid, active can be True or False.
        if isinstance(token, AccessTokenResponse):
            if token["exp"] < time.time():
                return False
        else:
            if not token.get("active"):
                return False
        # Check if client_id is in audience claim
        if self._client.client_id not in token["aud"]:
            # Log the exception if client_id is not in audience and returns False, you can configure audience with the
            # IdP
            logger.info("Token is valid but required audience is missing.")
            return False
        # Check if the scopes associated with the access token are permitted.
        if scopes and set(scopes).issubset(token["scope"]) is False:
            logger.info("Token is valid but does not have required scopes.")
            return False
        return True

    def _end_session_request(
        self,
        id_token_jwt: str,
        post_logout_redirect_uri: str,
        state: str,
        interactive: Optional[bool] = True,
    ) -> Optional[str]:
        """Performs RP-Initiated Logout action by sending the logout event to
        the Identity Provider. If there are any tokens bound to the user, they
        will be revoked.

        Args:
            id_token_jwt: Raw ID token.
            post_logout_redirect_uri:  URI of the logout endpoint.
            state: Value used to maintain state between the logout request and the callback.
            interactive: If False, logout event will be sent silently else the user will be redirected to the logout page of the
            IdP.

        Returns:
            URI: RP-Initiated Logout URI.
        """
        request_args = {
            "id_token_hint": id_token_jwt,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
        }
        if interactive is True:
            end_session_request = FrontChannelLogoutRequest(**request_args)
            logger.debug("send end session request: %s", end_session_request.to_dict())
            end_session_request = end_session_request.request(self.provider_end_session_endpoint)
            return end_session_request

        self._client.do_end_session_request(method="POST", request_args=request_args)

    def client_credentials_grant(self, scopes: Optional[List[str]] = None, **kwargs: Any) -> AccessTokenResponse:
        """Requests access token using client_credentials flow. This is useful
        for service to service communication where user-agent is not available.
        Your service can request an access token in order to access APIs of
        other services.

        On API call, token introspection will ensure that only valid token can
        be used to access your APIs.

        Args:
            scopes: List of scopes to be requested.
            **kwargs: Extra arguments to client credentials flow.

        Returns:
            AccessTokenResponse

        Examples:
        ```python
        auth = OIDCAuthentication({'default': provider_config},
                                    access_token_required=True)
        auth.init_app(app)
        auth.clients['default'].client_credentials_grant()
        ```

        Optionally, you can specify scopes for the access token.

        ```python
        auth.clients['default'].client_credentials_grant(
            scopes=['read', 'write'])
        ```

        You can also specify extra keyword arguments to client credentials flow.

        ```python
        auth.clients['default'].client_credentials_grant(
            scopes=['read', 'write'], audience=['client_id1', 'client_id2'])
        ```
        """
        request_args = {"grant_type": "client_credentials", **kwargs}
        if scopes:
            request_args["scope"] = " ".join(scopes)

        client_auth_method = self._client.registration_response.get("token_endpoint_auth_method", "client_secret_basic")
        access_token = self._oauth2_client.do_access_token_request(
            request_args=request_args, authn_method=client_auth_method, endpoint=self._client.token_endpoint
        )
        return access_token

    def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> http.HTTPStatus:
        """Revokes access token & refresh token.

        Args:
            token: Token to be revoked.
            token_type_hint: A hint of the type of token. Valid values: access_token & refresh_token.

        Returns:
            http.HTTPStatus

        Examples:
        ```python
        auth = OIDCAuthentication({'default': provider_config})
        auth.init_app(app)
        auth.clients['default'].revoke_token(token='access_token',
                                                token_type_hint='access_token')
        ```
        """
        request_args = {"token": token, "token_type_hint": token_type_hint}
        client_auth_method = self._client.registration_response.get(
            "revocation_endpoint_auth_method", "client_secret_basic"
        )
        token_revocation_response = self._client_extension.do_token_revocation(
            request_args=request_args, authn_method=client_auth_method, endpoint=self._client.revocation_endpoint
        )
        logger.debug("%s revoked" % token_type_hint)
        return token_revocation_response

    @property
    def session_refresh_interval_seconds(self):
        return self._provider_configuration.session_refresh_interval_seconds

    @property
    def provider_end_session_endpoint(self):
        provider_metadata = self._provider_configuration.ensure_provider_metadata(self._client)
        return provider_metadata.get("end_session_endpoint")

    @property
    def post_logout_redirect_uris(self):
        return self._client.registration_response.get("post_logout_redirect_uris")
