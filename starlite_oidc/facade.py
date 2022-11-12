from functools import partial
from http import HTTPStatus
from time import time
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Union, cast

from anyio.to_thread import run_sync
from oic.exception import PyoidcError
from oic.extension.client import Client as ClientExtension
from oic.extension.message import TokenIntrospectionResponse
from oic.oauth2 import Client as Oauth2Client
from oic.oauth2.message import (
    AccessTokenResponse,
    ASConfigurationResponse,
    CCAccessTokenRequest,
    Message,
    MessageTuple,
    OauthMessageFactory,
)
from oic.oic import Client, Token
from oic.oic.message import (
    AuthorizationRequest,
    AuthorizationResponse,
    FrontChannelLogoutRequest,
    OpenIDSchema,
    RegistrationResponse,
    TokenErrorResponse,
    UserInfoErrorResponse,
)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from starlite import NotAuthorizedException

if TYPE_CHECKING:

    from .config import ProviderConfig


class CCMessageFactory(OauthMessageFactory):
    """Client Credential Request Factory."""

    token_endpoint = MessageTuple(CCAccessTokenRequest, AccessTokenResponse)


class OIDCFacade:
    """A wrapper around the pyoidc library that offers a simplified API to
    interact with it."""

    __slots__ = (
        "config",
        "oidc_client",
        "oidc_client_extension",
        "oauth2_client",
        "redirect_uri",
        "is_client_registered",
    )

    def __init__(self, config: "ProviderConfig", redirect_uri: str) -> None:
        """

        Args:
            config: An instance of ProviderConfig
            redirect_uri: A redirection url.
        """
        self.config = config
        self.oidc_client = Client(client_authn_method=CLIENT_AUTHN_METHOD, settings=config.client_settings)
        self.oidc_client_extension = ClientExtension(
            client_authn_method=CLIENT_AUTHN_METHOD, settings=config.client_settings
        )
        self.oauth2_client = Oauth2Client(
            client_authn_method=CLIENT_AUTHN_METHOD,
            message_factory=CCMessageFactory,
            settings=self.config.client_settings,
        )
        self.redirect_uri = redirect_uri
        self.register_client_metadata()

    def register_client_metadata(self, **kwargs: Any) -> None:
        """
        Register the client metadata on the facades - if its defined.

        Args:
            **kwargs: additional kwargs to pass to the 'oidc.RegistrationResponse' that is created.

        Returns:
            None
        """
        if self.config.client_metadata:
            registration_response = RegistrationResponse(**self.config.client_metadata.dict(), **kwargs)
            self.oidc_client.store_registration_info(registration_response)
            self.oidc_client_extension.store_registration_info(registration_response)
            self.oauth2_client.client_id = registration_response["client_id"]
            self.oauth2_client.client_secret = registration_response["client_secret"]

    def validate_token(
        self, token: Union[AccessTokenResponse, TokenIntrospectionResponse], scopes: Optional[List[str]]
    ) -> bool:
        """Validate the token expiry, audience and scopes.

        Args:
            token : Union[AccessTokenResponse, TokenIntrospectionResponse]
            scopes : List[str]
                OIDC scopes required by the endpoint.

        Returns:
            A boolean dictating whether the token is valid or not.
        """

        if isinstance(token, AccessTokenResponse) and token["exp"] < time():
            return False

        if isinstance(token, TokenIntrospectionResponse) and not token.get("active"):
            return False

        if self.oidc_client.client_id not in token.get("aud"):
            return False

        if scopes and not set(scopes).issubset(token["scope"]):
            return False

        return True

    def create_authorization_request(
        self, state: str, nonce: str, extra_auth_params: Dict[str, str]
    ) -> AuthorizationRequest:
        """Creates an instance of.

        [AuthorizationRequest][oic.oic.message.AuthorizationRequest].

        Args:
            state: the request 'state'.
            nonce: the request 'nonce'.
            extra_auth_params: a dictionary of extra parameters.

        Returns:
            AuthorizationRequest: the authentication request
        """
        return self.oidc_client.construct_AuthorizationRequest(
            request_args={
                "client_id": self.oidc_client.client_id,
                "response_type": "code",
                "scope": ["openid"],
                "redirect_uri": self.redirect_uri,
                "state": state,
                "nonce": nonce,
                **self.config.auth_request_params,
                **extra_auth_params,
            }
        )

    def get_login_url_from_auth_request(self, auth_request: AuthorizationRequest) -> str:
        """Get a URL to the OIDC client authorization endpoint from an instance
        of AuthorizationRequest.

        Args:
            auth_request: authentication request

        Returns:
            A URL string.
        """
        return auth_request.request(self.oidc_client.authorization_endpoint)

    def parse_authorization_response(self, response_params: Dict[str, str]) -> "Message":
        """
        Args:
            response_params: authentication response parameters.

        Returns:
            The parsed authorization response.
        """
        auth_resp = self.oidc_client.parse_response(AuthorizationResponse, info=response_params, sformat="dict")
        if "id_token" in response_params:
            auth_resp["id_token_jwt"] = response_params["id_token"]
        return auth_resp

    async def register_client(self) -> None:
        """Registers the client using the OIDC Dynamic Client Registration
        Protocol.

        Notes:
            - This method can make an HTTP call to dynamically register a client.
        """
        if not self.config.client_metadata:
            await self.config.register_client(self.oidc_client)

        self.register_client_metadata()

    async def set_provider(self) -> None:
        """Sets the OP.

        Notes:
            - if needed, this method will make an OIDC discovery request.
        """
        await self.config.set_provider_metadata(self.oidc_client)
        if self.config.provider_metadata:
            self.oidc_client.handle_provider_config(
                pcr=ASConfigurationResponse(**self.config.provider_metadata.dict()),
                issuer=self.config.provider_metadata.issuer,
            )
        self.register_client_metadata(redirect_uris=[self.redirect_uri])

    async def request_access_token(
        self, code: str, state: str, auth_request: Dict[str, Any]
    ) -> Optional[AccessTokenResponse]:
        """Request an ID token using an authorization code.

        Args:
            auth_request:
            code: authorization code issued to client after user authorization
            state: state is used to keep track of responses to outstanding requests.

        Returns:
            The parsed token response, or None if no token request was performed.
        """
        if not self.oidc_client.token_endpoint:
            return None

        request_args = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

        client_auth_method = self.oidc_client.registration_response.get(
            "token_endpoint_auth_method", "client_secret_basic"
        )
        response = await run_sync(
            partial(
                self.oidc_client.do_access_token_request,
                state=state,
                request_args=request_args,
                authn_method=client_auth_method,
                endpoint=self.oidc_client.token_endpoint,
            )
        )

        if response:
            if "error" in response:
                raise NotAuthorizedException("error retrieving access token", extra=response.to_dict())
            if "id_token" in response:
                try:
                    self.oidc_client.verify_id_token(response["id_toke"], auth_request)
                except PyoidcError as e:
                    raise NotAuthorizedException("invalid ID token") from e

        return response

    async def request_token_refresh(self, refresh_token: str) -> Union[AccessTokenResponse, TokenErrorResponse, None]:
        """Request a new ID token using a refresh token.

        Args:
            refresh_token: refresh token issued to client after user authorization.

        Returns:
            The parsed token response, or None if no token request was performed.
        """
        request_args = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": self.redirect_uri,
        }
        client_auth_method = self.oidc_client.registration_response.get(
            "token_endpoint_auth_method", "client_secret_basic"
        )
        return await run_sync(
            partial(
                self.oidc_client.do_access_token_refresh,
                request_args=request_args,
                authn_method=client_auth_method,
                token=Token(resp={"refresh_token": refresh_token}),
                endpoint=self.oidc_client.token_endpoint,
            )
        )

    async def request_user_info(self, access_token: str) -> Optional[Union[OpenIDSchema, UserInfoErrorResponse]]:
        """Request user information using a token.

        Args:
            access_token: Bearer access token to use when fetching user_info.

        Returns:
            Optional[OpenIDSchema, UserInfoErrorResponse]
        """
        if (
            not access_token
            or not self.config.user_info_http_method
            or not getattr(self.oidc_client, "userinfo_endpoint", None)
        ):
            return None

        return await run_sync(
            partial(self.oidc_client.do_user_info_request, method=self.config.user_info_http_method, token=access_token)
        )

    async def request_token_introspection(self, access_token: str) -> Optional[Message]:
        """

        Args:
            access_token: Access token to be validated.

        Returns:
            Response object contains result of the token introspection.
        """
        introspection_endpoint = cast("Optional[str]", getattr(self.oidc_client, "introspection_endpoint", None))
        if not introspection_endpoint:
            return None

        client_auth_method = self.oidc_client.registration_response.get(
            "introspection_endpoint_auth_method", "client_secret_basic"
        )

        return await run_sync(
            partial(
                self.oidc_client_extension.do_token_introspection,
                request_args={"token": access_token, "token_type_hint": "access_token"},
                authn_method=client_auth_method,
                endpoint=introspection_endpoint,
            )
        )

    async def request_session_end(
        self,
        id_token_jwt: str,
        post_logout_redirect_uri: str,
        state: str,
        interactive: bool,
    ) -> Optional[str]:
        """Request RP-Initiated Logout action by sending the logout event to
        the Identity Provider.

        Args:
            id_token_jwt: Raw ID token.
            post_logout_redirect_uri:  URI of the logout endpoint.
            state: Value used to maintain state between the logout request and the callback.
            interactive: If False, logout event will be sent silently else the user will be redirected to the logout
            endpoint of the IdP.

        Notes:
            - If there are any tokens bound to the user, they will be revoked.

        Returns:
            An logout uri.
        """
        request_args = {
            "id_token_hint": id_token_jwt,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
        }

        if not interactive:
            await run_sync(partial(self.oidc_client.do_end_session_request, method="POST", request_args=request_args))
            return None

        return FrontChannelLogoutRequest(**request_args).request(self.config.provider_metadata.end_session_endpoint)

    async def request_client_credentials_grant(
        self, scopes: Optional[List[str]] = None, **kwargs: Any
    ) -> AccessTokenResponse:
        """Request access token using the 'client_credentials flow'.

        Notes:
            - This is useful for service to service communication where user-agent is not available.
            The service can request an access token in to access APIs of other services.

        Args:
            scopes: List of scopes to be requested.
            **kwargs: Extra arguments to pass to the request.

        Returns:
            AccessTokenResponse
        """
        request_args = {"grant_type": "client_credentials", **kwargs}

        if scopes:
            request_args["scope"] = " ".join([scope.strip() for scope in scopes])

        client_auth_method = self.oidc_client.registration_response.get(
            "token_endpoint_auth_method", "client_secret_basic"
        )

        return await run_sync(
            partial(
                self.oauth2_client.do_access_token_request,
                request_args=request_args,
                authn_method=client_auth_method,
                endpoint=self.oidc_client.token_endpoint,
            )
        )

    async def request_token_revoke(
        self, token: str, token_type_hint: Optional[Literal["access_token", "refresh_token"]] = None
    ) -> Optional[Union["HTTPStatus", "Message"]]:
        """Request revocation of a token.

        Args:
            token: token to be revoked.
            token_type_hint: A hint for the type of token. Valid values: access_token & refresh_token.

        Returns:
            Either a message or an HTTPStatus.
        """
        revocation_endpoint = cast("Optional[str]", getattr(self.oidc_client, "revocation_endpoint", None))

        if not revocation_endpoint:
            return None

        client_auth_method = self.oidc_client.registration_response.get(
            "revocation_endpoint_auth_method", "client_secret_basic"
        )
        return await run_sync(
            partial(
                self.oidc_client_extension.do_token_revocation,
                request_args={"token": token, "token_type_hint": token_type_hint},
                authn_method=client_auth_method,
                endpoint=revocation_endpoint,
            )
        )
