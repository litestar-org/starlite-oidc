import contextvars
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import ParseResultBytes, parse_qsl, urlparse

from oic import rndstr
from oic.extension.message import TokenIntrospectionResponse
from oic.oic import AuthorizationRequest
from starlette.responses import RedirectResponse
from starlette.status import (
    HTTP_301_MOVED_PERMANENTLY,
    HTTP_303_SEE_OTHER,
    HTTP_307_TEMPORARY_REDIRECT,
)
from starlette.types import Scope
from starlite import HttpMethod, Redirect, Request, Starlite, route
from starlite.enums import MediaType
from starlite.exceptions import (
    HTTPException,
    NotAuthorizedException,
    PermissionDeniedException,
)

from .auth_response_handler import (
    AuthResponseErrorResponseError,
    AuthResponseHandler,
    AuthResponseProcessError,
)
from .provider_configuration import ProviderConfiguration
from .pyoidc_facade import PyoidcFacade
from .user_session import UninitialisedSession, UserSession

logger = logging.getLogger(__name__)


class OIDCAuthentication:
    __slots__ = (
        "_provider_configurations",
        "clients",
        "_redirect_uri",
        "_error_view",
        "_post_logout_redirect_paths",
        "_scopes",
    )

    def __init__(self, provider_configurations: Dict[str, ProviderConfiguration]):

        self._provider_configurations = provider_configurations

        self.clients: Optional[Dict[str, PyoidcFacade]] = None
        self._redirect_uri: Optional[ParseResultBytes] = None
        self._post_logout_redirect_paths: List[str] = []

        # Context variable for OIDC scopes.
        self._scopes: contextvars.ContextVar[None] = contextvars.ContextVar("scopes", default=None)

    def init_app(
        self, app: Starlite, redirect_uri: str, logout_views: Optional[Union[List[str], Tuple[str, ...], str]] = None
    ) -> None:
        """Initializes required OIDC parameters and callback.

        Args:
            app: Starlite
            redirect_uri: Registered redirect URI for OIDC callback.
            logout_views: User defined route handler names to resolve post logout redirect URIs.
        """
        self._redirect_uri = urlparse(redirect_uri)
        # Register the callback route handler dynamically.
        app.register(
            value=route(path=self._redirect_uri.path, http_method=[HttpMethod.GET, HttpMethod.POST])(
                self._handle_authentication_response
            )
        )

        # Dynamically add redirect URI to the client.
        self.clients = {
            name: PyoidcFacade(configuration, redirect_uri)
            for (name, configuration) in self._provider_configurations.items()
        }

        # If the user has provided route handler names, use them to resolve paths.
        if logout_views:
            if isinstance(logout_views, str):
                logout_views = [logout_views]
            for view in logout_views:
                paths = app.get_handler_index_by_name(view)["paths"]
                for path in paths:
                    self._post_logout_redirect_paths.append(path)

    def _get_urls_for_logout_views(self):
        """Resolves post logout redirect URIs from the user defined logout
        paths."""
        root_url = f"{self._redirect_uri.scheme}://{self._redirect_uri.netloc}"
        return [f"{root_url}{post_logout}" for post_logout in self._post_logout_redirect_paths]

    def _register_client(self, client: PyoidcFacade):
        """Registers the client by using OIDC Dynamic Client Registration.

        Args:
            client: PyoidcFacade instance contains metadata of the provider and client.
        """
        # Check if the redirect URI is provided. If not, obtain it from the instance. There can be multiple
        # redirect URIs but if they are not provided, the one which is obtained from the instance is enough for OIDC.
        if not client._provider_configuration._client_registration_info.get("redirect_uris"):
            client._provider_configuration._client_registration_info["redirect_uris"] = [self._redirect_uri.geturl()]
        post_logout_redirect_uris = client._provider_configuration._client_registration_info.get(
            "post_logout_redirect_uris"
        )
        # Check if post_logout_redirect_uris is provided. If not, resolve it using self._post_logout_redirect_paths.
        if not post_logout_redirect_uris:
            client._provider_configuration._client_registration_info[
                "post_logout_redirect_uris"
            ] = self._get_urls_for_logout_views()

        logger.debug(
            "registering with post_logout_redirect_uris: %s"
            % client._provider_configuration._client_registration_info["post_logout_redirect_uris"]
        )

        # Start Dynamic Client Registration.
        client.register()

    def _authenticate(self, client: PyoidcFacade, scope: Scope, interactive: bool = True) -> RedirectResponse:
        """Initiates OIDC authentication.

        Args:
            client : PyoidcFacade
                PyoidcFacade instance contains metadata of the provider and client.
            scope: Scope
                The ASGI connection scope.
            interactive: bool
                If it's false, access token is refreshed without user iteration. It requires a refresh token to silently
                refresh the access token.

        Returns:
            RedirectResponse: Redirects to the IdP authentication URL.
        """
        # If the client is not registered with the IdP, then perform OIDC Dynamic Client Registration.
        if not client.is_registered():
            self._register_client(client)

        session = scope["session"]
        session["destination"] = scope["path"]

        # Use silent authentication for session refresh. This will not show login prompt to the user.
        extra_auth_params = {}
        if not interactive:
            extra_auth_params["prompt"] = "none"

        auth_req = client.authentication_request(state=rndstr(), nonce=rndstr(), extra_auth_params=extra_auth_params)
        session["auth_request"] = auth_req.to_json()
        login_url = client.login_url(auth_req)

        login_url_parse = urlparse(login_url)
        auth_params = dict(parse_qsl(login_url_parse.query))
        session["fragment_encoded_response"] = AuthResponseHandler.expect_fragment_encoded_response(auth_params)
        return RedirectResponse(url=login_url, status_code=HTTP_303_SEE_OTHER)

    async def _handle_authentication_response(self, request: Request) -> RedirectResponse:
        """This is a callback route handler registered at Starlite instance.
        See `self.init_app` for its registration parameters. This route handler
        exchanges OIDC tokens sent by the IdP. Then it sets them up in the
        session.

        Args:
            request

        Returns:
            RedirectResponse

        Raises:
            HTTPException: If the IdP sends error response.
        """
        if "error" in request.session:
            raise HTTPException(extra=request.session["error"])

        try:
            session = UserSession(request.session)
        except UninitialisedSession as e:
            self._handle_error_response(
                session=request.session, error_response={"error": "Uninitialised Session", "error_description": str(e)}
            )

        if "auth_request" not in request.session:
            self._handle_error_response(
                session=request.session,
                error_response={
                    "error": "unsolicited_response",
                    "error_description": "No authentication request stored.",
                },
            )

        auth_request = AuthorizationRequest().from_json(request.session.pop("auth_request"))

        is_processing_fragment_encoded_response = request.method == "POST"
        if is_processing_fragment_encoded_response:
            auth_resp = await request.form()
            auth_resp = dict(auth_resp)
        elif request.session.pop("fragment_encoded_response", False):
            auth_resp = dict(parse_qsl(urlparse(str(request.url)).query))
        else:
            auth_resp = request.query_params

        client = self.clients[session.current_provider]

        authn_resp = client.parse_authentication_response(auth_resp)
        logger.debug("received authentication response: %s", authn_resp.to_json())

        try:
            result = AuthResponseHandler(client).process_auth_response(authn_resp, auth_request)
        except AuthResponseErrorResponseError as e:
            self._handle_error_response(session=request.session, error_response=e.error_response)
        except AuthResponseProcessError as e:
            self._handle_error_response(
                session=request.session, error_response={"error": "unexpected_error", "error_description": str(e)}
            )

        # Sets OIDC tokens in the session.
        UserSession(request.session).update(
            access_token=result.access_token,
            expires_in=result.expires_in,
            id_token=result.id_token_claims,
            id_token_jwt=result.id_token_jwt,
            userinfo=result.userinfo_claims,
            refresh_token=result.refresh_token,
        )

        destination = request.session.pop("destination")
        return RedirectResponse(url=destination, status_code=HTTP_301_MOVED_PERMANENTLY)

    @staticmethod
    def _handle_error_response(session: Dict[str, Any], error_response: Union[Dict[str, Any], List, None]):
        """Handles error response from the IdP.

        Args:
            session
            error_response

        Raises:
            HTTPException
        """
        # error_response = json.dumps(error_response)
        logger.error(error_response)
        session["error"] = error_response
        raise HTTPException(extra=error_response)

    def oidc_auth(self, scope: Scope, provider_name: str) -> Optional[RedirectResponse]:
        """OIDC based authentication. This method manages user authentication
        by verifying if OIDC metadata exists in session and if it exists,
        whether the access token needs a refresh or else initiates
        authentication with the IdP.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Examples:
            ```python
            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='oidc',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
            ```
        """
        if provider_name not in self._provider_configurations:
            raise ValueError(
                f"Provider name '{provider_name}' not in configured providers: {self._provider_configurations.keys()}."
            )

        session = UserSession(scope["session"], provider_name)
        client = self.clients[session.current_provider]
        session._session_refresh_interval_seconds = client.session_refresh_interval_seconds

        if session.should_refresh():
            logger.debug("user auth will be refreshed 'silently'")
            return self._authenticate(client, scope, interactive=False)
        elif session.is_authenticated():
            logger.debug("user is already authenticated")
            # Store the information about the user in scope.
            scope["user"] = session.userinfo
            return
        else:
            logger.debug("user not authenticated, start flow")
            return self._authenticate(client, scope)

    def _logout(self, request: Request) -> Optional[Redirect]:
        """Initializes RP-Initiated Logout and clears the session.

        Args:
            request: Request
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            logger.info("user was already logged out, doing nothing")
            return None

        state = rndstr()
        post_logout_redirect_uri = str(request.url)
        request.session["end_session_state"] = state

        for provider in self.clients:
            client = self.clients[provider]
            if provider != session.current_provider and client.provider_end_session_endpoint:
                provider_data = request.session.get(provider)
                if provider_data:
                    id_token_jwt = provider_data.get("id_token_jwt")
                    access_token = provider_data.get("access_token")
                    client.end_session_request(
                        id_token_jwt=id_token_jwt,
                        post_logout_redirect_uri=post_logout_redirect_uri,
                        state=state,
                        access_token=access_token,
                        interactive=False,
                    )

        current_client = self.clients[session.current_provider]
        request_args = {
            "id_token_jwt": session.id_token_jwt,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
            "access_token": session.access_token,
        }
        session.clear(self._provider_configurations.keys())
        if current_client.provider_end_session_endpoint:
            end_session_request_url = current_client.end_session_request(**request_args)
            logger.debug("sending end session request to '%s'", end_session_request_url)
            return Redirect(path=end_session_request_url)

    def oidc_logout(self, request: Request) -> Optional[RedirectResponse]:
        """Before request hook for RP-Initiated Logout.

        Args:
            request: Request

        Returns:
            RedirectResponse: optional

        Examples:
            ```python
            @get(path='/', name='post_logout', before_request=[oidc_logout])
            def logout() -> ...:
                ...

            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='oidc',
                                       scopes=['read', 'write']).middleware],
                ...

            auth.init_app(redirect_uri='https://client.example.com',
                          logout_views=('post_logout', 'deactivate', 'exit'))
            )
            ```

        Note:
            This should be only used for route handlers that logs out the user.
        """
        logger.debug("Initializing RP-Initiated Logout")
        if "state" in request.query_params:
            if request.query_params["state"] != [request.session.pop("end_session_state", None)]:
                logger.error("Got unexpected state '%s' after logout redirect.", request.query_params["state"])
                request.clear_session()
            pass
        else:
            redirect_to_provider = self._logout(request)
            if redirect_to_provider:
                return redirect_to_provider.to_response(
                    headers={}, media_type=MediaType.HTML, status_code=HTTP_307_TEMPORARY_REDIRECT, app=request.app
                )

    def valid_access_token(self, request: Request, force_refresh: bool = False) -> Optional[str]:
        """Returns a valid access token.

        1. If the current access token in the user session is valid, return that.
        2. If the current access token has expired and there is a refresh token in the user session,
           make a refresh token request and return the new access token.
        3. If the token refresh fails, either due to missing refresh token or token error response, return None.

        Args:
            request
            force_refresh: whether to perform the refresh token request even if the current access token is valid
        Returns:
            valid access token

        Examples:
            ```python
            @get(path='/')
            def index(request: Request) -> ...:
                ...
                access_token = auth.valid_access_token(request)
                ...
            ```
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            logger.debug("user does not have an active session")
            return None

        if session.refresh_token is None:
            logger.info("no refresh token exists in the session")
            return None

        has_expired = session.access_token_expires_at <= time.time() if session.access_token_expires_at else False
        if has_expired is False and force_refresh is False:
            logger.debug("access token doesn't need to be refreshed")
            return session.access_token

        client = self.clients[session.current_provider]
        response = client.refresh_token(session.refresh_token)
        if "error" in response:
            logger.info("failed to refresh access token: %s" % json.dumps(response.to_dict()))
            return None

        access_token = response.get("access_token")
        session.update(
            access_token=access_token,
            expires_in=response.get("expires_in"),
            id_token=response["id_token"].to_dict() if "id_token" in response else None,
            id_token_jwt=response.get("id_token_jwt"),
            refresh_token=response.get("refresh_token"),
        )
        return access_token

    @staticmethod
    def _check_authorization_header(headers: Dict[str, str]) -> bool:
        """Look for authorization in request header.

        Args:
            headers: Request headers.

        Returns:
            bool: True if the request header contains authorization else False.
        """
        if "authorization" in headers and headers["authorization"].startswith("Bearer "):
            return True
        return False

    @staticmethod
    def _parse_access_token(headers: Dict[str, str]) -> str:
        """Parse access token from the authorization request header.

        Args:
            headers: Request header.

        Returns:
            accept_token: access token from the request header.
        """
        _, access_token = headers["authorization"].split(maxsplit=1)
        return access_token

    def introspect_token(self, headers: Dict[str, str], client: PyoidcFacade) -> Optional[TokenIntrospectionResponse]:
        """RFC 7662: Token Introspection The Token Introspection extension
        defines a mechanism for resource servers to obtain information about
        access tokens. With this spec, resource servers can check the validity
        of access tokens, and find out other information such as which user and
        which scopes are associated with the token.

        Args:
            headers: Request headers.
            client: PyoidcFacade instance contains metadata of the provider and client.

        Returns:
            result: TokenIntrospectionResponse or None
                If the access token is valid or None if invalid.
        """
        received_access_token = self._parse_access_token(headers)
        # Send token introspection request.
        result = client._token_introspection_request(access_token=received_access_token)
        logger.debug(result)
        # Check if the access token is valid, active can be True or False.
        if result.get("active") is False:
            return None
        # Check if client_id is in audience claim
        if client._client.client_id not in result["aud"]:
            # Log the exception if client_id is not in audience and returns False, you can configure audience with the
            # IdP
            logger.info("Token is valid but required audience is missing.")
            return None
        # Check if the scopes associated with the access token are the ones required by the endpoint and not something
        # else which is not permitted.
        scopes = self._scopes.get("scopes")
        if scopes and not set(scopes).issubset(set(result["scope"])):
            logger.info("Token is valid but does not have required scopes.")
            return None
        return result

    def token_auth(self, scope: Scope, provider_name: str) -> None:
        """Token based authorization.

        Args:
        scope: Scope
            The ASGI connection scope.
        provider_name : str
            Name of the provider registered with OIDCAuthorization.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Examples:
            ```python
            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='token',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
            ```
        """
        client = self.clients[provider_name]
        scopes = self._scopes.get()
        # Check for authorization field in the request header.
        headers = Request(scope).headers
        if not self._check_authorization_header(headers=headers):
            logger.info("Request header has no authorization field.")
            # Abort the request if authorization field is missing.
            raise NotAuthorizedException()
        token_introspection_result = self.introspect_token(headers=headers, client=client)
        if token_introspection_result is not None:
            logger.info("Request has valid access token.")
            # Store token introspection info in auth for the user to retrieve more information about the token.
            scope["auth"] = token_introspection_result.to_dict()
            return None
        # Forbid access if the access token is invalid.
        raise PermissionDeniedException()

    def access_control_auth(self, scope: Scope, provider_name: str) -> None:
        """This method serves dual purpose that is it can do both token based
        authorization and oidc based authentication. If your API needs to be
        accessible by either modes, use this decorator otherwise use either
        oidc_auth or token_auth.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Examples:
            ```python
            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='access_control',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
            ```
        """
        try:
            # If the request header contains authorization, token_auth verifies the access token otherwise an exception
            # occurs and the request falls back to oidc_auth.
            return self.token_auth(scope, provider_name)
        # Token_auth will raise the HTTPException if either authorization field is missing from the request header or
        # if the access token is invalid. If the authorization field is missing, fallback to oidc.
        except NotAuthorizedException:
            return self.oidc_auth(scope, provider_name)
        # If the access token is present, but it's invalid, do not fall back to oidc_auth. Instead, abort the request.
        except PermissionDeniedException:
            raise
