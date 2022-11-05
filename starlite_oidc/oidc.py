import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import ParseResultBytes, parse_qsl, urlparse

from oic import rndstr
from oic.oic.message import AccessTokenResponse, AuthorizationRequest
from starlite import Starlite, route
from starlite.connection import ASGIConnection, Request
from starlite.datastructures import Headers, Redirect
from starlite.enums import HttpMethod, MediaType
from starlite.exceptions import (
    HTTPException,
    NotAuthorizedException,
    PermissionDeniedException,
)
from starlite.response import RedirectResponse
from starlite.status_codes import (
    HTTP_301_MOVED_PERMANENTLY,
    HTTP_303_SEE_OTHER,
    HTTP_307_TEMPORARY_REDIRECT,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
)
from starlite.types import Scope

from .auth_response_handler import AuthResponseErrorResponseError, AuthResponseHandler
from .provider_configuration import ProviderConfiguration
from .pyoidc_facade import PyoidcFacade
from .user_session import UninitialisedSession, UserSession

logger = logging.getLogger(__name__)


class OIDCAuthentication:
    __slots__ = ("_provider_configurations", "clients", "_redirect_uri", "_post_logout_redirect_paths")

    def __init__(self, provider_configurations: Dict[str, ProviderConfiguration]):

        self._provider_configurations = provider_configurations

        self.clients: Optional[Dict[str, PyoidcFacade]] = None
        self._redirect_uri: Optional[ParseResultBytes] = None
        self._post_logout_redirect_paths: List[str] = []

    def init_app(
        self,
        app: Starlite,
        redirect_uri: str,
        logout_views: Optional[Union[List[str], Tuple[str, ...], str]] = None,
        **kwargs: Any,
    ) -> None:
        """Initializes required OIDC parameters and callback.

        Args:
            app: Starlite
            redirect_uri: Registered redirect URI for OIDC callback.
            logout_views: User defined route handler names to resolve post logout redirect URIs.
            kwargs: HTTP Route Decorator parameters. See
                https://starlite-api.github.io/starlite/reference/handlers/0-http-handlers/
        """
        self._redirect_uri = urlparse(redirect_uri)
        # Register the callback route handler dynamically.
        app.register(
            value=route(path=self._redirect_uri.path, http_method=[HttpMethod.GET, HttpMethod.POST], **kwargs)(
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
            client: PyoidcFacade instance contains metadata of the provider and client.
            scope: The ASGI connection scope.
            interactive: If it's false, access token is refreshed without user iteration.
                It requires a refresh token to silently refresh the access token.

        Returns:
            RedirectResponse: Redirects to the IdP authentication URL.
        """
        # If the client is not registered with the IdP, then perform OIDC Dynamic Client Registration.
        if not client.is_registered():
            self._register_client(client)

        session = scope["session"]
        # Store the path so that the user can be redirected back to this path again after authentication.
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
        # Redirect to the IdP's login.
        return RedirectResponse(url=login_url, status_code=HTTP_303_SEE_OTHER)

    async def _handle_authentication_response(self, request: Request) -> RedirectResponse:
        """This is a callback route handler registered at Starlite instance.
        See `self.init_app` for its registration parameters. This route handler
        exchanges OIDC tokens sent by the IdP. Then it sets them up in the
        session.

        Args:
            request

        Returns:
            RedirectResponse: Redirects back to the path from where OIDC was triggered.

        Raises:
            HTTPException: If the IdP sends error response.
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession as e:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, extra={"error": "Uninitialised Session", "error_description": str(e)}
            )

        if "auth_request" not in request.session:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                extra={"error": "unsolicited_response", "error_description": "No authentication request stored."},
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
            raise HTTPException(extra=e.error_response)

        # Set OIDC tokens into the session.
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

    def oidc_auth(self, scope: Scope, provider_name: str) -> Optional[RedirectResponse]:
        """OIDC based authentication. This method manages user authentication
        by verifying if OIDC metadata exists in session and if it exists,
        whether the access token needs a refresh or else initiates
        authentication with the IdP.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Returns:
            Redirect to the IdP for authentication. If the user is already authenticated, it returns None. If the
            access token is needed to be refreshed, it is refreshed silently and None is returned.

        Raises:
            ValueError: If the given provider is not in the configured providers.

        Example:
            ::

                from starlite import Starlite
                from starlite.middleware import DefineMiddleware

                app = Starlite(
                    ...
                    middleware=[DefineMiddleware(OIDCMiddleware, auth=auth, provider_name='default', enforce='oidc_auth'
                        )],
                    ...
                )
                auth.init_app(app, redirect_uri='https://client.example.com')
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
            return None
        else:
            logger.debug("user not authenticated, start flow")
            return self._authenticate(client, scope)

    def _logout(self, request: Request) -> Optional[Redirect]:
        """Initializes RP-Initiated Logout and clears the session.

        Args:
            request: Request

        Returns:
            Redirect instance for front channel logout request to the IdP.
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            logger.info("user was already logged out, doing nothing")
            return None

        state = rndstr()
        post_logout_redirect_uri = str(request.url)
        request.session["end_session_state"] = state
        redirect_to_provider = None

        for provider in self.clients:
            client = self.clients[provider]
            if provider != session.current_provider:
                provider_data = request.session.get(provider)
                if provider_data:
                    if client.provider_end_session_endpoint:
                        client._end_session_request(
                            id_token_jwt=provider_data.get("id_token_jwt"),
                            post_logout_redirect_uri=post_logout_redirect_uri,
                            state=state,
                            interactive=False,
                        )
            else:
                if client.provider_end_session_endpoint:
                    end_session_request_url = client._end_session_request(
                        id_token_jwt=session.id_token_jwt,
                        post_logout_redirect_uri=post_logout_redirect_uri,
                        state=state,
                    )
                    logger.debug("sending end session request to '%s'", end_session_request_url)
                    redirect_to_provider = Redirect(path=end_session_request_url)

        session.clear(self._provider_configurations.keys())
        return redirect_to_provider

    def oidc_logout(self, request: Request) -> Optional[RedirectResponse]:
        """Before request hook for RP-Initiated Logout.

        Args:
            request: Request

        Returns:
            RedirectResponse: optional

        Examples:
            To register logout endpoints for RP-Initiated Logout, provide 'name' argument to the logout route handler.
            ::

                @get(path='/', name='post_logout', before_request=[oidc_logout])
                def logout() -> ...:
                    ...

            Pass the 'name' parameter to 'logout_views' argument.
            >>> auth.init_app(app, redirect_uri='https://client.example.com', logout_views='post_logout')

            You can register multiple route handlers that handles RP-Initiated Logout.
            ::

                auth.init_app(app, redirect_uri='https://client.example.com',
                              logout_views=('post_logout', 'delete', 'deactivate')

            Note:
                This should be only used for route handlers that logs out the user.
        """
        logger.debug("Initializing RP-Initiated Logout")
        if "state" in request.query_params:
            if request.query_params["state"] != [request.session.pop("end_session_state", None)]:
                logger.error("Got unexpected state '%s' after logout redirect.", request.query_params["state"])
                request.clear_session()
        else:
            redirect_to_provider = self._logout(request)
            if redirect_to_provider:
                return redirect_to_provider.to_response(
                    headers={},
                    media_type=MediaType.HTML,
                    status_code=HTTP_307_TEMPORARY_REDIRECT,
                    app=request.app,
                    request=request,
                )

    def valid_access_token(self, request: Request, force_refresh: bool = False) -> Optional[str]:
        """Returns a valid access token.

        1. If the current access token in the user session is valid, return that.
        2. If the current access token has expired and there is a refresh token in the user session,
           make a refresh token request and return the new access token.
        3. If the token refresh fails, either due to missing refresh token or token error response, return None.

        Args:
            request
            force_refresh: whether to perform the refresh token request even if the current access token is valid.

        Returns:
            valid access token

        Examples:
            ::
                from starlite import get

                @get(path='/')
                def my_handler(request: Request) -> ...:
                    ...
                    access_token = auth.valid_access_token(request)
                    ...
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            logger.debug("user does not have an active session")
            return None

        is_expired = session.access_token_expires_at <= time.time() if session.access_token_expires_at else False
        if is_expired is False and force_refresh is False:
            logger.debug("access token doesn't need to be refreshed")
            return session.access_token

        if session.refresh_token is None:
            logger.info("no refresh token exists in the session")
            return None

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
    def _parse_authorization_header(headers: Headers) -> Optional[str]:
        """Looks for authorization in request headers.

        Args:
            headers: Request headers.

        Returns:
            access_token
        """
        if "authorization" in headers and headers["authorization"].startswith("Bearer "):
            _, access_token = headers["authorization"].split(maxsplit=1)
            return access_token

    def token_auth(self, scope: Scope, provider_name: str) -> None:
        """Token based authorization.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Examples:
            ::

                app = Starlite(
                    ...
                    middleware=[DefineMiddleware(OIDCMiddleware, auth=auth, provider_name='default',
                                                 enforce='token_auth')],
                    ...
                )
                auth.init_app(app, redirect_uri='https://client.example.com')
        """
        client = self.clients[provider_name]
        scopes = scope["route_handler"].opt.get("scopes")
        # Check for authorization field in the request headers.
        connection = ASGIConnection[Any, Any, Any](scope)

        access_token = self._parse_authorization_header(headers=connection.headers)
        if access_token is None:
            logger.info("Request header has no authorization field.")
            # Abort the request if authorization field is missing.
            raise NotAuthorizedException()

        if not scope["route_handler"].opt.get("introspection", False):
            result = AccessTokenResponse().from_jwt(txt=access_token, keyjar=client._client.keyjar)
        else:
            # Send token introspection request.
            result = client.introspect_token(access_token=access_token)

        if client._validate_token_info(token=result, scopes=scopes) is True:
            logger.info("Request has valid access token.")
            # Store token introspection info in auth for the user to retrieve more information about the token.
            scope["auth"] = result.to_dict()
            return None
        # Forbid access if the access token is invalid.
        raise PermissionDeniedException()

    def access_control(self, scope: Scope, provider_name: str) -> Optional[RedirectResponse]:
        """This method serves dual purpose that is it can do both token based
        authorization and oidc based authentication. If your API needs to be
        accessible by either modes, use this decorator otherwise use either
        oidc_auth or token_auth.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Returns:
            None if token_auth is successful.
            RedirectResponse if the authentication falls back to oidc_auth.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Examples:
            ::

                app = Starlite(
                    ...
                    middleware=[DefineMiddleware(OIDCMiddleware, auth=auth, provider_name='default',
                                                 enforce='access_control')],
                    ...
                )
                auth.init_app(app, redirect_uri='https://client.example.com')
        """
        try:
            # If the request header contains authorization, token_auth verifies the access token otherwise an exception
            # occurs and the request falls back to oidc_auth.
            return self.token_auth(scope, provider_name)
        # Token_auth will raise the HTTPException if either authorization field is missing from the request headers or
        # if the access token is invalid. If the authorization field is missing, fallback to oidc.
        except NotAuthorizedException:
            return self.oidc_auth(scope, provider_name)
        # If the access token is present, but it's invalid, do not fall back to oidc_auth. Instead, abort the request.
        except PermissionDeniedException:
            raise
