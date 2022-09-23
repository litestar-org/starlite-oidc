import contextvars
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import ParseResultBytes, parse_qsl, urlparse

import importlib_resources
from oic import rndstr
from oic.extension.message import TokenIntrospectionResponse
from oic.oic import AuthorizationRequest
from oic.oic.message import FrontChannelLogoutRequest
from starlette.responses import RedirectResponse, Response
from starlette.status import HTTP_301_MOVED_PERMANENTLY, HTTP_303_SEE_OTHER
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
    ):
        """Initializes required OIDC parameters and callback.

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
            self._post_logout_redirect_paths = [app.get_handler_index_by_name(view)["path"] for view in logout_views]

    def _get_urls_for_logout_views(self):
        """Resolves post logout redirect URIs from the user defined logout
        paths."""
        root_url = f"{self._redirect_uri.scheme}://{self._redirect_uri.netloc}"
        return [f"{root_url}{post_logout}" for post_logout in self._post_logout_redirect_paths]

    def _register_client(self, client: PyoidcFacade):
        """Registers the client by using OIDC Dynamic Client Registration.

        Parameters
        ----------
        client: PyoidcFacade
            PyoidcFacade instance contains metadata of the provider and client.
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

    def _authenticate(self, client: PyoidcFacade, scope: Scope, interactive=True) -> RedirectResponse:
        """Initiates OIDC authentication.

        Parameters
        ----------
        client : PyoidcFacade
            PyoidcFacade instance contains metadata of the provider and client.
        scope: Scope
            The ASGI connection scope.
        interactive: bool
            If it's false, access token is refreshed without user interation. It requires a refresh token to silently
            refresh the access token.

        Returns
        -------
        RedirectResponse
            Redirects to the IdP authentication URL.
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

        auth_params = dict(parse_qsl(login_url.split("?")[1]))
        session["fragment_encoded_response"] = AuthResponseHandler.expect_fragment_encoded_response(auth_params)
        return RedirectResponse(url=login_url, status_code=HTTP_303_SEE_OTHER)

    async def _handle_authentication_response(self, request: Request) -> Union[Response, str]:
        """This is a callback route handler registered at Starlite instance.
        See `self.init_app` for its registration parameters. This route handler
        exchanges OIDC tokens sent by the IdP. Then it sets them up in the
        session.

        Parameters
        ----------
        request: Request

        Returns
        -------
        Response

        Raises
        ------
        HTTPException
            If the IdP sends error response.
        """
        if request.query_params.get("error"):
            if "error" in request.session:
                raise HTTPException(request.session["error"])
            raise HTTPException("Something went wrong")

        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            return self._handle_error_response(
                request, {"error": "unsolicited_response", "error_description": "No initialised user session"}
            )

        if request.session.pop("fragment_encoded_response", False):
            content = importlib_resources.read_binary("starlite_oidc", "parse_fragment.html").decode("utf-8")
            return Response(content=content, media_type=MediaType.HTML)

        if "auth_request" not in request.session:
            return self._handle_error_response(
                request, {"error": "unsolicited_response", "error_description": "No authentication request stored"}
            )
        auth_request = AuthorizationRequest().from_json(request.session.pop("auth_request"))

        is_processing_fragment_encoded_response = request.method == "POST"
        if is_processing_fragment_encoded_response:
            auth_resp = await request.form()
            auth_resp = dict(auth_resp)
        else:
            auth_resp = request.query_params

        client = self.clients[session.current_provider]

        authn_resp = client.parse_authentication_response(auth_resp)
        logger.debug("received authentication response: %s", authn_resp.to_json())

        try:
            result = AuthResponseHandler(client).process_auth_response(authn_resp, auth_request)
        except AuthResponseErrorResponseError as e:
            return self._handle_error_response(request, e.error_response, is_processing_fragment_encoded_response)
        except AuthResponseProcessError as e:
            return self._handle_error_response(
                request,
                {"error": "unexpected_error", "error_description": str(e)},
                is_processing_fragment_encoded_response,
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
        if is_processing_fragment_encoded_response:
            # if the POST request was from the JS page handling fragment encoded responses we need to return the
            # destination URL as the response body
            return destination

        return RedirectResponse(url=destination, status_code=HTTP_301_MOVED_PERMANENTLY)

    def _handle_error_response(self, request: Request, error_response, should_redirect=False) -> Response:
        """Handles error response from the IdP.

        Parameters
        ----------
        request: Request
        error_response: dict
        should_redirect: bool

        Returns
        -------
        Response

        Raises
        ------
        HTTPException
        """
        logger.error(json.dumps(error_response))
        if should_redirect:
            # if the current request was from the JS page handling fragment encoded responses we need to return a URL
            # for the error page to redirect to.
            request.session["error"] = error_response
            path = f"{self._redirect_uri.path}?error=1"
            return Response(content=path, media_type=MediaType.HTML)
        raise HTTPException(error_response)

    def oidc_auth(self, scope: Scope, provider_name: str):
        """OIDC based authentication. This method manages user authentication
        by verifying if OIDC metadata exists in session and if it exists,
        whether the access token needs a refresh or else initiates
        authentication with the IdP.

        Parameters
        ----------
        scope: Scope
            The ASGI connection scope.
        provider_name : str
            Name of the provider registered with OIDCAuthorization.

        Examples
        --------
        ::

            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='oidc',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
        """
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
        """Performs RP-Initiated Logout action by reporting the logout event to
        the Identity Provider. All OIDC tokens are revoked and the session is
        cleared.

        Parameters
        ----------
        request: Request
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession as e:
            logger.info("user was already logged out, doing nothing")
            return None

        id_token_jwt = session.id_token_jwt
        client = self.clients[session.current_provider]
        session.clear(self._provider_configurations.keys())

        if client.provider_end_session_endpoint:
            request.session["end_session_state"] = rndstr()

            end_session_request = FrontChannelLogoutRequest(
                id_token_hint=id_token_jwt,
                post_logout_redirect_uri=str(request.url),
                state=request.session["end_session_state"],
            )

            logger.debug("send end session request: %s", end_session_request.to_dict())

            return Redirect(path=end_session_request.request(client.provider_end_session_endpoint))
        return None

    def oidc_logout(self, request: Request) -> Optional[RedirectResponse]:
        """Before request hook for RP-Initiated Logout.

        Parameters
        ----------
        request: Request

        Returns
        -------
        RedirectResponse: optional

        Examples
        --------
        ::

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

        Notes
        -----
        This should be only used for route handlers that logs out the user.
        """
        logger.debug("user logout")
        if "state" in request.query_params:
            if request.query_params["state"] != [request.session.pop("end_session_state", None)]:
                logger.error("Got unexpected state '%s' after logout redirect.", request.query_params["state"])
        else:
            redirect_to_provider = self._logout(request)
            if redirect_to_provider:
                return redirect_to_provider.to_response(
                    headers={}, media_type="text/html", status_code=HTTP_303_SEE_OTHER, app=request.app
                )

    def valid_access_token(self, request: Request, force_refresh=False):
        """Returns a valid access token.

        1. If the current access token in the user session is valid, return that.
        2. If the current access token has expired and there is a refresh token in the user session,
           make a refresh token request and return the new access token.
        3. If the token refresh fails, either due to missing refresh token or token error response, return None.

        Args:
            request (Request)
            force_refresh (bool): whether to perform the refresh token request even if the current access token is valid
        Returns:
            Option[str]: valid access token

        Examples:
            @get(path='/')
            def index(request: Request) -> ...:
                ...
                access_token = auth.valid_access_token(request)
                ...
        """
        try:
            session = UserSession(request.session)
        except UninitialisedSession:
            logger.debug("user does not have an active session")
            return None

        has_expired = session.access_token_expires_at < time.time() if session.access_token_expires_at else False
        if not has_expired and not force_refresh:
            logger.debug("access token doesn't need to be refreshed")
            return session.access_token

        if not session.refresh_token:
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
    def _check_authorization_header(headers) -> bool:
        """Look for authorization in request header.

        Parameters
        ----------
        headers
            Request header.

        Returns
        -------
        bool
            True if the request header contains authorization else False.
        """
        if "authorization" in headers and headers["authorization"].startswith("Bearer "):
            return True
        return False

    @staticmethod
    def _parse_access_token(headers) -> str:
        """Parse access token from the authorization request header.

        Parameters
        ----------
        headers
            Request header.

        Returns
        -------
        accept_token : str
            access token from the request header.
        """
        _, access_token = headers["authorization"].split(maxsplit=1)
        return access_token

    def introspect_token(self, headers, client: PyoidcFacade) -> Optional[TokenIntrospectionResponse]:
        """RFC 7662: Token Introspection The Token Introspection extension
        defines a mechanism for resource servers to obtain information about
        access tokens. With this spec, resource servers can check the validity
        of access tokens, and find out other information such as which user and
        which scopes are associated with the token.

        Parameters
        ----------
        headers
            Request header.
        client : PyoidcFacade
            PyoidcFacade instance contains metadata of the provider and client.

        Returns
        -------
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

        Parameters
        ----------
        scope: Scope
            The ASGI connection scope.
        provider_name : str
            Name of the provider registered with OIDCAuthorization.

        Raises
        ------
        NotAuthorizedException
            If no authentication parameters present.
        PermissionDeniedException
            If the access token is invalid.

        Examples
        --------
        ::

            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='token',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
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

        Parameters
        ----------
        scope: Scope
            The ASGI connection scope.
        provider_name : str
            Name of the provider registered with OIDCAuthorization.

        Raises
        ------
        NotAuthorizedException
            If no authentication parameters present.
        PermissionDeniedException
            If the access token is invalid.

        Examples
        --------
        ::

            app = Starlite(
                ...
                middleware=[OIDCConfig(auth=auth, provider_name='default', enforce='access_control',
                                       scopes=['read', 'write']).middleware],
                ...
            )
            auth.init_app(redirect_uri='https://client.example.com')
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
