from functools import partial
from time import time
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Mapping,
    NamedTuple,
    Optional,
)
from urllib.parse import parse_qsl, urlparse

from anyio import create_task_group
from oic import rndstr
from oic.oauth2 import Message
from oic.oic.message import AccessTokenResponse, AuthorizationRequest
from starlite import (
    HTTPRouteHandler,
    InternalServerException,
    PluginProtocol,
    route,
)
from starlite.connection import Request
from starlite.datastructures import Headers
from starlite.enums import HttpMethod
from starlite.exceptions import (
    HTTPException,
    NotAuthorizedException,
    PermissionDeniedException,
)
from starlite.response import RedirectResponse
from starlite.status_codes import (
    HTTP_301_MOVED_PERMANENTLY,
    HTTP_303_SEE_OTHER,
    HTTP_403_FORBIDDEN,
)
from starlite.utils import normalize_path

from .config import OIDCPluginConfig
from .facade import OIDCFacade
from .session import ProviderUserData, UserSession

if TYPE_CHECKING:
    from starlite.types import Scope


class AuthenticationResult(NamedTuple):
    access_token: Optional[str]
    expires_in: Optional[int]
    id_token_claims: Optional[Dict[str, Any]]
    id_token_jwt: Optional[str]
    user_info_claims: Optional[str]
    refresh_token: Optional[str]


async def process_auth_response(
    facade: OIDCFacade,
    auth_response: Message,
    auth_request: Dict[str, Any],
) -> AuthenticationResult:
    """
    Args:
        facade:
        auth_response: parsed OIDC auth response
        auth_request: original OIDC auth request
    Returns:
        AuthenticationResult: All relevant data associated with the authenticated user
    """
    if "error" in auth_response:
        raise NotAuthorizedException(extra=auth_response.to_dict())

    if auth_response["state"] != auth_request["state"]:
        raise NotAuthorizedException("invalid state")

    access_token = auth_response.get("access_token")
    expires_in = auth_response.get("expires_in")
    id_token_claims = auth_response["id_token"].to_dict() if "id_token" in auth_response else None
    id_token_jwt = auth_response.get("id_token_jwt")
    refresh_token = None

    if "code" in auth_response:
        token_resp = await facade.request_access_token(
            code=auth_response["code"], state=auth_response["state"], auth_request=auth_request
        )
        if token_resp:
            access_token = token_resp["access_token"]
            expires_in = token_resp.get("expires_in")
            refresh_token = token_resp.get("refresh_token")

            if "id_token" in token_resp:
                id_token_claims = token_resp["id_token"].to_dict()
                id_token_jwt = token_resp.get("id_token_jwt")

    user_info = await facade.request_user_info(access_token)
    user_info_claims = user_info.to_dict() if user_info else None

    if id_token_claims and user_info_claims and user_info_claims["sub"] != id_token_claims["sub"]:
        raise NotAuthorizedException("invalid 'sub'")

    return AuthenticationResult(
        access_token=access_token,
        expires_in=expires_in,
        id_token_claims=id_token_claims,
        id_token_jwt=id_token_jwt,
        user_info_claims=user_info_claims,
        refresh_token=refresh_token,
    )


def expect_fragment_encoded_response(auth_request: Mapping[str, str]) -> bool:
    """

    Args:
        auth_request:

    Returns:

    """
    if "response_mode" in auth_request:
        return auth_request["response_mode"] == "fragment"

    return set(auth_request["response_type"].split(" ")) in [
        {"code", "id_token"},
        {"code", "token"},
        {"code", "id_token", "token"},
        {"id_token"},
        {"id_token", "token"},
    ]


def parse_authorization_header(headers: Headers) -> Optional[str]:
    """Looks for authorization in request headers.

    Args:
        headers: Request headers.

    Returns:
        access_token
    """
    authorization_header = headers.get("authorization", "")
    if authorization_header.startswith("Bearer"):
        return authorization_header.replace("Bearer").strip()
    return None


def create_authentication_handler(redirect_path: str, facades: Dict[str, OIDCFacade]) -> "HTTPRouteHandler":
    """This is a callback route handler registered at Starlite instance. See
    `self.init_app` for its registration parameters. This route handler
    exchanges OIDC tokens sent by the IdP. Then it sets them up in the session.

    Args:
        redirect_path:
        facades:

    Returns:
    """

    async def handle_authentication_response(request: "Request") -> RedirectResponse:
        """

        Args:
            request: A Request instance.

        Returns:
            RedirectResponse: Redirects back to the path from where OIDC was triggered.

        Raises:
            HTTPException: If the IdP sends error response.
        """
        session = UserSession(**request.session)

        auth_request = request.session.pop("auth_request", None)
        if not auth_request:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                extra={"error": "unsolicited_response", "error_description": "No authentication request stored."},
            )

        try:
            facade = facades[session.current_provider_name]

            if request.method == "POST":
                auth_response = facade.parse_authorization_response(dict(await request.form()))
            elif request.session.pop("fragment_encoded_response", False):
                auth_response = facade.parse_authorization_response(dict(parse_qsl(urlparse(str(request.url)).query)))
            else:
                auth_response = facade.parse_authorization_response(request.query_params)

            result = await process_auth_response(
                facade=facade,
                auth_response=auth_response,
                auth_request=AuthorizationRequest().from_json(auth_request).to_dict(),
            )

            session.update(
                access_token=result.access_token,
                expires_in=result.expires_in,
                id_token=result.id_token_claims,
                id_token_jwt=result.id_token_jwt,
                user_info=result.user_info_claims,
                refresh_token=result.refresh_token,
            )

            destination = request.session.pop("destination")
            return RedirectResponse(url=destination, status_code=HTTP_301_MOVED_PERMANENTLY)
        except KeyError as e:
            raise InternalServerException(f"provider {session.current_provider_name} is not initialized") from e

    return route(path=redirect_path, http_method=[HttpMethod.GET, HttpMethod.POST])(handle_authentication_response)


async def authenticate(facade: "OIDCFacade", scope: "Scope", interactive: bool) -> RedirectResponse:
    """Initiates OIDC authentication.

    Args:
        facade: OIDCFacade instance contains metadata of the provider and facade.
        scope: The ASGI connection scope.
        interactive: If it's false, access token is refreshed without user iteration.
            It requires a refresh token to silently refresh the access token.

    Returns:
        RedirectResponse: Redirects to the IdP authentication URL.
    """
    if not facade.config.client_metadata:
        await facade.register_client()

    authorization_request = facade.create_authorization_request(
        state=rndstr(), nonce=rndstr(), extra_auth_params={} if interactive else {"prompt": "none"}
    )

    login_url = facade.get_login_url_from_auth_request(authorization_request)

    scope.setdefault("session", {})
    scope["session"]["destination"] = scope["path"]
    scope["session"]["auth_request"] = authorization_request.to_json()
    scope["session"]["fragment_encoded_response"] = expect_fragment_encoded_response(  # type: ignore
        dict(parse_qsl(urlparse(login_url).query))
    )

    return RedirectResponse(url=login_url, status_code=HTTP_303_SEE_OTHER)


class OIDCPlugin(PluginProtocol):
    """
    An OpenID Connect Plugin for Starlite.

    """

    __slots__ = ("facades", "config", "authentication_handler")

    def __init__(
        self,
        config: "OIDCPluginConfig",
    ):
        self.config = config
        redirect_url = urlparse(config.redirect_url)
        self.facades = {
            provider_name: OIDCFacade(config=provider, redirect_uri=config.redirect_url)
            for provider_name, provider in config.providers.items()
        }
        self.authentication_handler = create_authentication_handler(
            redirect_path=redirect_url.path, facades=self.facades
        )

        post_logout_redirect_uris = [
            f"{redirect_url.scheme}://{redirect_url.netloc}{normalize_path(post_logout_path)}"
            for post_logout_path in (config.post_logout_redirect_paths or [])
        ]

        for facade in self.facades:
            if not facade.config.client_registration_info.get("redirect_uris"):
                facade.config.client_registration_info["redirect_uris"] = [redirect_url.geturl()]
            if not facade.config.client_registration_info.get("post_logout_redirect_uris"):
                facade.config.client_registration_info["post_logout_redirect_uris"] = post_logout_redirect_uris

    def handle_oidc_auth(self, scope: "Scope", provider_name: str) -> Optional[RedirectResponse]:
        """
        Args:
            scope: The ASGI connection scope.
            provider_name: Name of the provider registered with OIDCAuthorization.

        Returns:
            Redirect to the IdP for authentication. If the user is already authenticated, it returns None. If the
            access token is needed to be refreshed, it is refreshed silently and None is returned.

        Raises:
            InternalServerException: If the given provider is not in the configured providers.
        """
        try:
            facade = self.facades[provider_name]
            user_session = UserSession(
                providers={provider_name: ProviderUserData(**scope.get("session", {}))},
                current_provider_name=provider_name,
            )

            should_refresh_token = (
                user_session.current_provider.last_session_refresh or 0
            ) + facade.config.session_refresh_interval_seconds <= time()

            is_authenticated = not should_refresh_token and bool(
                (user_session.current_provider.access_token_expires_at or 0 >= time())
                or user_session.current_provider.last_authenticated is not None
            )

            if is_authenticated:
                scope["auth"] = user_session.current_provider.user_info
                return None

            return await authenticate(facade=facade, scope=scope, interactive=not should_refresh_token)

        except KeyError as e:
            raise InternalServerException(f"provider {provider_name} is not initialized") from e

    async def handle_token_auth(self, scope: "Scope", provider_name: str) -> None:
        """Token based authorization.

        Args:
            scope: The ASGI connection scope.
            provider_name: Name of OP to use.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Returns:
            None
        """
        facade = self.facades[provider_name]

        access_token = parse_authorization_header(headers=Headers.from_scope(scope=scope))
        if not access_token:
            raise NotAuthorizedException("missing authorization header")

        opt = scope["route_handler"].opt
        should_introspect = bool(opt.get("introspection"))

        access_token_message = (
            (await facade.request_token_introspection(access_token=access_token))
            if should_introspect
            else AccessTokenResponse().from_jwt(txt=access_token, keyjar=facade.oidc_client.keyjar)
        )

        if not facade.validate_token(token=access_token_message, scopes=opt.get("scopes")):
            raise PermissionDeniedException()

        scope["auth"] = access_token_message.to_dict()

        return None

    async def handle_logout(self, request: "Request") -> Optional[RedirectResponse]:
        """

        Args:
            request:

        Returns:

        """
        state = request.query_params.get("state")
        if state and state != request.session.get("end_session_state"):
            request.clear_session()
            return

        scope_session = request.scope.get("session")

        if not scope_session or not scope_session.get("current_provider_name"):
            return

        current_provider_name = scope_session["current_provider_name"]

        user_session = UserSession(
            providers={current_provider_name: ProviderUserData(**request.scope["session"])},
            current_provider_name=current_provider_name,
        )

        state = rndstr()
        post_logout_redirect_uri = str(request.url)
        scope_session["end_session_state"] = state

        non_current_providers = [
            key for key in self.facades if key != current_provider_name and key in user_session.providers
        ]
        if non_current_providers:
            async with create_task_group() as task_group:
                for provider_name in non_current_providers:
                    user_provider_data = user_session.providers[provider_name]
                    task_group.start_soon(
                        partial(
                            self.facades[provider_name].request_session_end,
                            id_token_jwt=user_provider_data.id_token_jwt,
                            post_logout_redirect_uri=post_logout_redirect_uri,
                            state=state,
                            interactive=False,
                        )
                    )

        end_session_request_url: Optional[str] = None
        if self.facades[current_provider_name].provider_end_session_endpoint:
            end_session_request_url = await self.facades[current_provider_name].request_session_end(
                id_token_jwt=user_session.current_provider.id_token_jwt,
                post_logout_redirect_uri=post_logout_redirect_uri,
                state=state,
                interactive=True,
            )

        user_session.clear(set(self.facades.keys()))

        if end_session_request_url:
            return RedirectResponse(
                url=end_session_request_url,
            )
        return None
