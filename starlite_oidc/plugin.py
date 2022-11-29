from time import time
from typing import TYPE_CHECKING, Any, Dict, Mapping, NamedTuple, Optional
from urllib.parse import parse_qsl, urlparse

from oic import rndstr
from oic.oauth2 import Message
from oic.oic.message import AccessTokenResponse
from starlite import DefineMiddleware, InternalServerException, PluginProtocol, Starlite
from starlite.datastructures import Headers
from starlite.exceptions import NotAuthorizedException, PermissionDeniedException
from starlite.response import RedirectResponse
from starlite.status_codes import HTTP_303_SEE_OTHER
from starlite.utils import normalize_path

from .config import OIDCPluginConfig
from .facade import OIDCFacade
from .handlers import create_authentication_handler, create_logout_handler
from .middleware import OIDCAuthenticationMiddleware
from .session import UserSession

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
    """An OpenID Connect Plugin for Starlite."""

    __slots__ = ("facade", "config", "redirect_url")

    def __init__(
        self,
        config: "OIDCPluginConfig",
    ):
        self.config = config
        self.redirect_url = urlparse(config.redirect_url)
        self.facade = OIDCFacade(config=config.provider, redirect_uri=config.redirect_url)

        post_logout_redirect_uris = [
            f"{self.redirect_url.scheme}://{self.redirect_url.netloc}{normalize_path(post_logout_path)}"
            for post_logout_path in (config.post_logout_redirect_paths or [])
        ]

        if not self.facade.config.client_registration_info.get("redirect_uris"):
            self.facade.config.client_registration_info["redirect_uris"] = [self.redirect_url.geturl()]
        if not self.facade.config.client_registration_info.get("post_logout_redirect_uris"):
            self.facade.config.client_registration_info["post_logout_redirect_uris"] = post_logout_redirect_uris

    def on_app_init(self, app: "Starlite") -> None:
        app.register(create_authentication_handler(redirect_path=self.redirect_url.path, facade=self.facade))

        if self.config.logout_handler_path:
            app.register(create_logout_handler(logout_path=self.config.logout_handler_path, facade=self.facade))
        app.middleware = [
            DefineMiddleware(
                OIDCAuthenticationMiddleware,
                exclude=self.config.exclude,
                exclude_opt_key=self.config.exclude_opt_key,
                scopes=self.config.scopes,
                retrieve_user_handler=self.config.retrieve_user_handler,
                authentication_handler=self.handle_oidc_auth if self.config == "oidc_auth" else self.handle_token_auth,
            ),
            *app.middleware,
        ]

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
            user_session = UserSession(**scope.get("session", {}))

            should_refresh_token = (
                user_session.last_session_refresh or 0
            ) + self.facade.config.session_refresh_interval_seconds <= time()

            is_authenticated = not should_refresh_token and bool(
                (user_session.access_token_expires_at or 0 >= time()) or user_session.last_authenticated is not None
            )

            if is_authenticated:
                return user_session.user_info

            return await authenticate(facade=self.facade, scope=scope, interactive=not should_refresh_token)

        except KeyError as e:
            raise InternalServerException(f"provider {provider_name} is not initialized") from e

    async def handle_token_auth(self, scope: "Scope") -> Dict[str, Any]:
        """Token based authorization.

        Args:
            scope: The ASGI connection scope.

        Raises:
            NotAuthorizedException: If no authentication parameters present.
            PermissionDeniedException: If the access token is invalid.

        Returns:
            None
        """
        access_token = parse_authorization_header(headers=Headers.from_scope(scope=scope))
        if not access_token:
            raise NotAuthorizedException("missing authorization header")

        opt = scope["route_handler"].opt
        should_introspect = bool(opt.get("introspection"))

        access_token_message = (
            (await self.facade.request_token_introspection(access_token=access_token))
            if should_introspect
            else AccessTokenResponse().from_jwt(txt=access_token, keyjar=self.facade.oidc_client.keyjar)
        )

        if not self.facade.validate_token(token=access_token_message, scopes=opt.get("scopes")):
            raise PermissionDeniedException()

        return access_token_message.to_dict()
