from typing import Literal

from starlite.middleware import MiddlewareProtocol
from starlite.response import RedirectResponse
from starlite.types import ASGIApp, Receive, Scope, Send

from .oidc import OIDCAuthentication


class OIDCMiddleware(MiddlewareProtocol):
    """OIDC Middleware."""

    __slots__ = ("auth", "provider_name", "enforce", "exclude_from_auth_key")

    def __init__(
        self,
        app: ASGIApp,
        auth: OIDCAuthentication,
        provider_name: str,
        enforce: Literal["oidc_auth", "token_auth", "access_control"] = "oidc_auth",
        exclude_from_auth_key: str = "exclude_from_auth",
    ):
        """
        Args:
            app,
            auth,
            provider_name: Name of the provider defined in auth.
            enforce: 'oidc_auth' implements OIDC based authentication, 'token_auth' implements authorization of request
                and 'access_control' combines both of them.
            exclude_from_auth_key: Endpoints to be kept excluded from this middleware.
        """
        super().__init__()
        self.app = app
        self.auth = auth
        self.provider_name = provider_name
        self.enforce = enforce
        self.exclude_from_auth_key = exclude_from_auth_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Executes the ASGI middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.

        Returns:
            None
        """
        auth_result = None
        # Do not verify incoming request for callback, logout and for auth excluded paths.
        exclude_from_auth = scope["route_handler"].opt.get(self.exclude_from_auth_key, False)
        if exclude_from_auth is False and scope["path"] not in (
            self.auth._redirect_uri.path,
            *self.auth._post_logout_redirect_paths,
        ):
            auth_result = getattr(self.auth, self.enforce)(scope=scope, provider_name=self.provider_name)

        if isinstance(auth_result, RedirectResponse):
            await auth_result(scope, receive, send)
        else:
            await self.app(scope, receive, send)
