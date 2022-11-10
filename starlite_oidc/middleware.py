from typing import TYPE_CHECKING, List, Optional

from starlite import AbstractMiddleware
from starlite.response import RedirectResponse
from starlite.types import ASGIApp, Receive, Scope, Send

from .oidc import OIDCAuthentication

if TYPE_CHECKING:
    from typing_extensions import Literal


class OIDCMiddleware(AbstractMiddleware):
    """OIDC Middleware."""

    __slots__ = ("auth", "provider_name", "enforce", "exclude_from_auth_key")

    def __init__(
        self,
        app: ASGIApp,
        auth: OIDCAuthentication,
        provider_name: str,
        enforce: 'Literal["oidc_auth", "token_auth", "access_control"]' = "oidc_auth",
        exclude: Optional[List[str]] = None,
        exclude_opt_key: str = "exclude_from_auth",
    ):
        """
        Args:
            app,
            auth,
            provider_name: Name of the provider defined in auth.
            enforce: 'oidc_auth' implements OIDC based authentication, 'token_auth' implements authorization of request
                and 'access_control' combines both of them.
            exclude_opt_key: Endpoints to be kept excluded from this middleware.
        """
        super().__init__(app=app, exclude=exclude, exclude_opt_key=exclude_opt_key)
        self.auth = auth
        self.provider_name = provider_name
        self.enforce = enforce

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        """Executes the ASGI middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.

        Returns:
            None
        """
        auth_result = getattr(self.auth, self.enforce)(scope=scope, provider_name=self.provider_name)

        if isinstance(auth_result, RedirectResponse):
            await auth_result(scope, receive, send)
        else:
            await self.app(scope, receive, send)
