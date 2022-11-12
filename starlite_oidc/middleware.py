from typing import Optional, List, TYPE_CHECKING

from starlite import AbstractMiddleware
from starlite.response import RedirectResponse
from starlite.utils import AsyncCallable

if TYPE_CHECKING:
    from starlite.types import ASGIApp, Scopes, Scope, Receive, Send
    from starlite_oidc.types import AuthenticationHandler, RetrieveUserHandler


class OIDCAuthenticationMiddleware(AbstractMiddleware):
    """OIDC Middleware."""

    __slots__ = ("authentication_handler","retrieve_user_handler")

    def __init__(
        self,
        app: "ASGIApp",
        exclude: Optional[List[str]],
        exclude_opt_key: Optional[str],
        scopes: Optional["Scopes"],
        authentication_handler: "AuthenticationHandler",
        retrieve_user_handler: "RetrieveUserHandler",
    ):
        """
        Args:
            app,
            auth,
            provider_name: Name of the provider defined in auth.
            enforce: 'handle_oidc_auth' implements OIDC based authentication, 'handle_token_auth' implements authorization of request
                and 'access_control' combines both of them.
            exclude_opt_key: Endpoints to be kept excluded from this middleware.
        """
        super().__init__(app=app, exclude=exclude, exclude_opt_key=exclude_opt_key, scopes=scopes)
        self.authentication_handler = authentication_handler
        self.retrieve_user_handler = AsyncCallable(retrieve_user_handler)

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        """Executes the ASGI middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.

        Returns:
            None
        """
        auth_result = await self.authentication_handler(scope)

        if isinstance(auth_result, RedirectResponse):
            await auth_result(scope, receive, send)
            return

        scope["auth"] = auth_result
        scope["user"] = await self.retrieve_user_handler(scope, auth_result)
        await self.app(scope, receive, send)
