from typing import List, Literal, Optional

from pydantic import BaseConfig, BaseModel, validator
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from starlite.middleware import DefineMiddleware, MiddlewareProtocol

from .oidc import OIDCAuthentication


class OIDC(BaseModel):
    """Configuration for OIDC middleware."""

    auth: OIDCAuthentication
    provider_name: str
    enforce: Literal["oidc_auth", "token_auth", "access_control"] = "oidc_auth"
    scopes: Optional[List[str]] = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    @validator("scopes")
    def validate_secret(cls, scopes: List) -> List:
        if not isinstance(scopes, List):
            raise ValueError("scopes must be of type List.")
        return scopes

    @property
    def middleware(self) -> DefineMiddleware:
        return DefineMiddleware(OIDCMiddleware, config=self)


class OIDCMiddleware(MiddlewareProtocol):
    def __init__(self, app: ASGIApp, config: OIDC):

        super().__init__(app)
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Executes the ASGI middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive function.
            send: The ASGI send function.

        Returns:
            None
        """
        # If OIDC scopes are provided, update them on context vars. To keep a generic interface for oidc_auth,
        # token_auth and access_control, context variable is used. It is being used locally by the class, so
        # it will be garbage collected.
        if self.config.scopes:
            self.config.auth._scopes.set(self.config.scopes)

        auth_result = None
        # Do not verify incoming request for callback and logout path.
        if scope["path"] not in (self.config.auth._redirect_uri.path, *self.config.auth._post_logout_redirect_paths):
            auth_result = getattr(self.config.auth, self.config.enforce)(
                scope=scope, provider_name=self.config.provider_name
            )

        if isinstance(auth_result, RedirectResponse):
            await auth_result(scope, receive, send)
        else:
            await self.app(scope, receive, send)
