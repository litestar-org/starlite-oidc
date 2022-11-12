from typing import Callable, Awaitable, Union, Dict, Any

from starlite.response import RedirectResponse
from starlite.types import SyncOrAsyncUnion, Scope

AuthenticationHandler = Callable[[Scope], Awaitable[Union[RedirectResponse, Dict[str, Any]]]]
RetrieveUserHandler = Callable[[Scope, Dict[str, Any]], SyncOrAsyncUnion[Any]]
