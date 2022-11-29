from typing import Any, Awaitable, Callable, Dict, Union

from starlite.response import RedirectResponse
from starlite.types import Scope, SyncOrAsyncUnion

AuthenticationHandler = Callable[[Scope], Awaitable[Union[RedirectResponse, Dict[str, Any]]]]
RetrieveUserHandler = Callable[[Scope, Dict[str, Any]], SyncOrAsyncUnion[Any]]
