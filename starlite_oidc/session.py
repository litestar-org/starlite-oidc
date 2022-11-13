from dataclasses import dataclass
from time import time
from typing import Any, Dict, Optional


@dataclass
class UserSession:
    """User session object that can track authenticating against multiple
    providers."""

    access_token: Optional[str] = None
    access_token_expires_at: Optional[int] = None
    id_token: Optional[Dict[str, Any]] = None
    id_token_jwt: Optional[str] = None
    last_authenticated: Optional[int] = None
    last_session_refresh: Optional[int] = None
    refresh_token: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None

    def update(
        self,
        *,
        access_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        id_token: Optional[Dict[str, Any]] = None,
        id_token_jwt: Optional[str] = None,
        refresh_token: Optional[str] = None,
        user_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        now = int(time())
        self.last_authenticated = id_token.get("auth_time", now)
        self.last_session_refresh = now

        if access_token:
            self.access_token = access_token
        if expires_in:
            self.access_token_expires_at = now + expires_in
        if id_token:
            self.id_token = id_token
        if id_token_jwt:
            self.id_token_jwt = id_token_jwt
        if user_info:
            self.user_info = user_info
        if refresh_token:
            self.refresh_token = refresh_token
