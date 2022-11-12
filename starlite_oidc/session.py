from dataclasses import dataclass
from time import time
from typing import Any, Dict, Optional, Set


@dataclass
class ProviderUserData:
    """Container for user data for a particular provider."""

    access_token_expires_at: Optional[int] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    id_token: Optional[Dict[str, Any]] = None
    id_token_jwt: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None
    last_authenticated: Optional[int] = None
    last_session_refresh: Optional[int] = None


@dataclass
class UserSession:
    """User session object that can track authenticating against multiple
    providers."""

    current_provider_name: Optional[str]
    providers: Dict[str, ProviderUserData]

    @property
    def current_provider(self) -> Optional[ProviderUserData]:
        """

        Returns:

        """
        if self.current_provider_name:
            return self.providers[self.current_provider_name]
        return None

    def update(
        self,
        *,
        access_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        id_token: Optional[Dict[str, Any]] = None,
        id_token_jwt: Optional[str] = None,
        user_info: Optional[Dict[str, Any]] = None,
        refresh_token: Optional[str] = None
    ) -> None:
        """

        Args:
            access_token:
            expires_in:
            id_token:
            id_token_jwt:
            user_info:
            refresh_token:
        """
        now = int(time())
        self.current_provider.last_authenticated = id_token.get("auth_time", now)
        self.current_provider.last_session_refresh = now

        if access_token:
            self.current_provider.access_token = access_token
        if expires_in:
            self.current_provider.access_token_expires_at = now + expires_in
        if id_token:
            self.current_provider.id_token = id_token
        if id_token_jwt:
            self.current_provider.id_token_jwt = id_token_jwt
        if user_info:
            self.current_provider.user_info = user_info
        if refresh_token:
            self.current_provider.refresh_token = refresh_token

    def clear(self, provider_names: Set[str]) -> None:
        """Clears OIDC tokens and metadata."""
        for name in provider_names:
            if name in self.providers:
                del self.providers[name]

            if name == self.current_provider_name:
                self.current_provider_name = None
