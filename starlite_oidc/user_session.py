import time
from collections.abc import KeysView
from typing import Any, Dict, Mapping, Optional, cast


class UninitialisedSessionExcpetion(Exception):
    pass


class UserSession:
    """Session management for user OIDC.

    Wraps comparison of times necessary for session handling.
    """

    def __init__(self, session_storage: Dict[str, Any], provider_name: Optional[str] = None) -> None:
        """Loads session into the instance for session handling.

        Args:
            session_storage: Request session.
            provider_name

        Raises:
            UninitialisedSession: If the session is empty and provider_name is not given.
        """
        self._session_storage = session_storage
        self._session_refresh_interval_seconds = 0

        if "current_provider" not in self._session_storage and not provider_name:
            raise UninitialisedSessionExcpetion(
                "Trying to pick-up uninitialised session without specifying 'provider_name'"
            )

        if provider_name:
            self._session_storage["current_provider"] = provider_name

    def is_authenticated(self) -> bool:
        """Checks if the session is active.

        Session is empty when the session hasn't been initialised. Thus,
        checking for existence of any item is enough to determine if
        we're authenticated.
        """
        if self.access_token_expires_at and not self._session_refresh_interval_seconds:
            # If ProviderConfiguration.session_refresh_interval_seconds is None, access token will not be refreshed
            # automatically, so verify the validity of the access token.
            return self.access_token_expires_at >= time.time()
        return self.last_authenticated is not None

    def should_refresh(self) -> bool:
        """Checks if the access token is needed refresh."""
        return (
            self._session_refresh_interval_seconds
            and self.last_session_refresh is not None
            and self._refresh_time() <= time.time()
        )

    def _refresh_time(self) -> int:
        """Calculates time to refresh the access token."""
        last: int = self.last_session_refresh or 0
        return last + self._session_refresh_interval_seconds or 0

    def update(
        self,
        *,
        access_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        id_token: Optional[Dict[str, Any]] = None,
        id_token_jwt: Optional[str] = None,
        userinfo: Optional[Dict[str, Any]] = None,
        refresh_token: Optional[str] = None
    ) -> None:
        """Updates OIDC session.

        Args:
            access_token
            expires_in
            id_token
            id_token_jwt
            userinfo
            refresh_token
        """
        # Store the OIDC tokens under the name of the provider. This is because there can be multiple IdPs with their
        # own issued OIDC tokens.
        self._session_storage[self.current_provider] = {}

        def set_if_defined(session_key: str, value: Any) -> None:
            """Sets OIDC tokens and metadata."""
            if value:
                self._session_storage[self.current_provider][session_key] = value

        now = int(time.time())
        auth_time = now
        if id_token:
            auth_time = id_token.get("auth_time", auth_time)

        self._session_storage[self.current_provider]["last_authenticated"] = auth_time
        self._session_storage[self.current_provider]["last_session_refresh"] = now
        set_if_defined("access_token", access_token)
        set_if_defined("access_token_expires_at", now + expires_in if expires_in else None)
        set_if_defined("id_token", id_token)
        set_if_defined("id_token_jwt", id_token_jwt)
        set_if_defined("userinfo", userinfo)
        set_if_defined("refresh_token", refresh_token)

    def clear(self, provider_names: KeysView) -> None:
        """Clears OIDC tokens and metadata."""
        for key in provider_names:
            self._session_storage.pop(key, None)
        self._session_storage.pop("current_provider")

    @property
    def access_token(self) -> Optional[str]:
        return cast(str, self._session_storage.get(self.current_provider, {}).get("access_token"))

    @property
    def access_token_expires_at(self) -> Optional[int]:
        return cast(int, self._session_storage.get(self.current_provider, {}).get("access_token_expires_at"))

    @property
    def refresh_token(self) -> Optional[str]:
        return cast(str, self._session_storage.get(self.current_provider, {}).get("refresh_token"))

    @property
    def id_token(self) -> Optional[Mapping[str, Any]]:
        return cast("Mapping[str, Any]", self._session_storage.get(self.current_provider, {}).get("id_token"))

    @property
    def id_token_jwt(self) -> Optional[str]:
        return cast(str, self._session_storage.get(self.current_provider, {}).get("id_token_jwt"))

    @property
    def userinfo(self) -> Optional[Mapping[str, Any]]:
        return cast("Mapping[str, Any]", self._session_storage.get(self.current_provider, {}).get("userinfo"))

    @property
    def last_authenticated(self) -> Optional[int]:
        return cast(int, self._session_storage.get(self.current_provider, {}).get("last_authenticated"))

    @property
    def last_session_refresh(self) -> int:
        return cast(int, self._session_storage.get(self.current_provider, {}).get("last_session_refresh", 0))

    @property
    def current_provider(self) -> str:
        return cast(str, self._session_storage.get("current_provider", ""))
