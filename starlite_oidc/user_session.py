import time
from collections.abc import KeysView


class UninitialisedSession(Exception):
    pass


class UserSession:
    """Session object for user login state.

    Wraps comparison of times necessary for session handling.
    """

    def __init__(self, session_storage, provider_name=None):
        self._session_storage = session_storage
        self._session_refresh_interval_seconds = None

        if "current_provider" not in self._session_storage and not provider_name:
            raise UninitialisedSession("Trying to pick-up uninitialised session without specifying 'provider_name'")

        if provider_name:
            self._session_storage["current_provider"] = provider_name

    def is_authenticated(self):
        """Session is empty when the session hasn't been initialised.

        Thus checking for existence of any item is enough to determine
        if we're authenticated.
        """
        # If ProviderConfiguration.session_refresh_interval_seconds is None, access token will not be refreshed
        # automatically, so verify the validity of the access token.
        if self.access_token_expires_at and not self._session_refresh_interval_seconds:
            return self.access_token_expires_at >= time.time()
        return self.last_authenticated is not None

    def should_refresh(self):
        return (
            self._session_refresh_interval_seconds is not None
            and self.last_session_refresh is not None
            and self._refresh_time() <= time.time()
        )

    def _refresh_time(self):
        last = self.last_session_refresh
        return last + self._session_refresh_interval_seconds

    def update(
        self, *, access_token=None, expires_in=None, id_token=None, id_token_jwt=None, userinfo=None, refresh_token=None
    ):
        """
        Args:
            access_token (str)
            expires_in (int)
            id_token (Mapping[str, str])
            id_token_jwt (str)
            userinfo (Mapping[str, str])
            refresh_token (str)
        """
        # Store the OIDC tokens under the name of the provider. This is because there can be multiple IdPs with their
        # own issued OIDC tokens.
        self._session_storage[self.current_provider] = {}

        def set_if_defined(session_key, value):
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

    def clear(self, provider_names: KeysView):
        for key in provider_names:
            self._session_storage.pop(key, None)
        self._session_storage.pop("current_provider")

    @property
    def access_token(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("access_token")

    @property
    def access_token_expires_at(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("access_token_expires_at")

    @property
    def refresh_token(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("refresh_token")

    @property
    def id_token(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("id_token")

    @property
    def id_token_jwt(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("id_token_jwt")

    @property
    def userinfo(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("userinfo")

    @property
    def last_authenticated(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("last_authenticated")

    @property
    def last_session_refresh(self):
        if self.current_provider in self._session_storage:
            return self._session_storage[self.current_provider].get("last_session_refresh", 0)

    @property
    def current_provider(self):
        return self._session_storage.get("current_provider")
