import time
from unittest import mock

import pytest

from starlite_oidc.user_session import UninitialisedSession, UserSession

from .custom_types import SessionStorage


class TestUserSession:
    PROVIDER_NAME: str = "test-provider"
    REFRESH_INTERVAL: int = 10  # in seconds
    TIMESTAMP_MOCK: int = int(time.time())

    def initialise_session(self, session_storage: SessionStorage) -> UserSession:
        return UserSession(session_storage, self.PROVIDER_NAME)

    def create_session(self, **kwargs) -> SessionStorage:
        session_storage = {self.PROVIDER_NAME: kwargs}
        return session_storage

    def test_initialising_session_with_existing_user_session_should_preserve_state(self) -> None:
        """Reinitialising the UserSession with the same provider name should
        not overwrite the existing session."""
        session_storage = {}
        session1 = self.initialise_session(session_storage)
        session1.update()

        session2 = self.initialise_session(session_storage)
        # Don't call "session2.update" here, if the session with the same provider name already exists, this should
        # return True.
        assert session2.is_authenticated() is True

    def test_initialising_session_with_new_provider_name_should_maintain_distinct_sessions(self) -> None:
        """Multiple sessions can exist if there are multiple OIDC providers.

        It should maintain distinct session for each.
        """
        session_storage = {}
        session1 = UserSession(session_storage, "provider1")
        session1.update()
        session2 = UserSession(session_storage, "provider2")
        session2.update()

        assert {"provider1", "provider2"}.issubset(session_storage.keys())

    def test_unauthenticated_and_authenticated_session(self) -> None:
        session = self.initialise_session({})
        assert session.is_authenticated() is False
        # This sets last_authenticated of the current provider to the current time.
        session.update()
        assert session.is_authenticated() is True

    @pytest.mark.parametrize("expires_in, status", [(3600, True), (-1, False)])
    def test_authenticated_session_validate_access_token(self, expires_in: int, status: bool) -> None:
        """Should validate access token if token refresh is not supported.

        In such a case, the session should become unauthenticated if
        access token expires.
        """
        session = self.initialise_session({})
        session.update(expires_in=expires_in)
        assert session.is_authenticated() is status

    @pytest.mark.parametrize("refresh_interval", [None, REFRESH_INTERVAL])
    def test_should_not_refresh_if_no_refresh_interval_or_not_previously_authenticated(
        self, refresh_interval: int
    ) -> None:
        """Either case will not refresh the token."""
        session = self.initialise_session({})
        session._session_refresh_interval_seconds = refresh_interval
        assert session.should_refresh() is False

    @pytest.mark.parametrize("refresh_interval, status", [(REFRESH_INTERVAL - 1, False), (-REFRESH_INTERVAL, True)])
    def test_should_refresh(self, refresh_interval: int, status: bool) -> None:
        session_storage = self.create_session(last_session_refresh=int(time.time()) + refresh_interval)
        session = self.initialise_session(session_storage)
        session._session_refresh_interval_seconds = self.REFRESH_INTERVAL
        assert session.should_refresh() is status

    @pytest.mark.parametrize(
        "data",
        [
            {"access_token": "test-access-token"},
            {
                "id_token": {
                    "iss": "https://idp.example.com",
                    "sub": "user1",
                    "aud": ["client1"],
                    "exp": TIMESTAMP_MOCK,
                    "iat": TIMESTAMP_MOCK,
                }
            },
            {"id_token_jwt": "eyJh.eyJz.SflK"},
            {"userinfo": {"sub": "user1", "name": "Test User"}},
        ],
    )
    @mock.patch("time.time", return_value=TIMESTAMP_MOCK)
    def test_update(self, time_mock: mock.MagicMock, data: SessionStorage) -> None:
        session_storage = {}

        self.initialise_session(session_storage).update(**data)

        expected_session_data = {
            "current_provider": self.PROVIDER_NAME,
            self.PROVIDER_NAME: {
                "last_authenticated": time_mock.return_value,
                "last_session_refresh": time_mock.return_value,
                **data,
            },
        }
        assert session_storage == expected_session_data

    def test_update_should_use_auth_time_from_id_token_if_it_exists(self) -> None:
        auth_time = int(time.time())
        session = self.initialise_session({})
        session.update(id_token={"auth_time": auth_time})
        assert session.last_authenticated == auth_time

    def test_trying_to_pick_up_uninitialised_session_should_throw_exception(self) -> None:
        with pytest.raises(UninitialisedSession):
            UserSession(session_storage={})

    def test_clear(self) -> None:
        expected_data = {"initial data": "should remain"}
        session_storage = self.create_session(
            access_token="test-access-token",
            expires_in=3600,
            id_token={"sub": "user1"},
            id_token_jwt="eyJh.eyJz.SflK",
            userinfo={"sub": "user1}"},
            refresh_token="refresh-token",
        )
        session_storage.update(expected_data)

        session = self.initialise_session(session_storage)
        session.clear((self.PROVIDER_NAME,))

        assert session_storage == expected_data
