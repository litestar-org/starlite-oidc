import json
import time
from typing import Any, Dict, List, Union
from unittest import mock
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from oic.oic.message import AccessTokenResponse, OpenIDSchema
from pytest import FixtureRequest
from starlette.responses import RedirectResponse
from starlette.status import (
    HTTP_302_FOUND,
    HTTP_307_TEMPORARY_REDIRECT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from starlite import Starlite
from starlite.connection.request import Request
from starlite.exceptions import NotAuthorizedException, PermissionDeniedException
from starlite.handlers.http import get
from starlite.middleware.session import SessionCookieConfig
from starlite.testing import RequestFactory, TestClient
from starlite.testing.request_factory import _default_route_handler

from starlite_oidc.oidc import OIDCAuthentication
from starlite_oidc.provider_configuration import ClientRegistrationInfo
from starlite_oidc.user_session import UserSession

from .constants import (
    ACCESS_TOKEN,
    AUTH_CODE,
    CLIENT_BASE_URL,
    DYNAMIC_CLIENT_PROVIDER_NAME,
    LOGOUT_STATUS,
    NONCE,
    POST_LOGOUT_REDIRECT_PATH,
    POST_LOGOUT_VIEW,
    PROVIDER_NAME,
    REDIRECT_URI,
    STATE,
)
from .custom_types import IdTokenStore


class TestOIDCAuthentication:
    HOSTNAME = str(urlparse(CLIENT_BASE_URL).hostname)
    DYNAMIC_CLIENT_PROVIDER_NAME = "dynamic"
    CURRENT_PROVIDER = "current_provider"
    FORM_CONTENT_TYPE = {"Content-Type": "application/x-www-form-urlencoded"}
    AUTHORIZATION_HEADER = {"authorization": f"Bearer {ACCESS_TOKEN}"}
    SCOPES = ["read", "write"]

    @pytest.fixture()
    def app(self, auth: OIDCAuthentication, session_config: SessionCookieConfig) -> Starlite:
        @get(path=POST_LOGOUT_REDIRECT_PATH, name=POST_LOGOUT_VIEW, before_request=auth.oidc_logout)
        def logout() -> str:
            return "logged out"

        return Starlite(route_handlers=[_default_route_handler, logout], middleware=[session_config.middleware])

    @pytest.fixture(autouse=True)
    def init_app(self, request: FixtureRequest, app: Starlite, auth: OIDCAuthentication) -> None:
        param = getattr(request, "param", False)
        logout_views = POST_LOGOUT_VIEW if param is False else param
        init_app_args = {"app": app, "redirect_uri": REDIRECT_URI, "logout_views": logout_views}
        auth.init_app(**init_app_args)

    @pytest.fixture()
    def request_factory(self, request: FixtureRequest, app: Starlite) -> Request:
        params = getattr(request, "param", None)
        request = RequestFactory(app=app, server=self.HOSTNAME).get(headers=params)
        return request

    @pytest.fixture()
    def request_client(self, app: Starlite, session_config: SessionCookieConfig) -> TestClient:
        with TestClient(app=app, base_url=CLIENT_BASE_URL, session_config=session_config) as client:
            yield client

    @pytest.fixture()
    def expected_registration_request(
        self, client_registration_info: ClientRegistrationInfo
    ) -> Dict[str, Union[List[str], str]]:
        return {
            "application_type": "web",
            "response_types": ["code"],
            "client_name": client_registration_info["client_name"],
            "redirect_uris": client_registration_info["redirect_uris"],
            "post_logout_redirect_uris": client_registration_info["post_logout_redirect_uris"],
            "grant_types": ["authorization_code"],
        }

    def set_cookies(self, session: Dict[str, Any], test_client: TestClient) -> None:
        cookies = test_client.create_session_cookies(session_data=session)
        for key, value in cookies.items():
            test_client.cookies.set(key, value, domain=self.HOSTNAME)

    @pytest.mark.parametrize("init_app", [None, POST_LOGOUT_VIEW, [POST_LOGOUT_VIEW]], indirect=True)
    def test_init_app(self, auth: OIDCAuthentication, app: Starlite) -> None:
        assert auth._redirect_uri.geturl() == REDIRECT_URI
        assert PROVIDER_NAME in auth.clients
        assert auth._post_logout_redirect_paths in ([], [POST_LOGOUT_REDIRECT_PATH])

    def test_should_authenticate_if_no_session(self, auth: OIDCAuthentication, request_factory: Request) -> None:
        auth_redirect = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)

        assert isinstance(auth_redirect, RedirectResponse) is True
        assert "auth_request" in request_factory.session
        assert request_factory.session["current_provider"] == PROVIDER_NAME

    def test_should_not_authenticate_if_session_exists(
        self, request_factory: Request, userinfo: OpenIDSchema, auth: OIDCAuthentication
    ) -> None:
        UserSession(request_factory.session, PROVIDER_NAME).update(userinfo=userinfo)
        auth_status = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)
        assert auth_status is None
        assert request_factory.user == userinfo
        assert PROVIDER_NAME in request_factory.session["current_provider"]

    def test_reauthenticate_silently_if_session_expired(
        self, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration.session_refresh_interval_seconds = 60  # in seconds

        with mock.patch("time.time") as time_mock:
            time_mock.return_value = int(time.time()) - 1  # authenticated in the past
            UserSession(request_factory.session, PROVIDER_NAME).update()
        auth_redirect = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)

        assert isinstance(auth_redirect, RedirectResponse) is True
        assert PROVIDER_NAME in request_factory.session["current_provider"]

        _, location = auth_redirect.raw_headers
        _, uri = location
        assert b"prompt=none" in uri  # ensure silent auth is used

    @pytest.mark.parametrize("response_type, expected", [("code", False), ("id_token token", True)])
    def test_expected_auth_response_mode_is_set(
        self, response_type: str, expected: bool, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration.auth_request_params = {"response_type": response_type}
        auth_redirect = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)
        assert request_factory.session["fragment_encoded_response"] is expected
        assert isinstance(auth_redirect, RedirectResponse) is True

    @pytest.mark.parametrize(
        "init_app, remove_uris", [(None, False), (POST_LOGOUT_VIEW, True), (None, True)], indirect=["init_app"]
    )
    @responses.activate
    def test_should_register_client_if_not_registered_before(
        self,
        remove_uris: bool,
        auth: OIDCAuthentication,
        request_factory: Request,
        client_registration_response: Dict[str, Union[List[str], str]],
        expected_registration_request: Dict[str, Union[List[str], str]],
    ) -> None:
        client = auth.clients[DYNAMIC_CLIENT_PROVIDER_NAME]
        provider_config = client._provider_configuration

        if remove_uris is True:
            provider_config._client_registration_info["redirect_uris"] = None
            expected_registration_request["redirect_uris"] = [REDIRECT_URI]

            provider_config._client_registration_info["post_logout_redirect_uris"] = None
            if auth._post_logout_redirect_paths:
                expected_registration_request["post_logout_redirect_uris"] = [
                    f"{CLIENT_BASE_URL}{POST_LOGOUT_REDIRECT_PATH}"
                ]
            else:
                expected_registration_request.pop("post_logout_redirect_uris")

        registration_endpoint = provider_config._provider_metadata["registration_endpoint"]

        responses.post(registration_endpoint, json=client_registration_response)
        auth_redirect = auth.oidc_auth(scope=request_factory.scope, provider_name=DYNAMIC_CLIENT_PROVIDER_NAME)

        assert provider_config._client_metadata is not None
        assert isinstance(auth_redirect, RedirectResponse) is True

        registration_request = json.loads(responses.calls[0].request.body)
        assert registration_request == expected_registration_request

    @mock.patch("oic.utils.time_util.utc_time_sans_frac")  # used internally by pyoidc when verifying ID Token
    @mock.patch("time.time", return_value=int(time.time()))
    @responses.activate
    def test_handle_authentication_response(
        self,
        time_mock,
        utc_time_sans_frac_mock,
        access_token_response: AccessTokenResponse,
        id_token_store: IdTokenStore,
        userinfo: OpenIDSchema,
        auth: OIDCAuthentication,
        request_factory: Request,
        request_client: TestClient,
    ) -> None:
        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

        # Freeze time since ID Token validation includes expiration timestamps.
        utc_time_sans_frac_mock.return_value = time_mock.return_value
        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            auth.oidc_auth(request_factory.scope, PROVIDER_NAME)

        responses.post(provider_config._provider_metadata["token_endpoint"], json=token_response)
        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [id_token_store.id_token_signing_key.serialize()]},
        )
        responses.get(provider_config._provider_metadata["userinfo_endpoint"], json=userinfo.to_dict())
        self.set_cookies(session=request_factory.session, test_client=request_client)
        request_client.get(url=f"{auth._redirect_uri.path}?state={STATE}&code={AUTH_CODE}", follow_redirects=True)

        session_storage = request_client.get_session_from_cookies()
        session = UserSession(session_storage, PROVIDER_NAME)
        assert session.access_token == token_response["access_token"]
        assert session.access_token_expires_at == time_mock.return_value + token_response["expires_in"]
        assert session.refresh_token == token_response["refresh_token"]
        assert session.id_token == access_token_response["id_token"].to_dict()
        assert session.id_token_jwt == id_token_jwt
        assert session.userinfo == userinfo.to_dict()

    @pytest.mark.parametrize("request_method", ["GET", "POST"])
    @mock.patch("oic.utils.time_util.utc_time_sans_frac")  # used internally by pyoidc when verifying ID Token
    @mock.patch("time.time", return_value=int(time.time()))
    @responses.activate
    def test_handle_implicit_authentication_response(
        self,
        time_mock,
        utc_time_sans_frac_mock,
        request_method: str,
        access_token_response: AccessTokenResponse,
        auth: OIDCAuthentication,
        request_factory: Request,
        id_token_store: IdTokenStore,
        userinfo: OpenIDSchema,
        request_client: TestClient,
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration.auth_request_params = {"response_type": "id_token token"}

        id_token_claims = access_token_response.pop("id_token")
        id_token_jwt = access_token_response.pop("id_token_jwt")
        access_token_response["id_token"] = id_token_jwt
        access_token_response["state"] = STATE
        authorization_response = access_token_response.to_dict()

        # freeze time since ID Token validation includes expiration timestamps
        utc_time_sans_frac_mock.return_value = time_mock.return_value
        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            auth.oidc_auth(request_factory.scope, PROVIDER_NAME)

        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [id_token_store.id_token_signing_key.serialize()]},
        )
        responses.get(provider_config._provider_metadata["userinfo_endpoint"], json=userinfo.to_dict())
        self.set_cookies(session=request_factory.session, test_client=request_client)
        if request_method == "GET":
            request_client.get(
                url=f"{auth._redirect_uri.path}?{access_token_response.to_urlencoded()}", follow_redirects=True
            )
        else:
            request_client.post(
                url=str(auth._redirect_uri.path),
                content=access_token_response.to_urlencoded(),
                headers=self.FORM_CONTENT_TYPE,
                follow_redirects=True,
            )

        session_storage = request_client.get_session_from_cookies()
        session = UserSession(session_storage, PROVIDER_NAME)
        assert session.access_token == authorization_response["access_token"]
        assert session.access_token_expires_at == time_mock.return_value + authorization_response["expires_in"]
        # Refresh Tokens are not allowed in the implicit grant.
        assert session.refresh_token is None
        assert session.id_token == id_token_claims.to_dict()
        assert session.id_token_jwt == id_token_jwt
        assert session.userinfo == userinfo.to_dict()

    def test_handle_error_response(
        self, request_client: TestClient, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        uninitialised_session_error_response = {
            "error": "Uninitialised Session",
            "error_description": "Trying to pick-up uninitialised session without specifying 'provider_name'",
        }
        uninitialised_session_response = request_client.post(url=str(auth._redirect_uri.path))
        assert uninitialised_session_response.json()["extra"] == uninitialised_session_error_response

        auth.oidc_auth(request_factory.scope, PROVIDER_NAME)
        assert "auth_request" in request_factory.session

        error_response = {"state": STATE, "error": "invalid_request", "error_description": "test error"}
        self.set_cookies(session=request_factory.session, test_client=request_client)
        response = request_client.post(
            url=str(auth._redirect_uri.path), data=error_response, headers=self.FORM_CONTENT_TYPE
        )

        assert response.json()["extra"] == error_response
        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
        # Obtain session from raw session cookies to check if the callback route handler has modified the session.
        session = request_client.get_session_from_cookies()
        # If the session has been modified the key "error" should exist in the session.
        assert "error" in session

        # If the request to the callback route handler is retried without reinitializing oidc_auth, the state of the
        # error should not change regardless of the correct response.
        same_response = request_client.post(url=str(auth._redirect_uri.path))
        assert same_response.json()["extra"] == error_response
        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR

    def test_handle_error_response_no_stored_auth_request(
        self, auth: OIDCAuthentication, request_factory: Request, request_client: TestClient
    ) -> None:
        auth.oidc_auth(request_factory.scope, PROVIDER_NAME)
        request_factory.session.pop("auth_request")

        request_client.cookies = request_client.create_session_cookies(session_data=request_factory.session)
        response = request_client.post(url=str(auth._redirect_uri.path))

        missing_auth_request_error = {
            "error": "unsolicited_response",
            "error_description": "No authentication request stored.",
        }
        assert response.json()["extra"] == missing_auth_request_error

    @responses.activate
    def test_oidc_logout_redirects_to_provider(
        self,
        request_factory: Request,
        id_token_store: IdTokenStore,
        request_client: TestClient,
        auth: OIDCAuthentication,
    ) -> None:
        # Test with empty session. The logout route handler should run even if there is no session.
        assert request_client.get(url=POST_LOGOUT_REDIRECT_PATH).json() == LOGOUT_STATUS

        # Test with session. Add sessions of multiple providers.
        UserSession(request_factory.session, DYNAMIC_CLIENT_PROVIDER_NAME).update(
            id_token_jwt=id_token_store.id_token_jwt
        )
        UserSession(request_factory.session, PROVIDER_NAME).update(id_token_jwt=id_token_store.id_token_jwt)
        self.set_cookies(session=request_factory.session, test_client=request_client)

        end_session_url = auth.clients[DYNAMIC_CLIENT_PROVIDER_NAME].provider_end_session_endpoint
        responses.add(
            responses.Response(
                responses.POST,
                url=end_session_url,
                status=HTTP_302_FOUND,
                headers={"Location": f"{CLIENT_BASE_URL}{POST_LOGOUT_REDIRECT_PATH}?state={STATE}"},
                auto_calculate_content_length=True,
            )
        )
        end_session_redirect_response = request_client.get(url=POST_LOGOUT_REDIRECT_PATH, follow_redirects=False)

        parsed_url = urlparse(str(end_session_redirect_response.next_request.url))
        query_params = dict(parse_qsl(parsed_url.query))
        assert end_session_redirect_response.is_redirect is True
        assert end_session_redirect_response.status_code == HTTP_307_TEMPORARY_REDIRECT
        assert (
            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            == auth.clients[PROVIDER_NAME].provider_end_session_endpoint
        )
        assert query_params["id_token_hint"] == id_token_store.id_token_jwt
        assert query_params["post_logout_redirect_uri"] == f"{CLIENT_BASE_URL}{POST_LOGOUT_REDIRECT_PATH}"

        # Ensure that user session has been cleared.
        session = request_client.get_session_from_cookies()
        assert all(provider_name not in session for provider_name in auth.clients)
        assert query_params["state"] == session["end_session_state"]

        # If the logout is called more than once, RP-Initiated Logout should not re-run.
        for _ in range(2):
            recall_response = request_client.get(url=POST_LOGOUT_REDIRECT_PATH, params={"state": query_params["state"]})
            assert recall_response.json() == LOGOUT_STATUS
            assert request_client.get_session_from_cookies() == {}

    def test_oidc_logout_without_end_session_endpoint(
        self,
        auth: OIDCAuthentication,
        request_factory: Request,
        id_token_store: IdTokenStore,
        request_client: TestClient,
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata.pop("end_session_endpoint")

        UserSession(request_factory.session, PROVIDER_NAME).update(id_token_jwt=id_token_store.id_token_jwt)
        request_client.get(url=POST_LOGOUT_REDIRECT_PATH)
        self.set_cookies(session=request_factory.session, test_client=request_client)
        end_session_redirect_response = request_client.get(url=POST_LOGOUT_REDIRECT_PATH)
        # Redirect to provider cannot occur if end-session endpoint URL is missing. The route handler will be called.
        assert end_session_redirect_response.json() == LOGOUT_STATUS

        # Ensure that user session has been cleared.
        session = request_client.get_session_from_cookies()
        assert all(provider_name not in session for provider_name in auth.clients)

    def test_using_unknown_provider_name_should_raise_exception(
        self, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        with pytest.raises(ValueError) as exc_info:
            auth.oidc_auth(request_factory.scope, provider_name="unknown")
        assert "unknown" in str(exc_info.value)

    def test_validate_access_token_should_not_refresh_access_token(
        self, auth: OIDCAuthentication, request_factory: Request, access_token_response: AccessTokenResponse
    ) -> None:
        # Test with empty session
        assert auth.valid_access_token(request=request_factory) is None

        # Test with session
        session = UserSession(request_factory.session, PROVIDER_NAME)
        # Add access token with no expiry.
        session.update(access_token=ACCESS_TOKEN)
        assert auth.valid_access_token(request=request_factory) is ACCESS_TOKEN

        # Expire the access token.
        session.update(expires_in=-1)
        # No refresh token present, will return None.
        assert auth.valid_access_token(request=request_factory) is None
        # Add refresh token.
        session.update(
            access_token=ACCESS_TOKEN,
            refresh_token=access_token_response["refresh_token"],
            expires_in=access_token_response["expires_in"],
        )
        # Access token is not expired yet so the access token will not be updated and will be returned as is.
        assert auth.valid_access_token(request=request_factory) is ACCESS_TOKEN

    @pytest.mark.parametrize("expired, forced", [(True, False), (False, True)])
    @responses.activate
    def test_validate_access_token_should_refresh_access_token(
        self,
        expired: bool,
        forced: bool,
        access_token_response: AccessTokenResponse,
        auth: OIDCAuthentication,
        id_token_store: IdTokenStore,
        request_factory: Request,
    ):

        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

        if expired is True:
            expires_in = -1
        else:
            expires_in = token_response["expires_in"]

        UserSession(request_factory.session, PROVIDER_NAME).update(
            refresh_token=token_response["refresh_token"], expires_in=expires_in
        )

        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        responses.post(provider_config._provider_metadata["token_endpoint"], json=token_response)
        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [id_token_store.id_token_signing_key.serialize()]},
        )
        auth.valid_access_token(request=request_factory, force_refresh=forced)
        assert request_factory.session[PROVIDER_NAME]["access_token"] == ACCESS_TOKEN

    @responses.activate
    def test_should_return_none_if_token_refresh_request_fails(
        self, request_factory: Request, access_token_response: AccessTokenResponse, auth: OIDCAuthentication
    ) -> None:
        UserSession(request_factory.session, PROVIDER_NAME).update(
            refresh_token=access_token_response["refresh_token"], expires_in=-1
        )

        token_response = {"error": "invalid_grant", "error_description": "The refresh token is invalid"}

        responses.post(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["token_endpoint"],
            json=token_response,
        )
        assert auth.valid_access_token(request=request_factory) is None

    @pytest.mark.parametrize(
        "request_factory, status", [(None, False), (AUTHORIZATION_HEADER, True)], indirect=["request_factory"]
    )
    def test_should_check_for_authorization_header(
        self, auth: OIDCAuthentication, request_factory: Request, status: bool
    ) -> None:
        assert auth._check_authorization_header(request_factory.headers) is status
        if status is True:
            assert auth._parse_access_token(request_factory.headers) == ACCESS_TOKEN

    @pytest.mark.parametrize(
        "introspection_result",
        [{"active": False}, {"aud": "no_client"}, {"scope": "extra"}, {"short_lived": True}, {}],
        indirect=["introspection_result"],
    )
    @responses.activate
    def test_introspect_token(
        self,
        introspection_result: Dict[str, Union[bool, List[str]]],
        request_factory: Request,
        auth: OIDCAuthentication,
    ) -> None:
        request_factory._headers = self.AUTHORIZATION_HEADER
        request_factory.scope["route_handler"].opt["scopes"] = self.SCOPES

        client = auth.clients[PROVIDER_NAME]
        provider_config = client._provider_configuration

        responses.post(provider_config._provider_metadata["introspection_endpoint"], json=introspection_result)
        result = auth.introspect_token(request_factory.headers, self.SCOPES, client)
        assert result is None or result.to_dict() == introspection_result
        assert responses.assert_call_count(url=provider_config._provider_metadata["introspection_endpoint"], count=1)

    @pytest.mark.parametrize(
        "request_factory, auth_exception",
        [(None, NotAuthorizedException), (AUTHORIZATION_HEADER, PermissionDeniedException)],
        indirect=["request_factory"],
    )
    @responses.activate
    def test_token_auth_should_raise_exception_if_verification_fails(
        self,
        request_factory: Request,
        auth_exception: Union[NotAuthorizedException, PermissionDeniedException],
        auth: OIDCAuthentication,
        introspection_result: Dict[str, Union[bool, List[str]]],
    ) -> None:
        introspection_result["active"] = False

        responses.post(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        with pytest.raises(auth_exception):
            auth.token_auth(request_factory.scope, PROVIDER_NAME)

    @pytest.mark.parametrize("request_factory", [AUTHORIZATION_HEADER], indirect=True)
    @responses.activate
    def test_token_auth_for_valid_access_token(
        self,
        auth: OIDCAuthentication,
        introspection_result: Dict[str, Union[bool, List[str]]],
        request_factory: Request,
    ) -> None:
        request_factory.scope["route_handler"].opt["scopes"] = self.SCOPES

        responses.post(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        assert auth.token_auth(request_factory.scope, PROVIDER_NAME) is None
        assert request_factory.auth == introspection_result

    @pytest.mark.parametrize("request_factory", [AUTHORIZATION_HEADER], indirect=True)
    @responses.activate
    def test_access_control_should_run_token_auth(
        self,
        auth: OIDCAuthentication,
        introspection_result: Dict[str, Union[bool, List[str]]],
        request_factory: Request,
    ) -> None:
        request_factory.scope["route_handler"].opt["scopes"] = self.SCOPES

        responses.post(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        assert auth.access_control(request_factory.scope, PROVIDER_NAME) is None
        assert request_factory.auth == introspection_result

    def test_access_control_should_fallback_to_oidc_auth(
        self, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        control = auth.access_control(request_factory.scope, PROVIDER_NAME)
        assert isinstance(control, RedirectResponse) is True

    @pytest.mark.parametrize(
        "request_factory, introspection_result", [(AUTHORIZATION_HEADER, {"active": False})], indirect=True
    )
    @responses.activate
    def test_access_control_should_deny_permission_if_verification_fails(
        self,
        auth: OIDCAuthentication,
        introspection_result: Dict[str, Union[bool, List[str]]],
        request_factory: Request,
    ) -> None:
        responses.post(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        with pytest.raises(PermissionDeniedException):
            auth.access_control(request_factory.scope, PROVIDER_NAME)
