import copy
import json
import time
from typing import Any, Dict, List, Union
from unittest import mock
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from oic.oic.message import AccessTokenResponse, OpenIDSchema
from pytest import FixtureRequest
from starlite import Starlite, get
from starlite.connection import Request
from starlite.exceptions import NotAuthorizedException, PermissionDeniedException
from starlite.middleware.session import SessionCookieConfig
from starlite.response import RedirectResponse
from starlite.status_codes import (
    HTTP_302_FOUND,
    HTTP_307_TEMPORARY_REDIRECT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
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
    SCOPES,
    STATE,
)
from .custom_types import IdTokenStore
from .util import signing_key


class TestOIDCAuthentication:
    UNKNOWN_PROVIDER = "unknown"
    FORM_CONTENT_TYPE = {"Content-Type": "application/x-www-form-urlencoded"}

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
    def request_factory(
        self, request: FixtureRequest, signed_access_token: AccessTokenResponse, app: Starlite
    ) -> Request:
        headers = {}
        param = getattr(request, "param", None)
        if param == "signed":
            access_token = signed_access_token.to_jwt(key=[signing_key], algorithm=signing_key.alg)
            headers["authorization"] = f"Bearer {access_token}"
        elif param == "unsigned":
            headers["authorization"] = f"Bearer {ACCESS_TOKEN}"

        request = RequestFactory(app=app, server=str(urlparse(CLIENT_BASE_URL).hostname)).get(headers=headers)
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

    @staticmethod
    def set_cookies(session: Dict[str, Any], test_client: TestClient) -> None:
        cookies = test_client._create_session_cookies(backend=test_client.session_backend, data=session)
        for key, value in cookies.items():
            test_client.cookies.set(key, value, domain=test_client.base_url.host)

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
        self, request_factory: Request, user_info: OpenIDSchema, auth: OIDCAuthentication
    ) -> None:
        UserSession(request_factory.session, PROVIDER_NAME).update(user_info=user_info)
        auth_status = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)
        assert auth_status is None
        assert request_factory.user == user_info
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
        assert "prompt=none" in auth_redirect.headers["location"]  # ensure silent auth is used

    @pytest.mark.parametrize("response_type, expected", [("code", False), ("id_token token", True)])
    def test_expected_auth_response_mode_is_set(
        self, response_type: str, expected: bool, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration.auth_request_params = {"response_type": response_type}
        auth_redirect = auth.oidc_auth(scope=request_factory.scope, provider_name=PROVIDER_NAME)
        assert request_factory.session["fragment_encoded_response"] is expected
        assert isinstance(auth_redirect, RedirectResponse) is True

    def test_using_unknown_provider_should_raise_exception(
        self, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        with pytest.raises(ValueError) as exc_info:
            auth.oidc_auth(request_factory.scope, provider_name=self.UNKNOWN_PROVIDER)
        assert self.UNKNOWN_PROVIDER in str(exc_info.value)

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
        """Performs Dynamic client registration.

        Redirect URI(s) is required. If not provided by the feature, it
        will be obtained from the path of callback route handler.
        However, post logout redirect URIs are optional.
        """
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

        responses.post(provider_config._provider_metadata["registration_endpoint"], json=client_registration_response)
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
        auth: OIDCAuthentication,
        user_info: OpenIDSchema,
        request_factory: Request,
        request_client: TestClient,
    ) -> None:
        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

        # Freeze time since ID Token validation includes expiration timestamp.
        utc_time_sans_frac_mock.return_value = time_mock.return_value
        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            auth.oidc_auth(request_factory.scope, PROVIDER_NAME)

        # Mock IdP's responses for token exchange request, JWKs endpoint and user_info.
        responses.post(provider_config._provider_metadata["token_endpoint"], json=token_response)
        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
        )
        responses.get(provider_config._provider_metadata["user_info_endpoint"], json=user_info.to_dict())
        # Set cookies before making the request to the callback route handler.
        self.set_cookies(session=request_factory.session, test_client=request_client)
        # Mock request to the route handler with preloaded state and auth-code as if there are sent by IdP.
        request_client.get(url=f"{auth._redirect_uri.path}?state={STATE}&code={AUTH_CODE}", follow_redirects=True)

        # Callback route handler sets session with received OIDC tokens.
        session_storage = request_client.get_session_data()
        session = UserSession(session_storage, PROVIDER_NAME)
        assert session.access_token == token_response["access_token"]
        assert session.access_token_expires_at == time_mock.return_value + token_response["expires_in"]
        assert session.refresh_token == token_response["refresh_token"]
        assert session.id_token == access_token_response["id_token"].to_dict()
        assert session.id_token_jwt == id_token_jwt
        assert session.user_info == user_info.to_dict()

    @pytest.mark.parametrize("request_method", ["GET", "POST"])
    @mock.patch("oic.utils.time_util.utc_time_sans_frac")
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
        user_info: OpenIDSchema,
        request_client: TestClient,
    ) -> None:
        auth.clients[PROVIDER_NAME]._provider_configuration.auth_request_params = {"response_type": "id_token token"}

        id_token_claims = access_token_response.pop("id_token")
        id_token_jwt = access_token_response.pop("id_token_jwt")
        access_token_response["id_token"] = id_token_jwt
        access_token_response["state"] = STATE
        authorization_response = access_token_response.to_dict()

        utc_time_sans_frac_mock.return_value = time_mock.return_value
        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            auth.oidc_auth(request_factory.scope, PROVIDER_NAME)

        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
        )
        responses.get(provider_config._provider_metadata["user_info_endpoint"], json=user_info.to_dict())
        self.set_cookies(session=request_factory.session, test_client=request_client)
        if request_method == "GET":
            # The IdP sends urlencoded query parameters in GET request to the callback route handler.
            request_client.get(
                url=f"{auth._redirect_uri.path}?{access_token_response.to_urlencoded()}", follow_redirects=True
            )
        else:
            # Parameters are sent in form.
            request_client.post(
                url=str(auth._redirect_uri.path),
                content=access_token_response.to_urlencoded(),
                headers=self.FORM_CONTENT_TYPE,
                follow_redirects=True,
            )

        session_storage = request_client.get_session_data()
        session = UserSession(session_storage, PROVIDER_NAME)
        assert session.access_token == authorization_response["access_token"]
        assert session.access_token_expires_at == time_mock.return_value + authorization_response["expires_in"]
        # Refresh Tokens are not allowed in the implicit grant.
        assert session.refresh_token is None
        assert session.id_token == id_token_claims.to_dict()
        assert session.id_token_jwt == id_token_jwt
        assert session.user_info == user_info.to_dict()

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

    def test_handle_error_response_no_stored_auth_request(
        self, auth: OIDCAuthentication, request_factory: Request, request_client: TestClient
    ) -> None:
        auth.oidc_auth(request_factory.scope, PROVIDER_NAME)
        request_factory.session.pop("auth_request")

        request_client.set_session_data(data=request_factory.session)
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
        assert request_client.get(url=POST_LOGOUT_REDIRECT_PATH).text == LOGOUT_STATUS

        # Test with session. Add sessions of multiple providers.
        UserSession(request_factory.session, DYNAMIC_CLIENT_PROVIDER_NAME).update(
            id_token_jwt=id_token_store.id_token_jwt
        )
        UserSession(request_factory.session, PROVIDER_NAME).update(id_token_jwt=id_token_store.id_token_jwt)
        self.set_cookies(session=request_factory.session, test_client=request_client)

        end_session_url = auth.clients[DYNAMIC_CLIENT_PROVIDER_NAME].provider_end_session_endpoint
        # Mock redirect response from IdP.
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

        # Ensure that the user session has been cleared.
        session = request_client.get_session_data()
        assert all(provider_name not in session for provider_name in auth.clients)
        assert query_params["state"] == session["end_session_state"]

        # If the logout is called more than once, RP-Initiated Logout should not re-run.
        for _ in range(2):
            recall_response = request_client.get(url=POST_LOGOUT_REDIRECT_PATH, params={"state": query_params["state"]})
            assert recall_response.text == LOGOUT_STATUS
            assert request_client.get_session_data() == {}

    def test_oidc_logout_without_end_session_endpoint(
        self,
        auth: OIDCAuthentication,
        request_factory: Request,
        id_token_store: IdTokenStore,
        request_client: TestClient,
    ) -> None:
        # For branch coverage, mock third provider.
        auth.clients[self.UNKNOWN_PROVIDER] = copy.copy(auth.clients[PROVIDER_NAME])

        auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata.pop("end_session_endpoint")
        auth.clients[DYNAMIC_CLIENT_PROVIDER_NAME]._provider_configuration._provider_metadata.pop(
            "end_session_endpoint"
        )

        UserSession(request_factory.session, DYNAMIC_CLIENT_PROVIDER_NAME).update(
            id_token_jwt=id_token_store.id_token_jwt
        )
        UserSession(request_factory.session, PROVIDER_NAME).update(id_token_jwt=id_token_store.id_token_jwt)
        request_client.get(url=POST_LOGOUT_REDIRECT_PATH)
        self.set_cookies(session=request_factory.session, test_client=request_client)
        end_session_redirect_response = request_client.get(url=POST_LOGOUT_REDIRECT_PATH)
        # Redirect to provider cannot occur if end-session endpoint URL is missing. The route handler will still be
        # called.
        assert end_session_redirect_response.text == LOGOUT_STATUS

        session = request_client.get_session_data()
        assert all(provider_name not in session for provider_name in auth.clients)

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
        request_factory: Request,
    ):
        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

        if expired is True:
            expires_in = -1
        else:
            # Forced refresh will refresh the access token even if it is not expired.
            expires_in = token_response["expires_in"]

        UserSession(request_factory.session, PROVIDER_NAME).update(
            refresh_token=token_response["refresh_token"], expires_in=expires_in
        )

        provider_config = auth.clients[PROVIDER_NAME]._provider_configuration

        responses.post(provider_config._provider_metadata["token_endpoint"], json=token_response)
        responses.get(
            provider_config._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
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
        "request_factory, status", [(None, None), ("unsigned", ACCESS_TOKEN)], indirect=["request_factory"]
    )
    def test_should_parse_authorization_header(
        self, auth: OIDCAuthentication, request_factory: Request, status: bool
    ) -> None:
        access_token = status
        assert auth._parse_authorization_header(request_factory.headers) == access_token

    @pytest.mark.parametrize(
        "request_factory, signed_access_token, auth_exception",
        [(None, {}, NotAuthorizedException), ("signed", {"expires_in": -1}, PermissionDeniedException)],
        indirect=["request_factory", "signed_access_token"],
    )
    @responses.activate
    def test_token_auth_should_raise_exception_if_verification_fails(
        self,
        request_factory: Request,
        auth_exception: Union[NotAuthorizedException, PermissionDeniedException],
        auth: OIDCAuthentication,
    ) -> None:
        with pytest.raises(auth_exception):
            responses.get(
                auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["jwks_uri"],
                json={"keys": [signing_key.serialize()]},
            )
            auth.token_auth(request_factory.scope, PROVIDER_NAME)

    @pytest.mark.parametrize(
        "request_factory, introspection", [("unsigned", True), ("signed", False)], indirect=["request_factory"]
    )
    @responses.activate
    def test_token_auth_and_access_control_for_valid_access_token(
        self,
        introspection: bool,
        auth: OIDCAuthentication,
        request_factory: Request,
        signed_access_token: AccessTokenResponse,
        introspection_result: Dict[str, Union[bool, List[str]]],
    ) -> None:
        request_factory.scope["route_handler"].opt["scopes"] = SCOPES
        request_factory.scope["route_handler"].opt["introspection"] = introspection
        provider_metadata = auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata

        responses.get(provider_metadata["jwks_uri"], json={"keys": [signing_key.serialize()]})
        responses.post(provider_metadata["introspection_endpoint"], json=introspection_result)
        assert auth.token_auth(request_factory.scope, PROVIDER_NAME) is None
        assert auth.access_control(request_factory.scope, PROVIDER_NAME) is None
        assert request_factory.auth == introspection_result if introspection else signed_access_token.to_dict()
        # scope["route_handler"].opt is mutable, set it to False again.
        request_factory.scope["route_handler"].opt["introspection"] = False

    def test_access_control_should_fallback_to_oidc_auth(
        self, auth: OIDCAuthentication, request_factory: Request
    ) -> None:
        control = auth.access_control(request_factory.scope, PROVIDER_NAME)
        assert isinstance(control, RedirectResponse) is True

    @pytest.mark.parametrize("request_factory, signed_access_token", [("signed", {"expires_in": -1})], indirect=True)
    @responses.activate
    def test_access_control_should_deny_permission_if_verification_fails(
        self,
        auth: OIDCAuthentication,
        request_factory: Request,
    ) -> None:
        responses.get(
            auth.clients[PROVIDER_NAME]._provider_configuration._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
        )
        with pytest.raises(PermissionDeniedException):
            auth.access_control(request_factory.scope, PROVIDER_NAME)
