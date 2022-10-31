import time
from typing import Callable, Dict, List, Literal, Union
from urllib.parse import parse_qs, parse_qsl

import pytest
import responses
from oic.extension.message import TokenIntrospectionResponse
from oic.oic import Grant
from oic.oic.message import (
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationResponse,
    OpenIDSchema,
    TokenErrorResponse,
)
from starlite.status_codes import HTTP_200_OK

from starlite_oidc.pyoidc_facade import PyoidcFacade

from .constants import (
    ACCESS_TOKEN,
    AUTH_CODE,
    CLIENT_ID,
    CLIENT_NAME,
    CLIENT_SECRET,
    NONCE,
    REDIRECT_URI,
    REFRESH_TOKEN,
    SCOPES,
    STATE,
)
from .custom_types import IdTokenStore
from .util import signing_key


class TestPyoidcFacade:
    EXPIRES_IN = int(time.time()) + 60

    def test_registered_client_metadata_is_forwarded_to_pyoidc(self, facade: PyoidcFacade) -> None:
        assert facade._client.registration_response

    @pytest.mark.parametrize("facade", [True], indirect=True)
    def test_no_registered_client_metadata_is_handled(self, facade: PyoidcFacade) -> None:
        assert not facade._client.registration_response

    @pytest.mark.parametrize("facade, status", [(False, True), (True, False)], indirect=["facade"])
    def test_is_registered(self, facade: PyoidcFacade, status: bool) -> None:
        assert facade.is_registered() is status

    @pytest.mark.parametrize("facade", [True], indirect=True)
    @responses.activate
    def test_register(self, facade: PyoidcFacade) -> None:
        client_registration_info = facade._provider_configuration._client_registration_info
        provider_metadata = facade._provider_configuration._provider_metadata

        redirect_uris = client_registration_info["redirect_uris"]
        post_logout_redirect_uris = client_registration_info["post_logout_redirect_uris"]
        client_registration_response = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "client_name": CLIENT_NAME,
            "redirect_uris": redirect_uris,
            "post_logout_redirect_uris": post_logout_redirect_uris,
        }

        responses.post(provider_metadata["registration_endpoint"], json=client_registration_response)
        facade.register()
        assert facade.is_registered() is True
        assert facade.post_logout_redirect_uris == post_logout_redirect_uris

    def test_authentication_request(self, facade: PyoidcFacade) -> None:
        extra_user_auth_params = {"param1": "value1", "param2": "value2"}
        facade._provider_configuration.auth_request_params = extra_user_auth_params

        extra_lib_auth_params = {"param3": "value3", "param4": "value4"}
        nonce = NONCE
        auth_request = facade.authentication_request(state=STATE, nonce=nonce, extra_auth_params=extra_lib_auth_params)
        expected_auth_params = {
            "scope": "openid",
            "response_type": "code",
            "client_id": facade._provider_configuration._client_metadata["client_id"],
            "redirect_uri": REDIRECT_URI,
            "state": STATE,
            "nonce": nonce,
        }
        expected_auth_params.update(extra_user_auth_params)
        expected_auth_params.update(extra_lib_auth_params)

        assert auth_request.to_dict() == expected_auth_params

    @pytest.mark.parametrize(
        "auth, auth_response",
        [
            (AuthorizationResponse, {"state": STATE, "code": AUTH_CODE}),
            (AuthorizationErrorResponse, {"error": "invalid_request", "state": STATE}),
        ],
    )
    def test_parse_authentication_response(
        self,
        auth: Union[AuthorizationResponse, AuthorizationErrorResponse],
        auth_response: Dict[str, str],
        facade: PyoidcFacade,
    ) -> None:
        parsed_auth_response = facade.parse_authentication_response(response_params=auth_response)
        assert isinstance(parsed_auth_response, auth)
        assert parsed_auth_response.to_dict() == auth_response

    @responses.activate
    def test_parse_authentication_response_preserves_id_token_jwt(
        self, facade: PyoidcFacade, id_token_store: IdTokenStore
    ) -> None:
        auth_response = {"state": STATE, "id_token": id_token_store.id_token_jwt}

        responses.get(
            facade._provider_configuration._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
        )
        parsed_auth_response = facade.parse_authentication_response(response_params=auth_response)

        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response["state"] == STATE
        assert parsed_auth_response["id_token_jwt"] == id_token_store.id_token_jwt

    @pytest.mark.parametrize(
        "request_func, expected_token_request",
        [
            (
                lambda facade, auth_code, state: facade.exchange_authorization_code(auth_code, state),
                {"grant_type": "authorization_code", "state": STATE, "redirect_uri": REDIRECT_URI},
            ),
            (
                lambda facade, *args: facade.refresh_token(REFRESH_TOKEN),
                {"grant_type": "refresh_token", "refresh_token": REFRESH_TOKEN, "redirect_uri": REDIRECT_URI},
            ),
        ],
    )
    @responses.activate
    def test_token_request(
        self,
        request_func: Callable[[PyoidcFacade, str, str], AccessTokenResponse],
        expected_token_request: Dict[str, str],
        facade: PyoidcFacade,
        id_token_store: IdTokenStore,
        access_token_response: AccessTokenResponse,
    ) -> None:
        """Token request is made in authorization code flow and in refresh
        token so test for both."""
        grant = Grant(resp=access_token_response)
        grant.grant_expiration_time = int(time.time()) + grant.exp_in
        facade._client.grant = {STATE: grant}

        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

        responses.post(
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=token_response,
        )
        responses.get(
            facade._provider_configuration._provider_metadata["jwks_uri"],
            json={"keys": [signing_key.serialize()]},
        )
        token_request_response = request_func(facade, AUTH_CODE, STATE)

        assert isinstance(token_request_response, AccessTokenResponse)
        expected_token_response = access_token_response.to_dict()
        expected_token_response["id_token"] = id_token_store.id_token.to_dict()
        expected_token_response["id_token_jwt"] = id_token_store.id_token_jwt
        assert token_request_response.to_dict() == expected_token_response

        token_request = dict(parse_qsl(responses.calls[0].request.body))
        assert token_request == expected_token_request

    @responses.activate
    def test_token_request_handles_error_response(self, facade: PyoidcFacade) -> None:
        token_response = TokenErrorResponse(error="invalid_request", error_description="test error description")
        grant = Grant()
        grant.grant_expiration_time = int(time.time()) + grant.exp_in
        facade._client.grant = {STATE: grant}

        responses.post(
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=token_response.to_dict(),
            status=400,
        )
        assert facade.exchange_authorization_code(AUTH_CODE, STATE) == token_response

    def test_token_request_handles_missing_provider_token_endpoint(self, facade: PyoidcFacade) -> None:
        facade._client.token_endpoint = None
        assert facade.exchange_authorization_code(AUTH_CODE, STATE) is None

    @pytest.mark.parametrize("userinfo_http_method", [responses.GET, responses.POST])
    @responses.activate
    def test_configurable_userinfo_endpoint_method_is_used(
        self, userinfo_http_method: Literal["GET", "POST"], facade: PyoidcFacade, userinfo: OpenIDSchema
    ) -> None:
        facade._provider_configuration.userinfo_endpoint_method = userinfo_http_method

        responses.add(
            userinfo_http_method,
            facade._provider_configuration._provider_metadata["userinfo_endpoint"],
            json=userinfo.to_dict(),
        )
        assert facade.userinfo_request(access_token=ACCESS_TOKEN) == userinfo

    def test_no_userinfo_request_is_made_if_no_userinfo_http_method_is_configured(self, facade: PyoidcFacade) -> None:
        facade._provider_configuration.userinfo_endpoint_method = None
        assert facade.userinfo_request(access_token=ACCESS_TOKEN) is None

    def test_no_userinfo_request_is_made_if_no_userinfo_endpoint_is_configured(self, facade: PyoidcFacade) -> None:
        facade._client.userinfo_endpoint = None
        assert facade.userinfo_request(access_token=ACCESS_TOKEN) is None

    def test_no_userinfo_request_is_made_if_no_access_token(self, facade: PyoidcFacade) -> None:
        assert facade.userinfo_request(access_token="") is None

    @responses.activate
    def test_introspection_token(
        self, introspection_result: Dict[str, Union[bool, List[str]]], facade: PyoidcFacade
    ) -> None:
        responses.post(
            facade._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        assert facade.introspect_token(access_token=ACCESS_TOKEN).to_dict() == introspection_result

    @pytest.mark.parametrize(
        "signed_access_token, introspection_result, status, token_type",
        [
            ({}, {}, True, "jwt"),
            ({}, {}, True, "opaque"),
            ({"expires_in": -1}, {"active": False}, False, "run_all"),
            ({"aud": False}, {"scope": "extra"}, False, "run_all"),
        ],
        indirect=["signed_access_token", "introspection_result"],
    )
    @responses.activate
    def test_validate_token_info(
        self,
        signed_access_token: AccessTokenResponse,
        introspection_result: Dict[str, Union[bool, List[str]]],
        status: bool,
        token_type: Literal["jwt", "opaque", "run_all"],
        facade: PyoidcFacade,
    ) -> None:
        """Request should be denied if the access token is valid, client ID is
        not in the list of audience and the scope is not permitted or any of
        these."""
        # Test for both JWT and introspection. The method must behave the same.
        if token_type in ("jwt", "run_all"):
            assert facade._validate_token_info(token=signed_access_token, scopes=SCOPES) is status
        if token_type in ("opaque", "run_all"):
            assert (
                facade._validate_token_info(token=TokenIntrospectionResponse(**introspection_result), scopes=SCOPES)
                is status
            )

    @responses.activate
    @pytest.mark.parametrize("scopes, extra_args", [(None, {}), (SCOPES, {"audience": [CLIENT_ID, "client2"]})])
    def test_client_credentials_grant(
        self, scopes: List[str], extra_args: Dict[str, Union[List[str], str]], facade: PyoidcFacade
    ) -> None:
        client_credentials_scope = " ".join(SCOPES)
        client_credentials_grant_response = {
            "access_token": ACCESS_TOKEN,
            "expires_in": self.EXPIRES_IN,
            "refresh_expires_in": 0,
            "scope": client_credentials_scope,
            "token_type": "Bearer",
        }

        responses.post(
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=client_credentials_grant_response,
        )
        assert (
            client_credentials_grant_response == facade.client_credentials_grant(scopes=scopes, **extra_args).to_dict()
        )

        expected_token_request = {"grant_type": ["client_credentials"], **extra_args}
        if scopes:
            expected_token_request.update({"scope": [client_credentials_scope]})

        client_credentials_grant_request = parse_qs(responses.calls[0].request.body)
        assert client_credentials_grant_request == expected_token_request

    @responses.activate
    def test_revoke_token(self, introspection_result: Dict[str, Union[bool, List[str]]], facade: PyoidcFacade) -> None:
        request_args = {"token": ACCESS_TOKEN, "token_type_hint": "access_token"}
        responses.post(
            facade._provider_configuration._provider_metadata["revocation_endpoint"],
            body="",
            status=200,
            headers={"content-length": "0"},
        )
        assert facade.revoke_token(**request_args) == HTTP_200_OK

        revocation_request = dict(parse_qsl(responses.calls[0].request.body))
        assert revocation_request == request_args
