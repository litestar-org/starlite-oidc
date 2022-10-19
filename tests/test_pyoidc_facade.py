import time
from typing import Callable, Dict, List, Literal, Union
from unittest import mock
from urllib.parse import parse_qs, parse_qsl

import pytest
import responses
from oic.oic import Grant
from oic.oic.message import (
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationResponse,
    OpenIDSchema,
    TokenErrorResponse,
)
from starlette.status import HTTP_302_FOUND

from starlite_oidc.pyoidc_facade import PyoidcFacade

from .constants import (
    ACCESS_TOKEN,
    AUTH_CODE,
    CLIENT_BASE_URL,
    CLIENT_ID,
    CLIENT_NAME,
    CLIENT_SECRET,
    NONCE,
    POST_LOGOUT_REDIRECT_PATH,
    REDIRECT_URI,
    REFRESH_TOKEN,
    STATE,
)
from .custom_types import IdTokenStore


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
            json={"keys": [id_token_store.id_token_signing_key.serialize()]},
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
            json={"keys": [id_token_store.id_token_signing_key.serialize()]},
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
    def test_token_introspection_request_should_cache_and_return_cached_results(
        self, introspection_result: Dict[str, Union[bool, List[str]]], facade: PyoidcFacade
    ) -> None:
        responses.post(
            facade._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        # Make multiple token introspection request for the same access token. HTTP request should be made for only 1st
        # request. The others will be returned from cache.
        for _ in range(3):
            result = facade._token_introspection_request(access_token=ACCESS_TOKEN)
            assert result.to_dict() == introspection_result

        assert facade._token_introspection_request.cache(facade)
        assert responses.assert_call_count(
            url=facade._provider_configuration._provider_metadata["introspection_endpoint"], count=1
        )

        # Cache should be purged after it expires. Set the clock to future. Just by adding 1 sec more than TTL is
        # enough to expire the cache.
        with mock.patch("cachetools._TimedCache._Timer.__enter__", return_value=time.monotonic() + 61):
            assert not facade._token_introspection_request.cache(facade)

    @responses.activate
    def test_end_session_should_purge_access_token_from_cache_on_end_session_request(
        self,
        facade: PyoidcFacade,
        introspection_result: Dict[str, Union[bool, List[str]]],
        id_token_store: IdTokenStore,
    ):
        responses.post(
            facade._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        facade._token_introspection_request(access_token=ACCESS_TOKEN)
        assert len(facade._token_introspection_request.cache(facade)) == 1

        post_logout_redirect_uri = f"{CLIENT_BASE_URL}{POST_LOGOUT_REDIRECT_PATH}"
        responses.add(
            responses.Response(
                responses.POST,
                url=facade.provider_end_session_endpoint,
                status=HTTP_302_FOUND,
                headers={"Location": f"{post_logout_redirect_uri}?state={STATE}"},
                auto_calculate_content_length=True,
            )
        )
        facade._end_session_request(
            id_token_jwt=id_token_store.id_token_jwt,
            post_logout_redirect_uri=post_logout_redirect_uri,
            state=STATE,
            access_token=ACCESS_TOKEN,
            interactive=False,
        )
        assert len(facade._token_introspection_request.cache(facade)) == 0

    @responses.activate
    @pytest.mark.parametrize(
        "scopes, extra_args", [(None, {}), (["read", "write"], {"audience": [CLIENT_ID, "client2"]})]
    )
    def test_client_credentials_grant(
        self, scopes: List[str], extra_args: Dict[str, Union[List[str], str]], facade: PyoidcFacade
    ) -> None:
        client_credentials_grant_response = {
            "access_token": ACCESS_TOKEN,
            "expires_in": self.EXPIRES_IN,
            "refresh_expires_in": 0,
            "scope": "read write",
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
            expected_token_request.update({"scope": [" ".join(scopes)]})

        client_credentials_grant_request = parse_qs(responses.calls[0].request.body)
        assert client_credentials_grant_request == expected_token_request

    @responses.activate
    def test_revoke_token(self, introspection_result: Dict[str, Union[bool, List[str]]], facade: PyoidcFacade) -> None:
        # "PyoidcFacade.revoke_token" not only revokes the token but also removes its cache. So, create an access token
        # cache by making a token introspection request.
        responses.post(
            facade._provider_configuration._provider_metadata["introspection_endpoint"],
            json=introspection_result,
        )
        facade._token_introspection_request(access_token=ACCESS_TOKEN)

        # Validate the length of the cache to verify if access token has been cached.
        assert len(facade._token_introspection_request.cache(facade)) == 1
        assert facade._token_introspection_request.cache_key(facade, access_token="ACCESS_TOKEN")

        request_args = {"token": ACCESS_TOKEN, "token_type_hint": "access_token"}
        responses.post(
            facade._provider_configuration._provider_metadata["revocation_endpoint"],
            body="",
            status=200,
            headers={"content-length": "0"},
        )
        revocation_response = facade.revoke_token(**request_args)
        assert revocation_response == 200
        # Validate the length of the cache again to verify if its cache has been removed.
        assert len(facade._token_introspection_request.cache(facade)) == 0

        revocation_request = dict(parse_qsl(responses.calls[0].request.body))
        assert revocation_request == request_args
