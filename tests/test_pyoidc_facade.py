import time
from typing import Callable, Dict, List, Literal, Union
from urllib.parse import parse_qs, parse_qsl

import pytest
import responses
from oic.oic import (
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationResponse,
    Grant,
    OpenIDSchema,
    TokenErrorResponse,
)

from starlite_oidc.provider_configuration import (
    ClientMetadata,
    ClientRegistrationInfo,
    ProviderConfiguration,
    ProviderMetadata,
)
from starlite_oidc.pyoidc_facade import PyoidcFacade

from .util import signed_id_token


class TestPyoidcFacade:
    CLIENT_ID: str = "client1"
    REDIRECT_URI: str = "https://client.example.com/redirect"
    STATE: str = "test-state"
    NONCE: str = "test-nonce"
    AUTH_CODE: str = "test-auth-code"
    ACCESS_TOKEN: str = "test-token"

    def test_registered_client_metadata_is_forwarded_to_pyoidc(self, facade: PyoidcFacade) -> None:
        assert facade._client.registration_response

    def test_no_registered_client_metadata_is_handled(self, provider_metadata: ProviderMetadata) -> None:
        config = ProviderConfiguration(
            provider_metadata=provider_metadata, client_registration_info=ClientRegistrationInfo()
        )
        facade = PyoidcFacade(config, self.REDIRECT_URI)
        assert not facade._client.registration_response

    def test_is_registered(self, provider_metadata: ProviderMetadata, client_metadata: ClientMetadata) -> None:
        unregistered = ProviderConfiguration(
            provider_metadata=provider_metadata, client_registration_info=ClientRegistrationInfo()
        )
        registered = ProviderConfiguration(provider_metadata=provider_metadata, client_metadata=client_metadata)
        assert PyoidcFacade(unregistered, self.REDIRECT_URI).is_registered() is False
        assert PyoidcFacade(registered, self.REDIRECT_URI).is_registered() is True

    @responses.activate
    def test_register(
        self, client_registration_info: ClientRegistrationInfo, provider_metadata: ProviderMetadata
    ) -> None:
        redirect_uris = client_registration_info["redirect_uris"]
        post_logout_redirect_uris = client_registration_info["post_logout_redirect_uris"]
        client_registration_response = {
            "client_id": self.CLIENT_ID,
            "client_secret": "secret1",
            "client_name": "Test Client",
            "redirect_uris": redirect_uris,
            "post_logout_redirect_uris": post_logout_redirect_uris,
        }
        unregistered = ProviderConfiguration(
            provider_metadata=provider_metadata, client_registration_info=client_registration_info
        )
        facade = PyoidcFacade(unregistered, self.REDIRECT_URI)

        responses.add(responses.POST, provider_metadata["registration_endpoint"], json=client_registration_response)
        facade.register()
        assert facade.is_registered() is True

    def test_authentication_request(self, provider_metadata: ProviderMetadata, client_metadata: ClientMetadata) -> None:
        extra_user_auth_params = {"param1": "value1", "param2": "value2"}
        config = ProviderConfiguration(
            provider_metadata=provider_metadata,
            client_metadata=client_metadata,
            auth_request_params=extra_user_auth_params,
        )
        facade = PyoidcFacade(config, self.REDIRECT_URI)

        extra_lib_auth_params = {"param3": "value3", "param4": "value4"}
        auth_request = facade.authentication_request(
            state=self.STATE, nonce=self.NONCE, extra_auth_params=extra_lib_auth_params
        )
        expected_auth_params = {
            "scope": "openid",
            "response_type": "code",
            "client_id": client_metadata["client_id"],
            "redirect_uri": self.REDIRECT_URI,
            "state": self.STATE,
            "nonce": self.NONCE,
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
    def test_parse_authentication_response_preserves_id_token_jwt(self, facade: PyoidcFacade) -> None:
        now = int(time.time())
        id_token, id_token_signing_key = signed_id_token(
            {
                "iss": facade._provider_configuration._provider_metadata["issuer"],
                "sub": "test_sub",
                "aud": [self.CLIENT_ID],
                "exp": now + 1,
                "iat": now,
            }
        )
        auth_response = {"state": self.STATE, "id_token": id_token}

        responses.add(
            responses.GET,
            facade._provider_configuration._provider_metadata["jwks_uri"],
            json={"keys": [id_token_signing_key.serialize()]},
        )
        parsed_auth_response = facade.parse_authentication_response(response_params=auth_response)

        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response["state"] == self.STATE
        assert parsed_auth_response["id_token_jwt"] == id_token

    @pytest.mark.parametrize(
        "request_func, expected_token_request",
        [
            (
                lambda facade, auth_code, state: facade.exchange_authorization_code(auth_code, state),
                {"grant_type": "authorization_code", "state": STATE, "redirect_uri": REDIRECT_URI},
            ),
            (
                lambda facade, *args: facade.refresh_token("refresh-token"),
                {"grant_type": "refresh_token", "refresh_token": "refresh-token", "redirect_uri": REDIRECT_URI},
            ),
        ],
    )
    @responses.activate
    def test_token_request(
        self,
        request_func: Callable[[PyoidcFacade, str, str], AccessTokenResponse],
        expected_token_request: Dict[str, str],
        facade: PyoidcFacade,
    ) -> None:
        now = int(time.time())
        id_token_claims = {
            "iss": facade._provider_configuration._provider_metadata["issuer"],
            "sub": "test_user",
            "aud": [self.CLIENT_ID],
            "exp": now + 1,
            "iat": now,
            "nonce": self.NONCE,
        }
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        token_response = AccessTokenResponse(
            access_token="test_access_token",
            refresh_token="refresh-token",
            token_type="Bearer",
            id_token=id_token_jwt,
            expires_in=now + 1,
        )

        grant = Grant(resp=token_response)
        grant.grant_expiration_time = now + grant.exp_in
        facade._client.grant = {self.STATE: grant}

        responses.add(
            responses.POST,
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=token_response.to_dict(),
        )
        responses.add(
            responses.GET,
            facade._provider_configuration._provider_metadata["jwks_uri"],
            json={"keys": [id_token_signing_key.serialize()]},
        )
        token_request_response = request_func(facade, self.AUTH_CODE, self.STATE)

        assert isinstance(token_request_response, AccessTokenResponse)
        expected_token_response = token_response.to_dict()
        expected_token_response["id_token"] = id_token_claims
        expected_token_response["id_token_jwt"] = id_token_jwt
        assert token_request_response.to_dict() == expected_token_response

        token_request = dict(parse_qsl(responses.calls[0].request.body))
        assert token_request == expected_token_request

    @responses.activate
    def test_token_request_handles_error_response(self, facade: PyoidcFacade) -> None:
        token_response = TokenErrorResponse(error="invalid_request", error_description="test error description")
        grant = Grant()
        grant.grant_expiration_time = int(time.time()) + grant.exp_in
        facade._client.grant = {self.STATE: grant}

        responses.add(
            responses.POST,
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=token_response.to_dict(),
            status=400,
        )
        assert facade.exchange_authorization_code(self.AUTH_CODE, self.STATE) == token_response

    def test_token_request_handles_missing_provider_token_endpoint(self, facade: PyoidcFacade) -> None:
        facade._client.token_endpoint = None
        assert facade.exchange_authorization_code(self.AUTH_CODE, self.STATE) is None

    @pytest.mark.parametrize("userinfo_http_method", [responses.GET, responses.POST])
    @responses.activate
    def test_configurable_userinfo_endpoint_method_is_used(
        self, userinfo_http_method: Literal["GET", "POST"], facade: PyoidcFacade
    ) -> None:
        userinfo_response = OpenIDSchema(sub="user1")
        facade._provider_configuration.userinfo_endpoint_method = userinfo_http_method

        responses.add(
            userinfo_http_method,
            facade._provider_configuration._provider_metadata["userinfo_endpoint"],
            json=userinfo_response.to_dict(),
        )
        assert facade.userinfo_request(access_token=self.ACCESS_TOKEN) == userinfo_response

    def test_no_userinfo_request_is_made_if_no_userinfo_http_method_is_configured(self, facade: PyoidcFacade) -> None:
        facade._provider_configuration.userinfo_endpoint_method = None
        assert facade.userinfo_request(access_token=self.ACCESS_TOKEN) is None

    def test_no_userinfo_request_is_made_if_no_userinfo_endpoint_is_configured(self, facade: PyoidcFacade) -> None:
        facade._client.userinfo_endpoint = None
        assert facade.userinfo_request(access_token=self.ACCESS_TOKEN) is None

    def test_no_userinfo_request_is_made_if_no_access_token(self, facade: PyoidcFacade) -> None:
        assert facade.userinfo_request(access_token="") is None

    @responses.activate
    @pytest.mark.parametrize(
        "scope, extra_args", [(None, {}), (["read", "write"], {"audience": [CLIENT_ID, "client2"]})]
    )
    def test_client_credentials_grant(
        self, scope: List[str], extra_args: Dict[str, Union[List[str], str]], facade: PyoidcFacade
    ) -> None:
        client_credentials_grant_response = {
            "access_token": self.ACCESS_TOKEN,
            "expires_in": 60,
            "refresh_expires_in": 0,
            "scope": "read write",
            "token_type": "Bearer",
        }

        responses.add(
            responses.POST,
            facade._provider_configuration._provider_metadata["token_endpoint"],
            json=client_credentials_grant_response,
        )
        assert client_credentials_grant_response == facade.client_credentials_grant(scope=scope, **extra_args).to_dict()

        expected_token_request = {"grant_type": ["client_credentials"], **extra_args}
        if scope:
            expected_token_request.update({"scope": [" ".join(scope)]})

        client_credentials_grant_request = parse_qs(responses.calls[0].request.body)
        assert client_credentials_grant_request == expected_token_request

    @responses.activate
    def test_revoke_token(self, facade: PyoidcFacade) -> None:
        # "PyoidcFacade.revoke_token" not only revokes the token but also removes its cache. So, create an access token
        # cache by making a token introspection request.
        token_introspection_response = {
            "active": True,
            "exp": int(time.time()) + 60,
            "aud": ["admin", self.CLIENT_ID],
            "scope": "read write delete",
            "client_id": self.CLIENT_ID,
        }

        responses.add(
            responses.POST,
            facade._provider_configuration._provider_metadata["introspection_endpoint"],
            json=token_introspection_response,
        )
        facade._token_introspection_request(access_token=self.ACCESS_TOKEN)

        # Validate the length of the cache to verify if access token has been cached.
        assert len(facade._token_introspection_request.cache(facade)) == 1

        request_args = {"token": self.ACCESS_TOKEN, "token_type_hint": "access_token"}
        responses.add(
            responses.POST,
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
