from unittest.mock import MagicMock, NonCallableMagicMock

import pytest
from oic.oic import (
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationRequest,
    AuthorizationResponse,
    OpenIDSchema,
    TokenErrorResponse,
)

from starlite_oidc.auth_response_handler import (
    AuthResponseErrorResponseError,
    AuthResponseHandler,
    AuthResponseMismatchingSubjectError,
    AuthResponseUnexpectedStateError,
    InvalidIdTokenError,
)
from starlite_oidc.pyoidc_facade import PyoidcFacade


class TestAuthResponseHandler:
    AUTH_REQUEST = AuthorizationRequest(**{"state": "test-state", "nonce": "test-nonce"})
    AUTH_RESPONSE = AuthorizationResponse(**{"code": "test-auth-code", "state": AUTH_REQUEST["state"]})
    ERROR_RESPONSE = {"error": "test_error", "error_description": "something went wrong"}

    def test_should_detect_state_mismatch(self, client_mock: PyoidcFacade) -> None:
        auth_request = {"state": "other-state", "nonce": self.AUTH_REQUEST["nonce"]}
        with pytest.raises(AuthResponseUnexpectedStateError):
            AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE, auth_request)

    def test_should_detect_nonce_mismatch(
        self, facade: PyoidcFacade, access_token_response: AccessTokenResponse
    ) -> None:
        facade.exchange_authorization_code = MagicMock(return_value=access_token_response)
        auth_request = {"state": self.AUTH_RESPONSE["state"], "nonce": "other-nonce"}
        with pytest.raises(InvalidIdTokenError):
            AuthResponseHandler(facade).process_auth_response(self.AUTH_RESPONSE, auth_request)

    def test_should_handle_auth_error_response(self, client_mock: PyoidcFacade) -> None:
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(
                AuthorizationErrorResponse(**self.ERROR_RESPONSE), self.AUTH_REQUEST
            )
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_handle_token_error_response(self, client_mock: PyoidcFacade) -> None:
        client_mock.exchange_authorization_code.return_value = TokenErrorResponse(**self.ERROR_RESPONSE)
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(
                AuthorizationResponse(**self.AUTH_RESPONSE), self.AUTH_REQUEST
            )
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_detect_mismatching_subject(
        self, client_mock: PyoidcFacade, access_token_response: AccessTokenResponse, userinfo: OpenIDSchema
    ) -> None:
        client_mock.exchange_authorization_code.return_value = access_token_response
        userinfo["sub"] = "other-sub"
        client_mock.userinfo_request.return_value = userinfo
        with pytest.raises(AuthResponseMismatchingSubjectError):
            AuthResponseHandler(client_mock).process_auth_response(
                AuthorizationResponse(**self.AUTH_RESPONSE), self.AUTH_REQUEST
            )

    def test_should_handle_auth_response_with_authorization_code(
        self, client_mock: PyoidcFacade, access_token_response: AccessTokenResponse, userinfo: OpenIDSchema
    ) -> None:
        client_mock.exchange_authorization_code.return_value = access_token_response
        client_mock.userinfo_request.return_value = userinfo
        result = AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE, self.AUTH_REQUEST)
        assert result.access_token == access_token_response["access_token"]
        assert result.expires_in == access_token_response["expires_in"]
        assert result.id_token_claims == access_token_response["id_token"].to_dict()
        assert result.id_token_jwt == access_token_response["id_token_jwt"]
        assert result.userinfo_claims == userinfo.to_dict()
        assert result.refresh_token == access_token_response["refresh_token"]

    def test_should_handle_auth_response_without_authorization_code(
        self, client_mock: NonCallableMagicMock, access_token_response: AccessTokenResponse, userinfo: OpenIDSchema
    ) -> None:
        auth_response = AuthorizationResponse(**access_token_response)
        auth_response["state"] = self.AUTH_REQUEST["state"]
        client_mock.userinfo_request.return_value = userinfo
        result = AuthResponseHandler(client_mock).process_auth_response(auth_response, self.AUTH_REQUEST)
        assert not client_mock.exchange_authorization_code.called
        assert result.access_token == access_token_response["access_token"]
        assert result.expires_in == access_token_response["expires_in"]
        assert result.id_token_jwt == access_token_response["id_token_jwt"]
        assert result.id_token_claims == access_token_response["id_token"].to_dict()
        assert result.userinfo_claims == userinfo.to_dict()
        assert result.refresh_token is None

    def test_should_handle_token_response_without_id_token(
        self, client_mock: PyoidcFacade, access_token_response: AccessTokenResponse
    ) -> None:
        access_token_response.pop("id_token")
        access_token_response.pop("id_token_jwt")
        client_mock.exchange_authorization_code.return_value = access_token_response
        result = AuthResponseHandler(client_mock).process_auth_response(
            AuthorizationResponse(**self.AUTH_RESPONSE), self.AUTH_REQUEST
        )
        assert result.access_token == access_token_response["access_token"]
        assert result.id_token_claims is None

    def test_should_handle_no_token_response(
        self, client_mock: PyoidcFacade, access_token_response: AccessTokenResponse
    ) -> None:
        client_mock.exchange_authorization_code.return_value = None
        client_mock.userinfo_request.return_value = None
        hybrid_auth_response = self.AUTH_RESPONSE.copy()
        hybrid_auth_response.update(access_token_response)
        result = AuthResponseHandler(client_mock).process_auth_response(
            AuthorizationResponse(**hybrid_auth_response), self.AUTH_REQUEST
        )
        assert result.access_token == access_token_response["access_token"]
        assert result.id_token_claims == access_token_response["id_token"].to_dict()
        assert result.id_token_jwt == access_token_response["id_token_jwt"]

    @pytest.mark.parametrize(
        "response_type, expected",
        [
            ("code", False),  # Authorization Code Flow
            ("id_token", True),  # Implicit Flow
            ("id_token token", True),  # Implicit Flow
            ("code id_token", True),  # Hybrid Flow
            ("code token", True),  # Hybrid Flow
            ("code id_token token", True),  # Hybrid Flow
        ],
    )
    def test_expect_fragment_encoded_response_by_response_type(self, response_type: str, expected: bool) -> None:
        assert AuthResponseHandler.expect_fragment_encoded_response({"response_type": response_type}) is expected

    @pytest.mark.parametrize(
        "response_type, response_mode, expected",
        [
            ("code", "fragment", True),
            ("id_token", "query", False),
            ("code token", "form_post", False),
        ],
    )
    def test_expect_fragment_encoded_response_with_non_default_response_mode(
        self, response_type: str, response_mode: str, expected: bool
    ):
        auth_req = {"response_type": response_type, "response_mode": response_mode}
        assert AuthResponseHandler.expect_fragment_encoded_response(auth_req) is expected
