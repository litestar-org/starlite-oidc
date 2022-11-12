from unittest.mock import MagicMock, NonCallableMagicMock, create_autospec

import pytest
from oic.oic import (
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationRequest,
    AuthorizationResponse,
    OpenIDSchema,
    TokenErrorResponse,
)
from starlite import NotAuthorizedException

from starlite_oidc.facade import OIDCFacade
from starlite_oidc.plugin import expect_fragment_encoded_response, process_auth_response

from .constants import AUTH_CODE, NONCE, STATE


class TestAuthResponseHandler:
    AUTH_REQUEST = AuthorizationRequest(**{"state": STATE, "nonce": NONCE})
    AUTH_RESPONSE = AuthorizationResponse(**{"code": AUTH_CODE, "state": AUTH_REQUEST["state"]})
    ERROR_RESPONSE = {"error": "test_error", "error_description": "something went wrong"}

    @pytest.fixture()
    def facade(self) -> OIDCFacade:
        """

        Returns:

        """
        return create_autospec(OIDCFacade, spec_set=True, instance=True)

    async def test_should_detect_state_mismatch(self, facade: OIDCFacade) -> None:
        auth_request = {"state": "other-state", "nonce": self.AUTH_REQUEST["nonce"]}
        with pytest.raises(NotAuthorizedException):
            await process_auth_response(facade=facade, auth_response=self.AUTH_RESPONSE, auth_request=auth_request)

    async def test_should_detect_nonce_mismatch(
        self, facade: OIDCFacade, access_token_response: AccessTokenResponse
    ) -> None:
        facade.config.request_access_token = MagicMock(return_value=access_token_response)
        auth_request = {"state": self.AUTH_RESPONSE["state"], "nonce": "other-nonce"}
        with pytest.raises(NotAuthorizedException):
            await process_auth_response(facade=facade, auth_response=self.AUTH_RESPONSE, auth_request=auth_request)

    async def test_should_handle_auth_error_response(self, facade: OIDCFacade) -> None:
        with pytest.raises(NotAuthorizedException):
            await process_auth_response(
                facade=facade,
                auth_response=AuthorizationErrorResponse(**self.ERROR_RESPONSE),
                auth_request=self.AUTH_REQUEST.to_dict(),
            )

    async def test_should_handle_token_error_response(self, facade: OIDCFacade) -> None:
        facade.request_access_token.return_value = TokenErrorResponse(**self.ERROR_RESPONSE)
        with pytest.raises(NotAuthorizedException):
            await process_auth_response(
                facade=facade,
                auth_response=AuthorizationResponse(**self.AUTH_RESPONSE),
                auth_request=self.AUTH_REQUEST.to_dict(),
            )

    async def test_should_detect_mismatching_subject(
        self, facade: OIDCFacade, access_token_response: AccessTokenResponse, user_info: OpenIDSchema
    ) -> None:
        facade.request_access_token.return_value = access_token_response
        user_info["sub"] = "other-sub"
        facade.request_user_info.return_value = user_info
        with pytest.raises(NotAuthorizedException):
            await process_auth_response(
                facade=facade,
                auth_response=AuthorizationResponse(**self.AUTH_RESPONSE),
                auth_request=self.AUTH_REQUEST.to_dict(),
            )

    async def test_should_handle_auth_response_with_authorization_code(
        self, facade: OIDCFacade, access_token_response: AccessTokenResponse, user_info: OpenIDSchema
    ) -> None:
        facade.request_access_token.return_value = access_token_response
        facade.request_user_info.return_value = user_info
        result = await process_auth_response(
            facade=facade, auth_response=self.AUTH_RESPONSE, auth_request=self.AUTH_REQUEST.to_dict()
        )
        assert result.access_token == access_token_response["access_token"]
        assert result.expires_in == access_token_response["expires_in"]
        assert result.id_token_claims == access_token_response["id_token"].to_dict()
        assert result.id_token_jwt == access_token_response["id_token_jwt"]
        assert result.user_info_claims == user_info.to_dict()
        assert result.refresh_token == access_token_response["refresh_token"]

    async def test_should_handle_auth_response_without_authorization_code(
        self, facade: NonCallableMagicMock, access_token_response: AccessTokenResponse, user_info: OpenIDSchema
    ) -> None:
        auth_response = AuthorizationResponse(**access_token_response)
        auth_response["state"] = self.AUTH_REQUEST["state"]
        facade.user_info_request.return_value = user_info
        result = await process_auth_response(
            facade=facade, auth_response=auth_response, auth_request=self.AUTH_REQUEST.to_dict()
        )
        assert facade.exchange_authorization_code.called is False
        assert result.access_token == access_token_response["access_token"]
        assert result.expires_in == access_token_response["expires_in"]
        assert result.id_token_jwt == access_token_response["id_token_jwt"]
        assert result.id_token_claims == access_token_response["id_token"].to_dict()
        assert result.user_info_claims == user_info.to_dict()
        assert result.refresh_token is None

    async def test_should_handle_token_response_without_id_token(
        self, facade: OIDCFacade, access_token_response: AccessTokenResponse
    ) -> None:
        access_token_response.pop("id_token")
        access_token_response.pop("id_token_jwt")
        facade.request_access_token.return_value = access_token_response
        result = await process_auth_response(
            facade=facade,
            auth_response=AuthorizationResponse(**self.AUTH_RESPONSE),
            auth_request=self.AUTH_REQUEST.to_dict(),
        )
        assert result.access_token == access_token_response["access_token"]
        assert result.id_token_claims is None

    async def test_should_handle_no_token_response(
        self, facade: OIDCFacade, access_token_response: AccessTokenResponse
    ) -> None:
        facade.request_access_token.return_value = None
        facade.request_user_info.return_value = None
        hybrid_auth_response = self.AUTH_RESPONSE.copy()
        hybrid_auth_response.update(access_token_response)
        result = await process_auth_response(
            facade=facade,
            auth_response=AuthorizationResponse(**hybrid_auth_response),
            auth_request=self.AUTH_REQUEST.to_dict(),
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
        assert expect_fragment_encoded_response({"response_type": response_type}) is expected

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
    ) -> None:
        auth_req = {"response_type": response_type, "response_mode": response_mode}
        assert expect_fragment_encoded_response(auth_req) is expected
