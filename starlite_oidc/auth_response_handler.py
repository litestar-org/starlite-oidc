import collections
import logging
from typing import Mapping, Union

from oic.exception import PyoidcError
from oic.oic.message import AuthorizationErrorResponse, AuthorizationResponse

from .pyoidc_facade import PyoidcFacade

logger = logging.getLogger(__name__)

AuthenticationResult = collections.namedtuple(
    "AuthenticationResult",
    ["access_token", "expires_in", "id_token_claims", "id_token_jwt", "user_info_claims", "refresh_token"],
)


class AuthResponseProcessError(ValueError):
    pass


class AuthResponseUnexpectedStateError(AuthResponseProcessError):
    pass


class InvalidIdTokenError(AuthResponseProcessError):
    pass


class AuthResponseMismatchingSubjectError(AuthResponseProcessError):
    pass


class AuthResponseErrorResponseError(AuthResponseProcessError):
    def __init__(self, error_response: Mapping[str, str]) -> None:
        """
        Args:
            error_response: OAuth error response containing 'error' and 'error_description'
        """
        self.error_response = error_response


class AuthResponseHandler:
    def __init__(self, client: PyoidcFacade):
        """
        Args:
            client: Client proxy to make requests to the provider
        """
        self._client = client

    def process_auth_response(
        self,
        auth_response: Union[AuthorizationResponse, AuthorizationErrorResponse],
        auth_request: Mapping[str, str],
    ) -> AuthenticationResult:
        """
        Args:
            auth_response: parsed OIDC auth response
            auth_request: original OIDC auth request
        Returns:
            AuthenticationResult: All relevant data associated with the authenticated user
        """
        if "error" in auth_response:
            raise AuthResponseErrorResponseError(auth_response.to_dict())

        if auth_response["state"] != auth_request["state"]:
            raise AuthResponseUnexpectedStateError()

        # implicit/hybrid flow may return tokens in the auth response
        access_token = auth_response.get("access_token")
        expires_in = auth_response.get("expires_in")
        id_token_claims = auth_response["id_token"].to_dict() if "id_token" in auth_response else None
        id_token_jwt = auth_response.get("id_token_jwt")
        refresh_token = None  # but never refresh token

        if "code" in auth_response:
            token_resp = self._client.exchange_authorization_code(auth_response["code"], auth_response["state"])
            if token_resp:
                if "error" in token_resp:
                    raise AuthResponseErrorResponseError(token_resp.to_dict())

                access_token = token_resp["access_token"]
                expires_in = token_resp.get("expires_in")
                refresh_token = token_resp.get("refresh_token")

                if "id_token" in token_resp:
                    id_token = token_resp["id_token"]
                    logger.debug("received id token: %s", id_token.to_json())

                    try:
                        self._client.verify_id_token(id_token, auth_request)
                    except PyoidcError as e:
                        raise InvalidIdTokenError(str(e)) from e

                    id_token_claims = id_token.to_dict()
                    id_token_jwt = token_resp.get("id_token_jwt")

        # do user_info request
        user_info = self._client.user_info_request(access_token)
        user_info_claims = None
        if user_info:
            user_info_claims = user_info.to_dict()

        if id_token_claims and user_info_claims and user_info_claims["sub"] != id_token_claims["sub"]:
            raise AuthResponseMismatchingSubjectError("The 'sub' of user_info does not match 'sub' of ID Token.")

        return AuthenticationResult(
            access_token, expires_in, id_token_claims, id_token_jwt, user_info_claims, refresh_token
        )

    @classmethod
    def expect_fragment_encoded_response(cls, auth_request: Mapping[str, str]):
        if "response_mode" in auth_request:
            return auth_request["response_mode"] == "fragment"

        response_type = set(auth_request["response_type"].split(" "))
        is_implicit_flow = response_type == {"id_token"} or response_type == {"id_token", "token"}
        is_hybrid_flow = (
            response_type == {"code", "id_token"}
            or response_type == {"code", "token"}
            or response_type == {"code", "id_token", "token"}
        )

        return is_implicit_flow or is_hybrid_flow
