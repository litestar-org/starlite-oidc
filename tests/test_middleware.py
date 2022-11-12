from unittest import mock

import pytest
import responses
from oic.oic.message import AccessTokenResponse, OpenIDSchema
from starlite import Starlite, get
from starlite.middleware import DefineMiddleware
from starlite.middleware.session import SessionCookieConfig
from starlite.status_codes import HTTP_301_MOVED_PERMANENTLY
from starlite.testing import TestClient
from starlite.testing.request_factory import _default_route_handler

from starlite_oidc import OIDCPlugin
from starlite_oidc.config import ProviderMetaData
from starlite_oidc.middleware import OIDCMiddleware

from .constants import (
    AUTH_CODE,
    CLIENT_BASE_URL,
    CLIENT_ID,
    LOGOUT_STATUS,
    NONCE,
    POST_LOGOUT_REDIRECT_PATH,
    POST_LOGOUT_VIEW,
    PROVIDER_NAME,
    REDIRECT_URI,
    STATE,
)
from .util import signing_key


class TestOIDCMiddleware:
    EXCLUSION_PATH = "/exclude"
    EXCLUSION_STATUS = "entered exclusion zone"

    @pytest.fixture()
    def init_app(self, auth: OIDCPlugin, session_config: SessionCookieConfig) -> Starlite:
        """

        Args:
            auth:
            session_config:

        Returns:

        """

        @get(path=self.EXCLUSION_PATH, opt={"exclude_from_auth": True})
        def excluded_handler() -> str:
            """

            Returns:

            """
            return self.EXCLUSION_STATUS

        @get(path=POST_LOGOUT_REDIRECT_PATH, name=POST_LOGOUT_VIEW, before_request=auth.handle_logout)
        def logout() -> str:
            """

            Returns:

            """
            return LOGOUT_STATUS

        app = Starlite(
            route_handlers=[_default_route_handler, excluded_handler, logout],
            middleware=[
                session_config.middleware,
                DefineMiddleware(OIDCMiddleware, auth=auth, provider_name=PROVIDER_NAME, enforce="access_control"),
            ],
        )
        # auth.init_app(app=app, redirect_uri=REDIRECT_URI, logout_views=POST_LOGOUT_VIEW)

        return app

    @pytest.fixture()
    def request_client(self, init_app: Starlite, session_config: SessionCookieConfig) -> TestClient:
        """

        Args:
            init_app:
            session_config:
        """
        with TestClient(
            app=init_app, base_url=CLIENT_BASE_URL, session_config=session_config, raise_server_exceptions=False
        ) as client:
            yield client

    @pytest.mark.parametrize("headers", [{}, True])
    @responses.activate
    def test_oidc(
        self,
        headers: bool,
        access_token_response: AccessTokenResponse,
        signed_access_token: AccessTokenResponse,
        provider_metadata: ProviderMetaData,
        user_info: OpenIDSchema,
        request_client: TestClient,
    ) -> None:
        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt
        if headers is True:
            headers = {
                "authorization": f"""Bearer {signed_access_token.to_jwt(key=[signing_key],
                                                                               algorithm=signing_key.alg)}"""
            }

        params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": REDIRECT_URI,
            "state": STATE,
            "nonce": NONCE,
        }
        responses.add(
            responses.Response(
                responses.GET,
                url=provider_metadata.authorization_endpoint,
                match=[responses.matchers.query_param_matcher(params)],
                status=HTTP_301_MOVED_PERMANENTLY,
                headers={"Location": f"{REDIRECT_URI}?state={STATE}&code={AUTH_CODE}"},
            )
        )
        responses.post(provider_metadata.token_endpoint, json=token_response)
        responses.get(provider_metadata.jwks_uri, json={"keys": [signing_key.serialize()]})
        responses.get(provider_metadata.user_info_endpoint, json=user_info.to_dict())

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            response = request_client.get(url="/", headers=headers, follow_redirects=False)
        assert response

    def test_should_skip_excluded_routes(self, request_client: TestClient) -> None:
        assert request_client.get(url=POST_LOGOUT_REDIRECT_PATH).text == LOGOUT_STATUS
        assert request_client.get(url=self.EXCLUSION_PATH).text == self.EXCLUSION_STATUS
