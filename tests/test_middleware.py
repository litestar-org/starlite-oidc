from typing import Dict, List, Union
from unittest import mock

import pytest
import responses
from oic.oic.message import AccessTokenResponse, OpenIDSchema
from starlette.status import HTTP_301_MOVED_PERMANENTLY
from starlite import Starlite, get
from starlite.middleware import DefineMiddleware
from starlite.middleware.session import SessionCookieConfig
from starlite.testing.request_factory import _default_route_handler
from starlite.testing.test_client import TestClient

from starlite_oidc import OIDCAuthentication
from starlite_oidc.middleware import OIDCMiddleware
from starlite_oidc.provider_configuration import ProviderMetadata

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
from .custom_types import IdTokenStore


class TestOIDCMiddleware:
    EXCLUSION_PATH = "/exclude"
    EXCLUSION_STATUS = "entered exclusion zone"

    @pytest.fixture()
    def init_app(self, auth: OIDCAuthentication, session_config: SessionCookieConfig) -> Starlite:
        @get(path=self.EXCLUSION_PATH, opt={"exclude_from_auth": True})
        def excluded_handler() -> str:
            return self.EXCLUSION_STATUS

        @get(path=POST_LOGOUT_REDIRECT_PATH, name=POST_LOGOUT_VIEW, before_request=auth.oidc_logout)
        def logout() -> str:
            return LOGOUT_STATUS

        app = Starlite(
            route_handlers=[_default_route_handler, excluded_handler, logout],
            middleware=[
                session_config.middleware,
                DefineMiddleware(OIDCMiddleware, auth=auth, provider_name=PROVIDER_NAME, enforce="access_control"),
            ],
        )
        auth.init_app(app=app, redirect_uri=REDIRECT_URI, logout_views=POST_LOGOUT_VIEW)

        return app

    @pytest.fixture()
    def request_client(self, init_app: Starlite, session_config: SessionCookieConfig) -> TestClient:
        with TestClient(app=init_app, base_url=CLIENT_BASE_URL, session_config=session_config) as client:
            yield client

    @pytest.mark.parametrize("headers", [None, {"authorization": "Bearer test-access-token"}])
    @responses.activate
    def test_oidc(
        self,
        headers,
        access_token_response: AccessTokenResponse,
        provider_metadata: ProviderMetadata,
        id_token_store: IdTokenStore,
        userinfo: OpenIDSchema,
        introspection_result: Dict[str, Union[bool, List[str]]],
        request_client: TestClient,
    ) -> None:
        id_token_jwt = access_token_response.pop("id_token_jwt")
        token_response = access_token_response.to_dict()
        token_response["id_token"] = id_token_jwt

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
                url=provider_metadata["authorization_endpoint"],
                match=[responses.matchers.query_param_matcher(params)],
                status=HTTP_301_MOVED_PERMANENTLY,
                headers={"Location": f"{REDIRECT_URI}?state={STATE}&code={AUTH_CODE}"},
            )
        )
        responses.post(provider_metadata["token_endpoint"], json=token_response)
        responses.get(provider_metadata["jwks_uri"], json={"keys": [id_token_store.id_token_signing_key.serialize()]})
        responses.get(provider_metadata["userinfo_endpoint"], json=userinfo.to_dict())
        responses.post(provider_metadata["introspection_endpoint"], json=introspection_result)

        with mock.patch("starlite_oidc.oidc.rndstr", side_effect=[STATE, NONCE]):
            response = request_client.get(url="/", headers=headers, follow_redirects=True)
        assert response

    def test_should_skip_excluded_routes(self, request_client: TestClient) -> None:
        assert request_client.get(url=POST_LOGOUT_REDIRECT_PATH).json() == LOGOUT_STATUS
        assert request_client.get(url=self.EXCLUSION_PATH).json() == self.EXCLUSION_STATUS
