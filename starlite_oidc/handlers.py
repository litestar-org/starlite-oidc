from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qsl, urlparse

from oic import rndstr
from oic.oic import AuthorizationRequest
from starlite import HTTPException, HttpMethod, InternalServerException, route
from starlite.response import RedirectResponse
from starlite.status_codes import HTTP_301_MOVED_PERMANENTLY, HTTP_403_FORBIDDEN

e
from starlite_oidc.plugin import process_auth_response
from starlite_oidc.session import UserSession

if TYPE_CHECKING:
    from starlite import HTTPRouteHandler, Request

    from starlite_oidc.facade import OIDCFacade


def create_authentication_handler(redirect_path: str, facade: "OIDCFacade") -> "HTTPRouteHandler":
    """This is a callback route handler registered at Starlite instance. See
    `self.init_app` for its registration parameters. This route handler
    exchanges OIDC tokens sent by the IdP. Then it sets them up in the session.

    Args:
        redirect_path:
        facade:

    Returns:
    """

    async def handle_authentication_response(request: "Request") -> RedirectResponse:
        """

        Args:
            request: A Request instance.

        Returns:
            RedirectResponse: Redirects back to the path from where OIDC was triggered.

        Raises:
            HTTPException: If the IdP sends error response.
        """
        session = UserSession(**request.session)

        auth_request = request.session.pop("auth_request", None)
        if not auth_request:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                extra={"error": "unsolicited_response", "error_description": "No authentication request stored."},
            )

        try:
            if request.method == "POST":
                auth_response = facade.parse_authorization_response(dict(await request.form()))
            elif request.session.pop("fragment_encoded_response", False):
                auth_response = facade.parse_authorization_response(dict(parse_qsl(urlparse(str(request.url)).query)))
            else:
                auth_response = facade.parse_authorization_response(request.query_params)

            result = await process_auth_response(
                facade=facade,
                auth_response=auth_response,
                auth_request=AuthorizationRequest().from_json(auth_request).to_dict(),
            )

            session.update(
                access_token=result.access_token,
                expires_in=result.expires_in,
                id_token=result.id_token_claims,
                id_token_jwt=result.id_token_jwt,
                user_info=result.user_info_claims,
                refresh_token=result.refresh_token,
            )

            destination = request.session.pop("destination")
            return RedirectResponse(url=destination, status_code=HTTP_301_MOVED_PERMANENTLY)
        except KeyError as e:
            raise InternalServerException(f"provider is not initialized") from e

    return route(path=redirect_path, http_method=[HttpMethod.GET, HttpMethod.POST])(handle_authentication_response)


def create_logout_handler(logout_path: str, facade: "OIDCFacade") -> "HTTPRouteHandler":
    async def handle_logout(request: "Request") -> Optional[RedirectResponse]:
        state = request.query_params.get("state")
        if state and state != request.session.get("end_session_state"):
            request.clear_session()
            return

        scope_session = request.scope.get("session")

        if not scope_session or not scope_session.get("current_provider_name"):
            return

        user_session = UserSession(**request.scope["session"])

        state = rndstr()
        post_logout_redirect_uri = str(request.url)
        scope_session["end_session_state"] = state

        if facade.config.provider_metadata.end_session_endpoint:
            end_session_request_url = await facade.request_session_end(
                id_token_jwt=user_session.id_token_jwt,
                post_logout_redirect_uri=post_logout_redirect_uri,
                state=state,
                interactive=True,
            )
            if end_session_request_url:
                return RedirectResponse(
                    url=end_session_request_url,
                )
        return None

    return route(logout_path, http_method=[HttpMethod.GET, HttpMethod.DELETE])(handle_logout)
