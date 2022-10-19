import base64
from typing import Callable, Dict, List, Union
from unittest.mock import NonCallableMagicMock, create_autospec

import pytest
import responses
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from starlite_oidc.provider_configuration import (
    ClientMetadata,
    ClientRegistrationInfo,
    OIDCData,
    ProviderConfiguration,
    ProviderMetadata,
)

from .constants import PROVIDER_BASE_URL


class TestProviderConfiguration:
    @pytest.fixture()
    def pyoidc_client_mock(self) -> Client:
        return create_autospec(Client, spec_set=True, instance=True)

    @staticmethod
    def assert_registration_response(
        provider_config: ProviderConfiguration, client_registration_response: Dict[str, Union[List[str], str]]
    ) -> None:
        redirect_uris = provider_config._client_metadata["redirect_uris"]
        post_logout_redirect_uris = provider_config._client_metadata.get("post_logout_redirect_uris")

        assert provider_config._client_metadata["client_id"] == client_registration_response["client_id"]
        assert provider_config._client_metadata["client_secret"] == client_registration_response["client_secret"]
        assert provider_config._client_metadata["client_name"] == client_registration_response["client_name"]
        assert (
            provider_config._client_metadata["registration_client_uri"]
            == client_registration_response["registration_client_uri"]
        )
        assert (
            provider_config._client_metadata["registration_access_token"]
            == client_registration_response["registration_access_token"]
        )
        assert redirect_uris == client_registration_response["redirect_uris"]
        assert post_logout_redirect_uris == client_registration_response.get("post_logout_redirect_uris")

    def test_missing_provider_metadata_raises_exception(self, client_registration_info: ClientRegistrationInfo) -> None:
        with pytest.raises(ValueError) as exc_info:
            ProviderConfiguration(client_registration_info=client_registration_info)

        exc_message = str(exc_info.value)
        assert "issuer" in exc_message
        assert "provider_metadata" in exc_message

    def test_missing_client_metadata_raises_exception(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            ProviderConfiguration(issuer=PROVIDER_BASE_URL)

        exc_message = str(exc_info.value)
        assert "client_registration_info" in exc_message
        assert "client_metadata" in exc_message

    @responses.activate
    def test_should_fetch_provider_metadata_if_not_given(
        self,
        provider_metadata: ProviderMetadata,
        provider_configuration: Callable[..., ProviderConfiguration],
    ) -> None:
        provider_config = provider_configuration(dynamic_provider=True)
        provider_metadata_response = provider_metadata.to_dict()

        responses.get(PROVIDER_BASE_URL + "/.well-known/openid-configuration", json=provider_metadata_response)
        provider_config.ensure_provider_metadata(Client())
        assert set(provider_metadata_response.keys()).issubset(provider_config._provider_metadata)

    def test_should_not_fetch_provider_metadata_if_given(
        self,
        provider_configuration: Callable[..., ProviderConfiguration],
        pyoidc_client_mock: NonCallableMagicMock,
    ) -> None:
        provider_config = provider_configuration()
        provider_config.ensure_provider_metadata(pyoidc_client_mock)
        assert pyoidc_client_mock.provider_config.called is False

    def test_should_not_register_client_if_client_metadata_is_given(
        self, provider_configuration: Callable[..., ProviderConfiguration], pyoidc_client_mock: NonCallableMagicMock
    ) -> None:
        provider_config = provider_configuration()
        provider_config.register_client(pyoidc_client_mock)
        assert pyoidc_client_mock.register.called is False

    def test_should_raise_exception_for_non_registered_client_when_missing_registration_endpoint(
        self,
        provider_configuration: Callable[..., ProviderConfiguration],
        pyoidc_client_mock: NonCallableMagicMock,
    ) -> None:
        provider_config = provider_configuration(dynamic_client=True)
        provider_config._provider_metadata["registration_endpoint"] = None
        with pytest.raises(ValueError):
            provider_config.register_client(pyoidc_client_mock)

    @pytest.mark.parametrize("post_logout_redirect_uris", [True, False])
    @responses.activate
    def test_should_register_dynamic_client_if_client_registration_info_is_given(
        self,
        post_logout_redirect_uris: bool,
        provider_configuration: Callable[..., ProviderConfiguration],
        client_registration_response: Dict[str, Union[List[str], str]],
    ) -> None:
        provider_config = provider_configuration(dynamic_client=True)
        if post_logout_redirect_uris is False:
            provider_config._client_registration_info["post_logout_redirect_uris"] = []
            client_registration_response.pop("post_logout_redirect_uris")

        responses.post(
            provider_config._provider_metadata["registration_endpoint"],
            json=client_registration_response,
        )
        provider_config.register_client(Client())
        self.assert_registration_response(provider_config, client_registration_response)

    @responses.activate
    def test_register_client_should_register_dynamic_client_with_initial_access_token(
        self,
        provider_configuration: Callable[..., ProviderConfiguration],
        client_registration_response: Dict[str, Union[List[str], str]],
    ) -> None:
        registration_token = "initial_access_token"
        provider_config = provider_configuration(dynamic_client=True)
        provider_config._client_registration_info["registration_token"] = registration_token

        responses.post(
            provider_config._provider_metadata["registration_endpoint"],
            json=client_registration_response,
        )
        provider_config.register_client(Client(CLIENT_AUTHN_METHOD))

        self.assert_registration_response(provider_config, client_registration_response)
        assert (
            responses.calls[0].request.headers["Authorization"]
            == f"Bearer {base64.b64encode(registration_token.encode()).decode()}"
        )


class TestOIDCData:
    def test_client_secret_should_not_be_in_string_representation(self, client_metadata: ClientMetadata) -> None:
        client_metadata = OIDCData(**client_metadata)
        assert client_metadata["client_secret"] not in str(client_metadata)
        assert client_metadata["client_secret"] in repr(client_metadata)
        client_metadata.pop("client_secret")
        assert "client_secret" not in str(client_metadata)

    def test_copy_should_overwrite_existing_value(self) -> None:
        data = OIDCData(abc="xyz")
        copy_data = data.copy(qwe="rty", abc="123")
        assert copy_data == {"abc": "123", "qwe": "rty"}

    def test_del_and_len(self) -> None:
        data = OIDCData(abc="xyz", qwe="rty")
        assert len(data) == 2
        del data["qwe"]
        assert data.to_dict() == {"abc": "xyz"}
