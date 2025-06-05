import json
import requests
from datetime import datetime
from datetime import timedelta
from unittest import mock
from unittest.mock import Mock, mock_open

import pytest
import responses
from google.oauth2.credentials import Credentials

import dapla_auth_client
from dapla_auth_client import AuthClient
from dapla_auth_client import MissingConfigurationException

auth_endpoint_url = "https://mock-auth.no/user"


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {
        "DAPLA_SERVICE": "JUPYTERLAB",
        "DAPLA_REGION": "DAPLA_LAB",
    },
    clear=True,
)
@mock.patch("dapla_auth_client.auth.AuthClient._read_kubernetes_token")
@mock.patch(
    "dapla_auth_client.auth.AuthClient._exchange_kubernetes_token_for_keycloak_token"
)
@responses.activate
def test_fetch_personal_token_for_dapla_lab(
    mock_exchange_kubernetes_token: Mock,
    mock_read_kubernetes_token: Mock,
) -> None:
    mock_exchange_kubernetes_token.return_value = (
        "dummy_token",
        datetime.now() + timedelta(hours=1),
    )
    mock_read_kubernetes_token.return_value = "dummy_kubernetes_token"

    client = AuthClient()
    token = client.fetch_personal_token()

    assert token == "dummy_token"


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {
        "DAPLA_SERVICE": "JUPYTERLAB",
        "DAPLA_REGION": "DAPLA_LAB",
    },
    clear=True,
)
@mock.patch("dapla_auth_client.auth.AuthClient._read_kubernetes_token")
@responses.activate
def test_fetch_personal_token_error_on_dapla_lab(
    mock_read_kubernetes_token: Mock,
) -> None:

    mock_read_kubernetes_token.return_value = "dummy_kubernetes_token"

    with pytest.raises(MissingConfigurationException) as exception:
        AuthClient().fetch_personal_token()
    assert (
        str(exception.value)
        == "Configuration error: Missing required environment variable: LABID_TOKEN_EXCHANGE_URL"
    )


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"OIDC_TOKEN_EXCHANGE_URL": auth_endpoint_url, "OIDC_TOKEN": "dummy_token"},
    clear=True,
)
@responses.activate
def test_fetch_google_token_exchange_error() -> None:
    mock_response = Mock()

    mock_data = {"error_description": "Invalid token"}
    mock_json = json.dumps(mock_data)
    mock_response.data = mock_json
    mock_response.status = 404

    mock_google_request = Mock()
    mock_google_request.return_value = mock_response

    with mock.patch.object(
        dapla_auth_client.auth.GoogleAuthRequest,  # type: ignore [attr-defined]
        "__call__",
        mock_response,
    ):
        with pytest.raises(RuntimeError):
            client = AuthClient()
            client.fetch_google_token_from_oidc_exchange(mock_google_request)


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"OIDC_TOKEN_EXCHANGE_URL": auth_endpoint_url, "OIDC_TOKEN": "fake_access_token"},
    clear=True,
)
@responses.activate
def test_fetch_google_token_from_exchange_dapla_lab() -> None:
    mock_response = Mock()
    mock_response.data = json.dumps(
        {
            "access_token": "google_token",
            "expires_in": round((datetime.now() + timedelta(hours=1)).timestamp()),
        }
    )
    mock_response.status = 200
    mock_google_request = Mock()
    mock_google_request.return_value = mock_response
    with mock.patch.object(
        dapla_auth_client.auth.GoogleAuthRequest,  # type: ignore [attr-defined]
        "__call__",
        mock_response,
    ):
        client = AuthClient()
        token, _expiry = client.fetch_google_token_from_oidc_exchange(
            mock_google_request
        )

        assert token == "google_token"


@mock.patch("dapla_auth_client.auth.AuthClient.fetch_google_token_from_oidc_exchange")
@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"OIDC_TOKEN": "fake-token"},
    clear=True,
)
@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"OIDC_TOKEN_EXCHANGE_URL": "fake-endpoint"},
    clear=True,
)
@responses.activate
def test_fetch_google_credentials_from_oidc_exchange(
    fetch_google_token_from_oidc_exchange_mock: Mock,
) -> None:
    fetch_google_token_from_oidc_exchange_mock.return_value = (
        "google_token",
        datetime.now() + timedelta(hours=1),
    )

    client = AuthClient()
    credentials = client.fetch_google_credentials(force_token_exchange=True)
    credentials.refresh(None)

    assert credentials.token == "google_token"
    assert not credentials.expired


@mock.patch("dapla_auth_client.auth.AuthClient.fetch_google_token_from_oidc_exchange")
@mock.patch.dict(
    "dapla_auth_client.auth.os.environ", {"OIDC_TOKEN": "fake-token"}, clear=True
)
@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"OIDC_TOKEN_EXCHANGE_URL": "fake-endpoint"},
    clear=True,
)
@responses.activate
def test_fetch_google_credentials_expired(
    fetch_google_token_from_oidc_exchange_mock: Mock,
) -> None:
    fetch_google_token_from_oidc_exchange_mock.return_value = (
        "google_token",
        datetime.now() - timedelta(hours=1),
    )

    client = AuthClient()
    credentials = client.fetch_google_credentials(force_token_exchange=True)

    fetch_google_token_from_oidc_exchange_mock.return_value = (
        "google_token",
        datetime.now() + timedelta(hours=1),
    )

    credentials.refresh(None)
    assert not credentials.expired


def test_credentials_object_refresh_exists() -> None:
    # We test whether the "refresh" method exists,
    # since it might be removed in a future release and we are overriding the method.
    credentials = Credentials("fake-token")
    assert hasattr(credentials, "refresh")


@mock.patch("dapla_auth_client.auth.AuthClient.fetch_google_token")
def test_fetch_credentials_force_token_exchange(mock_fetch_google_token: Mock) -> None:
    mock_fetch_google_token.return_value = (Mock(), Mock())
    AuthClient.fetch_google_credentials(force_token_exchange=True)
    mock_fetch_google_token.assert_called_once()


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ", {"DAPLA_SERVICE": "CLOUD_RUN"}, clear=True
)
@mock.patch("dapla_auth_client.auth.google.auth.default")
def test_fetch_credentials_cloud_run(mock_google_auth_default: Mock) -> None:
    mock_google_auth_default.return_value = (Mock(), Mock())
    AuthClient.fetch_google_credentials()
    mock_google_auth_default.assert_called_once()


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"DAPLA_REGION": "DAPLA_LAB", "DAPLA_GROUP_CONTEXT": "dummy-group-developers"},
    clear=True,
)
@mock.patch("dapla_auth_client.auth.google.auth.default")
def test_fetch_credentials_dapla_lab(mock_google_auth_default: Mock) -> None:
    mock_google_auth_default.return_value = (Mock(), Mock())
    AuthClient.fetch_google_credentials()
    mock_google_auth_default.assert_called_once()


@mock.patch("dapla_auth_client.auth.google.auth.default")
def test_fetch_credentials_default(mock_google_auth_default: Mock) -> None:
    mock_google_auth_default.return_value = (Mock(), Mock())
    AuthClient.fetch_google_credentials()
    mock_google_auth_default.assert_called_once()


def test_read_kubernetes_token_success(tmp_path, monkeypatch):
    fake_content = "my-kube-token"

    m = mock_open(read_data=fake_content)
    with mock.patch("builtins.open", m):
        token = AuthClient._read_kubernetes_token()
        assert token == fake_content


def test_read_kubernetes_token_file_not_found(monkeypatch):
    def raise_filenotfound(path, mode="r", *args, **kwargs):
        raise FileNotFoundError

    with mock.patch("builtins.open", side_effect=raise_filenotfound):
        with pytest.raises(FileNotFoundError) as excinfo:
            AuthClient._read_kubernetes_token()
        expected_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        assert (
            str(excinfo.value) == f"Kubernetes token file not found at {expected_path}"
        )


def test_read_kubernetes_token_empty(monkeypatch):
    m = mock_open(read_data="")
    with mock.patch("builtins.open", m):
        with pytest.raises(ValueError) as excinfo:
            AuthClient._read_kubernetes_token()
        assert str(excinfo.value) == "Token file is empty or invalid."


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {
        "DAPLA_REGION": "DAPLA_LAB",
        "LABID_TOKEN_EXCHANGE_URL": "https://example.com/exchange",
    },
    clear=True,
)
@mock.patch.object(
    AuthClient, "_read_kubernetes_token", return_value="dummy_kube_token"
)
@mock.patch("requests.post")
def test_exchange_kubernetes_token_success(mock_requests_post, mock_read_kube):

    fake_response = Mock()
    fake_response.raise_for_status.return_value = None

    fake_expires_in = 120
    fake_response.json.return_value = {
        "access_token": "keycloak-abc123",
        "expires_in": fake_expires_in,
    }
    mock_requests_post.return_value = fake_response

    token, expiry = AuthClient._exchange_kubernetes_token_for_keycloak_token(
        audience=["aud1", "aud2"], scope=["scope1"]
    )

    assert token == "keycloak-abc123"
    assert isinstance(expiry, datetime)

    now = datetime.utcnow()
    delta = expiry - now
    assert (
        timedelta(seconds=fake_expires_in - 2)
        < delta
        < timedelta(seconds=fake_expires_in + 2)
    )

    mock_requests_post.assert_called_once()
    _, called_kwargs = mock_requests_post.call_args
    assert called_kwargs["url"] == "https://example.com/exchange"
    assert "Authorization" in called_kwargs["headers"]
    assert called_kwargs["headers"]["Authorization"].startswith(
        "Bearer dummy_kube_token"
    )
    assert "audience" in called_kwargs["data"]
    assert called_kwargs["data"]["audience"] == "aud1,aud2"
    assert called_kwargs["data"]["scope"] == "scope1"


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {"DAPLA_REGION": "DAPLA_LAB"},
    clear=True,
)
def test_exchange_kubernetes_token_missing_url():
    with pytest.raises(MissingConfigurationException) as excinfo:
        AuthClient._exchange_kubernetes_token_for_keycloak_token()
    assert (
        str(excinfo.value)
        == "Configuration error: Missing required environment variable: LABID_TOKEN_EXCHANGE_URL"
    )


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {
        "DAPLA_REGION": "DAPLA_PROD",
        "LABID_TOKEN_EXCHANGE_URL": "https://example.com/exchange",
    },
    clear=True,
)
def test_exchange_kubernetes_token_wrong_region():
    with pytest.raises(RuntimeError) as excinfo:
        AuthClient._exchange_kubernetes_token_for_keycloak_token()
    assert str(excinfo.value) == "Dapla Lab region not detected."


@mock.patch.dict(
    "dapla_auth_client.auth.os.environ",
    {
        "DAPLA_REGION": "DAPLA_LAB",
        "LABID_TOKEN_EXCHANGE_URL": "https://example.com/exchange",
    },
    clear=True,
)
@mock.patch.object(
    AuthClient, "_read_kubernetes_token", return_value="dummy_kube_token"
)
@mock.patch("requests.post", side_effect=requests.RequestException("network-failure"))
def test_exchange_kubernetes_token_request_failure(mock_requests_post, mock_read_kube):
    with pytest.raises(RuntimeError) as excinfo:
        AuthClient._exchange_kubernetes_token_for_keycloak_token()
    assert "Failed to fetch Keycloak token for Dapla Lab." in str(excinfo.value)
