import json
import logging
import os
from collections.abc import Sequence
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional, Sequence as Seq

import google.auth
import requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2.credentials import Credentials

from dapla_auth_client.const import DaplaEnvironment, DaplaRegion, DaplaService

logger = logging.getLogger(__name__)

# Refresh window was modified in: https://github.com/googleapis/google-auth-library-python/commit/c6af1d692b43833baca978948376739547cf685a
# The change was directed towards high latency environments, and should not apply to us.
# Since we can't force a refresh, the threshold is lowered to keep us from waiting ~4 minutes for a new token.
# A permanent fix would be to supply credentials with a refresh endpoint
# that always returns a token that is valid for more than 3m 45s.
google.auth._helpers.REFRESH_THRESHOLD = timedelta(seconds=20)


class AuthClient:
    """Client for retrieving authentication information."""

    @staticmethod
    def _get_current_dapla_metadata() -> (
        tuple[Optional[DaplaEnvironment], Optional[DaplaService], Optional[DaplaRegion]]
    ):
        try:
            env = DaplaEnvironment(os.getenv("DAPLA_ENVIRONMENT"))
        except ValueError:
            env = None

        try:
            service = DaplaService(os.getenv("DAPLA_SERVICE"))
        except ValueError:
            service = None

        try:
            region = DaplaRegion(os.getenv("DAPLA_REGION"))
        except ValueError:
            region = None

        return env, service, region

    @staticmethod
    def get_dapla_region() -> Optional[DaplaRegion]:
        """Checks if the current Dapla Region is Dapla Lab."""
        _, _, region = AuthClient._get_current_dapla_metadata()
        return region

    @staticmethod
    def _refresh_handler() -> tuple[str, datetime]:
        # We manually override the refresh_handler method with our custom logic for fetching tokens.
        # Previously, we directly overrode the `refresh` method. However, this
        # approach led to deadlock issues in gcsfs/credentials.py's maybe_refresh method.
        return AuthClient.fetch_google_token()

    @staticmethod
    def _fetch_kubernetes_token() -> str:
        """
        Fetches the Kubernetes service account token from the default file path.
        This function reads the token from the file located at
        "/var/run/secrets/kubernetes.io/serviceaccount/token". It ensures that
        the token is not empty or invalid and raises appropriate exceptions
        if the file is missing or the token is invalid.

        Returns:
            str: The Kubernetes service account token.

        Raises:
            FileNotFoundError: If the token file is not found at the specified path.
            ValueError: If the token file is empty or contains invalid data.
        """
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        try:
            with open(token_path, "r") as token_file:
                token = token_file.read()
                if not token:
                    raise ValueError("Token file is empty or invalid.")
                return token
        except FileNotFoundError:
            raise FileNotFoundError(f"Kubernetes token file not found at {token_path}")

    @staticmethod
    def _exchange_kubernetes_token_for_keycloak_token(
        audience: Optional[list[str]] = None, scope: Optional[list[str]] = None
    ) -> tuple[str, datetime]:
        """Fetches a Keycloak token for the current user in Dapla Lab.

        This method exchanges the Kubernetes service account token for a Keycloak token
        using the LABID_TOKEN_EXCHANGE_URL environment variable. It requires the
        Dapla Lab region to be set and the LABID_TOKEN_EXCHANGE_URL to be configured.

        Args:
            audience: Optional list of audiences to include in the token exchange request.
            scope: Optional list of scopes to include in the token exchange request.

        Raises:
            RuntimeError: If the region is not DAPLA_LAB, or if the HTTP request fails.
            MissingConfigurationException: If LABID_TOKEN_EXCHANGE_URL is not set.

        Returns:
            A tuple of (keycloak-token, expiry).
        """

        _, _, region = AuthClient._get_current_dapla_metadata()
        if region != DaplaRegion.DAPLA_LAB:
            raise RuntimeError("Dapla Lab region not detected.")

        labid_url = os.getenv("LABID_TOKEN_EXCHANGE_URL")
        if labid_url is None:
            raise MissingConfigurationException("LABID_TOKEN_EXCHANGE_URL")

        kubernetes_token = AuthClient._fetch_kubernetes_token()
        try:
            response = requests.post(
                url=labid_url,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {kubernetes_token}",
                },
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token_type": "urn:ietf:params:oauth:grant-type:id_token",
                    "subject_token": kubernetes_token,
                    **({"scope": ",".join(scope)} if scope else {}),
                    **({"audience": ",".join(audience)} if audience else {}),
                },
            )
            response.raise_for_status()
            auth_data = response.json()
            expiry = datetime.utcnow() + timedelta(seconds=auth_data["expires_in"])
            access_token = auth_data["access_token"]

            return access_token, expiry

        except requests.RequestException as e:
            logger.error(f"Failed to fetch Keycloak token: {e}")
            raise RuntimeError("Failed to fetch Keycloak token for Dapla Lab.") from e

    @staticmethod
    def fetch_google_token_from_oidc_exchange(
        request: GoogleAuthRequest,
    ) -> tuple[str, datetime]:
        """Fetches the Google token by exchanging an OIDC token.

        Args:
            request: The GoogleAuthRequest object.
            _scopes: The scopes to request.

        Raises:
            RuntimeError: If the request to the OIDC token exchange endpoint fails.

        Returns:
            A tuple of (google-token, expiry).
        """
        if os.getenv("OIDC_TOKEN_EXCHANGE_URL") is None:
            raise RuntimeError(
                "env variable 'OIDC_TOKEN_EXCHANGE_URL' was not found when "
                "attempting token exchange with OIDC endpoint"
            )

        response = request.__call__(
            url=os.environ["OIDC_TOKEN_EXCHANGE_URL"],
            method="POST",
            body={
                "subject_token": os.environ["OIDC_TOKEN"],
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_issuer": "google",
                "client_id": "onyxia-api",
            },
        )

        if response.status == 200:
            auth_data = json.loads(response.data)
            expiry = datetime.utcnow() + timedelta(seconds=auth_data["expires_in"])
            return auth_data["access_token"], expiry
        else:
            error = json.loads(response.data)
            print("Error: ", error.get("error_description", "Unknown error"))
            raise RuntimeError("OIDC token exchange failed.")

    @staticmethod
    def fetch_google_token(
        request: Optional[GoogleAuthRequest] = None,
        scopes: Optional[Seq[str]] = None,
    ) -> tuple[str, datetime]:
        """Fetches the Google token for the current user.

        Scopes in the argument is ignored, but are kept for compatibility
        with the Credentials refresh handler method signature.

        Args:
            request: The GoogleAuthRequest object.
            scopes: The scopes to request.

        Raises:
            RuntimeError: If the token exchange fails.

        Returns:
            A tuple of (google-token, expiry).
        """
        try:
            if request is None:
                request = GoogleAuthRequest()

            google_token, expiry = AuthClient.fetch_google_token_from_oidc_exchange(
                request
            )
        except Exception as err:
            raise RuntimeError(str(err))

        return google_token, expiry

    @staticmethod
    def fetch_google_credentials(force_token_exchange: bool = False) -> Credentials:
        """Fetches the Google credentials for the current user.

        Args:
            force_token_exchange: Forces authentication by token exchange.

        Raises:
            RuntimeError: If fails to fetch credentials.

        Returns:
            The Google "Credentials" object.
        """
        env, service, region = AuthClient._get_current_dapla_metadata()
        force_token_exchange = (
            os.getenv("DAPLA_TOOLBELT_FORCE_TOKEN_EXCHANGE") == "1"
            or force_token_exchange
        )

        try:
            match (env, service, region):
                case (_, _, _) if force_token_exchange is True:
                    logger.debug("Auth - Forced token exchange")
                    token, expiry = AuthClient.fetch_google_token()
                    credentials = Credentials(
                        token=token,
                        expiry=expiry,
                        token_uri="https://oauth2.googleapis.com/token",
                        refresh_handler=AuthClient._refresh_handler,
                    )

                case (_, DaplaService.CLOUD_RUN, _):
                    logger.debug("Auth - Cloud Run detected, using ADC")
                    credentials, _ = google.auth.default()

                case (
                    _,
                    DaplaService.JUPYTERLAB,
                    DaplaRegion.ON_PREM,
                ):
                    logger.debug("Auth - JupyterLab detected, using token exchange")
                    token, expiry = AuthClient.fetch_google_token()
                    credentials = Credentials(
                        token=token,
                        expiry=expiry,
                        token_uri="https://oauth2.googleapis.com/token",
                        refresh_handler=AuthClient._refresh_handler,
                    )

                case (_, _, DaplaRegion.DAPLA_LAB):
                    logger.debug("Auth - Dapla Lab detected, attempting to use ADC")
                    adc_env = os.getenv("DAPLA_GROUP_CONTEXT")
                    if adc_env is None:
                        raise RuntimeError(
                            "Dapla Group selection feature is not enabled. "
                            "This is necessary in order to access buckets in Dapla Lab. "
                            "The feature needs to be enabled *before* starting the service, "
                            "and can be done in the 'Buckets' configuration tab"
                        )
                    logger.debug(
                        "Auth - 'DAPLA_GROUP_CONTEXT' env variable is set, "
                        f"using ADC as group {adc_env}"
                    )
                    credentials, _ = google.auth.default()

                case (_, _, _):
                    logger.debug("Auth - Default authentication used (ADC)")
                    credentials, _ = google.auth.default()

        except Exception as err:
            raise RuntimeError(str(err))

        return credentials

    @staticmethod
    def fetch_personal_token() -> str:
        """If Dapla Region is Dapla Lab, retrieve the Keycloak token."""

        _, _, region = AuthClient._get_current_dapla_metadata()
        if region != DaplaRegion.DAPLA_LAB:
            raise RuntimeError("Dapla Lab region not detected.")

        logger.debug("Auth - Dapla Lab detected, returning Keycloak token")
        keycloak_token, _ = AuthClient._exchange_kubernetes_token_for_keycloak_token()
        return keycloak_token

    @staticmethod
    @lru_cache(maxsize=1)
    def fetch_email_from_credentials() -> Optional[str]:
        """Retrieves an e-mail based on current Google Credentials. Potentially makes a Google API call."""
        if os.getenv("DAPLA_REGION") == DaplaRegion.DAPLA_LAB.value:
            return os.getenv("DAPLA_USER")

        credentials = AuthClient.fetch_google_credentials()
        response = requests.get(
            url=f"https://oauth2.googleapis.com/tokeninfo?access_token={credentials.token}"
        )

        return response.json().get("email") if response.status_code == 200 else None


class MissingConfigurationException(Exception):
    """Exception raised when a required environment variable or configuration is missing."""

    def __init__(self, variable_name: str) -> None:
        """Initializes a new instance of the MissingConfigurationException class.

        Args:
            variable_name (str): The name of the missing environment variable or configuration.
        """
        self.variable_name = variable_name
        self.message = f"Missing required environment variable: {variable_name}"
        super().__init__(self.message)

    def __str__(self) -> str:
        """Returns a string representation of the exception."""
        return f"Configuration error: {self.message}"
