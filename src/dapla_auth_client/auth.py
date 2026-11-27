import logging
import os
from datetime import UTC
from datetime import datetime
from datetime import timedelta

import requests

from dapla_auth_client.const import DaplaEnvironment
from dapla_auth_client.const import DaplaRegion
from dapla_auth_client.const import DaplaService

logger = logging.getLogger(__name__)


class AuthClient:
    """Client for retrieving authentication information."""

    @staticmethod
    def get_current_dapla_metadata() -> (
        tuple[DaplaEnvironment | None, DaplaService | None, DaplaRegion | None]
    ):
        """Read the DAPLA related environment variables and return them as a tuple."""
        if env_var := os.getenv("DAPLA_ENVIRONMENT"):
            env = DaplaEnvironment(env_var)
        else:
            env = None

        if service_var := os.getenv("DAPLA_SERVICE"):
            service = DaplaService(service_var)
        else:
            service = None

        if region_var := os.getenv("DAPLA_REGION"):
            region = DaplaRegion(region_var)
        else:
            region = None

        return env, service, region

    @staticmethod
    def get_dapla_region() -> DaplaRegion | None:
        """Checks if the current Dapla Region is Dapla Lab."""
        _, _, region = AuthClient.get_current_dapla_metadata()
        return region

    @staticmethod
    def _read_kubernetes_token() -> str:
        """Fetches the Kubernetes service account token from the default file path.

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
            with open(token_path) as token_file:
                token = token_file.read()
                if not token:
                    raise ValueError("Token file is empty or invalid.")
                return token
        except FileNotFoundError:
            raise FileNotFoundError(f"Kubernetes token file not found at {token_path}")

    @staticmethod
    def _exchange_kubernetes_token_for_keycloak_token(
        audiences: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[str, datetime]:
        """Fetches a Keycloak token for the current user in Dapla Lab.

        This method exchanges the Kubernetes service account token for a Keycloak token
        using the LABID_TOKEN_EXCHANGE_URL environment variable. It requires the
        Dapla Lab region to be set and the LABID_TOKEN_EXCHANGE_URL to be configured.

        Args:
            audiences: Optional list of audiences to include in the token exchange request.
            scopes: Optional list of scopes to include in the token exchange request.

        Raises:
            RuntimeError: If the region is not DAPLA_LAB, or if the HTTP request fails.
            MissingConfigurationException: If LABID_TOKEN_EXCHANGE_URL is not set.

        Returns:
            A tuple of (keycloak-token, expiry).
        """
        _, _, region = AuthClient.get_current_dapla_metadata()
        if region != DaplaRegion.DAPLA_LAB:
            raise RuntimeError("Dapla Lab region not detected.")

        labid_url = os.getenv("LABID_TOKEN_EXCHANGE_URL")
        if labid_url is None:
            raise MissingConfigurationException("LABID_TOKEN_EXCHANGE_URL")

        kubernetes_token = AuthClient._read_kubernetes_token()
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
                    **({"scope": ",".join(scopes)} if scopes else {}),
                    **({"audience": ",".join(audiences)} if audiences else {}),
                },
            )
            response.raise_for_status()
            auth_data = response.json()
            expiry = datetime.now(UTC) + timedelta(seconds=auth_data["expires_in"])
            access_token = auth_data["access_token"]

            return access_token, expiry

        except requests.RequestException as e:
            logger.error(f"Failed to fetch Keycloak token: {e}")
            raise RuntimeError("Failed to fetch Keycloak token for Dapla Lab.") from e

    @staticmethod
    def fetch_personal_token(
        scopes: list[str] | None = None,
        audiences: list[str] | None = None,
    ) -> str:
        """If Dapla Region is Dapla Lab, retrieve the Keycloak token.

        This method checks if the current Dapla Region is Dapla Lab and retrieves
        the Keycloak token for the current user. If the region is not Dapla Lab,
        it raises a RuntimeError.

        Args:
            scopes: Optional list of scopes to include in the token request (ex. current_group, all_groups). Defaults to current_group.
            audiences: Optional list of audiences to include in the token exchange request.

        Raises:
            RuntimeError: If the region is not DAPLA_LAB.

        Returns:
            str: The Keycloak token for the current user.
        """
        _, _, region = AuthClient.get_current_dapla_metadata()
        if region != DaplaRegion.DAPLA_LAB:
            raise RuntimeError("Dapla Lab region not detected.")

        logger.debug("Auth - Dapla Lab detected, returning Keycloak token")

        if scopes is None:
            scopes = ["current_group"]

        keycloak_token, _ = AuthClient._exchange_kubernetes_token_for_keycloak_token(
            scopes=scopes, audiences=audiences
        )
        return keycloak_token


class MissingConfigurationException(Exception):
    """Exception raised when a required environment variable or configuration is missing."""

    def __init__(self, variable_name: str) -> None:
        """Initializes a new instance of the MissingConfigurationException class.

        Args:
            variable_name: The name of the missing environment variable or configuration.
        """
        self.variable_name = variable_name
        self.message = f"Missing required environment variable: {variable_name}"
        super().__init__(self.message)

    def __str__(self) -> str:
        """Returns a string representation of the exception."""
        return f"Configuration error: {self.message}"
