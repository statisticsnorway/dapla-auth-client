"""Dapla Auth Client."""

# Expose the AuthClient class directly for easy access.
from .auth import AuthClient, MissingConfigurationException

__all__ = ["AuthClient", "MissingConfigurationException"]
