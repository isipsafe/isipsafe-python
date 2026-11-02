from __future__ import annotations

from typing import Any, Optional


class IsIPsafeError(Exception):
    """Base class for every error raised by this library."""


class APIError(IsIPsafeError):
    """The API answered with an error status."""

    def __init__(self, message: str, status: int, body: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.body = body

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status}, message={self.message!r})"


class AuthenticationError(APIError):
    """401: the API key is missing or wrong."""


class ValidationError(APIError):
    """422: the request was rejected, for example an invalid or allowlisted IP."""


class RateLimitError(APIError):
    """429: too many requests. ``retry_after`` is in seconds when the API sent it."""

    def __init__(
        self,
        message: str,
        status: int,
        body: Optional[Any] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, status, body)
        self.retry_after = retry_after


class NetworkError(IsIPsafeError):
    """The API could not be reached or did not answer in time."""
