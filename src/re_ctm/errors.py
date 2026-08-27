from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReCTMError(Exception):
    """Structured error used by every Re-CTM plane."""

    code: str
    message: str
    category: str = "runtime"
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def to_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "category": self.category,
            "retryable": self.retryable,
            "details": self.details,
        }


def invalid_argument(message: str, **details: Any) -> ReCTMError:
    return ReCTMError(
        "INVALID_ARGUMENT",
        message,
        category="validation",
        details=details,
    )


def permission_denied(message: str, **details: Any) -> ReCTMError:
    return ReCTMError(
        "PERMISSION_DENIED",
        message,
        category="permission",
        details=details,
    )
