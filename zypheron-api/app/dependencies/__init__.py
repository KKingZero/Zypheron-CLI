"""Dependencies package for FastAPI dependency injection.

Contains reusable dependencies for:
- Device binding and validation
- Authentication checks
- Rate limiting
- Permission checks
"""

from app.dependencies.device import (
    OptionalDevice,
    ValidatedDevice,
    get_device_from_header,
    get_optional_device,
)

__all__ = [
    "ValidatedDevice",
    "OptionalDevice",
    "get_device_from_header",
    "get_optional_device",
]
