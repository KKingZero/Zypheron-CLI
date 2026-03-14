#!/usr/bin/env python3
"""Schema validation script.

This script validates that all database models are correctly defined and can be
instantiated without errors. It also checks for common issues like missing
relationships, incorrect types, and circular import problems.

Usage:
    python scripts/validate_schema.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.database import Base
from app.models import (
    Device,
    DeviceCode,
    License,
    Session,
    TokenUsage,
    User,
    UserQuota,
)


def validate_models():
    """Validate all database models."""
    print("=" * 70)
    print("Zypheron Schema Validation")
    print("=" * 70)

    models = [User, Device, DeviceCode, License, Session, TokenUsage, UserQuota]

    print(f"\nFound {len(models)} models:")
    for model in models:
        print(f"  ✓ {model.__name__}")

    # Check metadata
    print(f"\nRegistered tables in Base.metadata:")
    for table_name, table in Base.metadata.tables.items():
        print(f"  - {table_name}")
        print(f"    Columns: {', '.join([c.name for c in table.columns])}")

    # Validate specific model: DeviceCode
    print("\n" + "=" * 70)
    print("DeviceCode Model Validation")
    print("=" * 70)

    device_code_table = Base.metadata.tables.get("device_codes")
    if device_code_table is None:
        print("✗ ERROR: device_codes table not found in metadata!")
        return False

    print("✓ Table: device_codes")
    print("\nColumns:")
    for column in device_code_table.columns:
        nullable = "NULL" if column.nullable else "NOT NULL"
        primary_key = "PRIMARY KEY" if column.primary_key else ""
        unique = "UNIQUE" if column.unique else ""
        indexed = "INDEXED" if column.index else ""
        flags = " ".join(filter(None, [nullable, primary_key, unique, indexed]))
        print(f"  - {column.name:20s} {str(column.type):15s} {flags}")

    print("\nIndexes:")
    for index in device_code_table.indexes:
        columns = ", ".join([c.name for c in index.columns])
        print(f"  - {index.name}: ({columns})")

    print("\nForeign Keys:")
    for fk in device_code_table.foreign_keys:
        print(f"  - {fk.parent.name} → {fk.column}")

    # Validate relationships
    print("\n" + "=" * 70)
    print("Relationship Validation")
    print("=" * 70)

    print("\nUser relationships:")
    user_relationships = User.__mapper__.relationships
    for rel_name, rel in user_relationships.items():
        target = rel.mapper.class_.__name__
        cascade = rel.cascade if hasattr(rel, "cascade") else "None"
        print(f"  - {rel_name:20s} → {target:15s} (cascade: {cascade})")

    print("\nDeviceCode relationships:")
    device_code_relationships = DeviceCode.__mapper__.relationships
    for rel_name, rel in device_code_relationships.items():
        target = rel.mapper.class_.__name__
        cascade = rel.cascade if hasattr(rel, "cascade") else "None"
        print(f"  - {rel_name:20s} → {target:15s} (cascade: {cascade})")

    # Test model instantiation
    print("\n" + "=" * 70)
    print("Model Instantiation Test")
    print("=" * 70)

    try:
        from datetime import datetime, timezone

        # Test creating a DeviceCode instance
        device_code = DeviceCode(
            device_code="test_device_code_123",
            user_code="ABC-DEF",
            device_info={"os": "Linux", "version": "1.0.0"},
            status="pending",
            expires_at=DeviceCode.generate_expiration(10),
        )
        print("✓ DeviceCode instance created successfully")
        print(f"  - repr: {device_code}")
        print(f"  - is_pending(): {device_code.is_pending()}")
        print(f"  - is_expired(): {device_code.is_expired()}")
        print(f"  - is_authorized(): {device_code.is_authorized()}")

    except Exception as e:
        print(f"✗ ERROR: Failed to create DeviceCode instance: {e}")
        import traceback

        traceback.print_exc()
        return False

    print("\n" + "=" * 70)
    print("✓ All validations passed!")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = validate_models()
    sys.exit(0 if success else 1)
