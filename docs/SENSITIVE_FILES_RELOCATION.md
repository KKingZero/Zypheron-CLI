# Sensitive Files Relocation

Date: 2026-03-14

The following files were removed from this repository because they contained secret-bearing material or embedded API-key-like values:

- `zypheron-ai/.env`
- `verify_key_fix.py`

They were moved to:

- `/home/zero/Downloads/Zypheron project/docs/zypheron-sensitive/`

Notes:

- This document intentionally excludes secret values.
- Root `.gitignore` already excludes `*.env`, which is why `zypheron-ai/.env` was not tracked.
- If any moved credentials were real and used outside local testing, rotate them.
