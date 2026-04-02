# Zypheron API Testing Guide

Quick local reference for testing the current API surface with `curl`.

## Start the Server

```bash
./run.sh
```

Or:

```bash
uvicorn app.main:app --reload
```

Base URL: `http://localhost:8000`

## Authentication Flow

### Register

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123"}'
```

### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123"}'
```

### Current User

```bash
export TOKEN="<access-token>"
curl http://localhost:8000/auth/me -H "Authorization: Bearer $TOKEN"
```

## Device Flow

### Register a Device

```bash
curl -X POST http://localhost:8000/devices/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_uuid":"test-uuid-123","device_name":"My Device","platform":"linux"}'
```

### List Devices

```bash
curl http://localhost:8000/devices -H "Authorization: Bearer $TOKEN"
```

## Usage Endpoints

### Usage Summary

```bash
curl http://localhost:8000/tokens/usage -H "Authorization: Bearer $TOKEN"
```

### Usage History

```bash
curl http://localhost:8000/tokens/history -H "Authorization: Bearer $TOKEN"
```

## Health and Docs

```bash
curl http://localhost:8000/health
```

- `http://localhost:8000/docs`
- `http://localhost:8000/redoc`

## Notes

- prefer SQLite for fast local validation
- treat Redis and PostgreSQL as optional unless the specific test requires them
- keep endpoint smoke tests simple and reproducible
