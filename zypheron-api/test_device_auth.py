#!/usr/bin/env python3
"""Test script for device code authentication endpoints.

This script demonstrates the complete device code authentication flow:
1. CLI requests device code
2. User authorizes on web app
3. CLI polls for token
4. CLI receives access token

Run this script with the API server running on http://localhost:8000
"""

import asyncio
import time

import httpx


API_BASE_URL = "http://localhost:8000"


async def test_device_code_flow():
    """Test the complete device code authentication flow."""
    async with httpx.AsyncClient() as client:
        print("=" * 80)
        print("DEVICE CODE AUTHENTICATION FLOW TEST")
        print("=" * 80)
        print()

        # Step 1: Request device code (CLI side)
        print("Step 1: Requesting device code...")
        device_info = {
            "os": "Linux",
            "os_version": "6.14.0-37-generic",
            "hostname": "test-machine",
            "cli_version": "1.0.0",
        }

        response = await client.post(
            f"{API_BASE_URL}/auth/device/code",
            json={"device_info": device_info},
        )

        if response.status_code != 201:
            print(f"Error: {response.status_code}")
            print(response.json())
            return

        device_code_data = response.json()
        print(f"Device Code: {device_code_data['device_code']}")
        print(f"User Code: {device_code_data['user_code']}")
        print(f"Verification URL: {device_code_data['verification_url']}")
        print(f"Expires In: {device_code_data['expires_in']} seconds")
        print(f"Polling Interval: {device_code_data['interval']} seconds")
        print()

        device_code = device_code_data["device_code"]
        user_code = device_code_data["user_code"]

        # Display instructions to user
        print("-" * 80)
        print("USER INSTRUCTIONS:")
        print(f"1. Open your browser and go to: {device_code_data['verification_url']}")
        print(f"2. Log in if not already logged in")
        print(f"3. Enter the code: {user_code}")
        print("4. Authorize the device")
        print()
        print("TESTING INSTRUCTIONS:")
        print("To test the authorization endpoint manually, run:")
        print(f"  curl -X POST {API_BASE_URL}/auth/device/authorize \\")
        print(f"       -H 'Content-Type: application/json' \\")
        print(f"       -H 'Authorization: Bearer YOUR_JWT_TOKEN' \\")
        print(f"       -d '{{\"user_code\": \"{user_code}\"}}'")
        print("-" * 80)
        print()

        # Step 2: Poll for token (CLI side)
        print("Step 2: Polling for authorization...")
        print("(In a real scenario, the CLI would poll every 5 seconds)")
        print()

        max_attempts = 60  # Poll for up to 5 minutes
        interval = 5  # seconds

        for attempt in range(1, max_attempts + 1):
            print(f"Polling attempt {attempt}/{max_attempts}...", end=" ")

            response = await client.post(
                f"{API_BASE_URL}/auth/device/token",
                json={
                    "device_code": device_code,
                    "device_info": device_info,
                },
            )

            if response.status_code != 200:
                print(f"Error: {response.status_code}")
                print(response.json())
                break

            token_data = response.json()
            status = token_data["status"]
            print(f"Status: {status}")

            if status == "authorized":
                print()
                print("=" * 80)
                print("SUCCESS! Device authorized!")
                print("=" * 80)
                print(f"Access Token: {token_data['access_token'][:50]}...")
                print(f"User ID: {token_data['user_id']}")
                print(f"Email: {token_data['email']}")
                print(f"Tier: {token_data['tier']}")
                print(f"Token Type: {token_data['token_type']}")
                print()
                print("The CLI can now use this access token for authenticated requests.")
                print("=" * 80)
                return token_data

            elif status == "pending":
                # Continue polling
                if attempt < max_attempts:
                    await asyncio.sleep(interval)
            elif status == "expired":
                print()
                print("Device code has expired. Please request a new code.")
                break
            elif status == "denied":
                print()
                print("Device authorization was denied by the user.")
                break

        print()
        print("Polling timeout or authorization not completed.")


async def test_authorize_endpoint_simulation():
    """Simulate the web app authorizing a device code.

    NOTE: This requires a valid JWT token from a logged-in user.
    In a real scenario, the user would:
    1. Log in on the web app
    2. Navigate to /device?code=XXXX-XXXX
    3. The web app would call this endpoint with their JWT token
    """
    async with httpx.AsyncClient() as client:
        print()
        print("=" * 80)
        print("AUTHORIZATION ENDPOINT TEST (Web App Side)")
        print("=" * 80)
        print()

        # First, let's try to register/login a test user
        print("Step 1: Creating test user...")
        test_email = f"test_{int(time.time())}@example.com"
        test_password = "TestPass123"

        response = await client.post(
            f"{API_BASE_URL}/auth/register",
            json={
                "email": test_email,
                "password": test_password,
            },
        )

        if response.status_code == 201:
            user_data = response.json()
            jwt_token = user_data["access_token"]
            print(f"Created user: {test_email}")
            print(f"JWT Token: {jwt_token[:50]}...")
            print()

            # Now create a device code
            print("Step 2: Creating device code...")
            device_info = {
                "os": "Linux",
                "os_version": "6.14.0-37-generic",
                "hostname": "test-machine",
                "cli_version": "1.0.0",
            }

            response = await client.post(
                f"{API_BASE_URL}/auth/device/code",
                json={"device_info": device_info},
            )

            if response.status_code == 201:
                device_code_data = response.json()
                user_code = device_code_data["user_code"]
                print(f"User Code: {user_code}")
                print()

                # Authorize the device code
                print("Step 3: Authorizing device code (as logged-in user)...")
                response = await client.post(
                    f"{API_BASE_URL}/auth/device/authorize",
                    json={"user_code": user_code},
                    headers={"Authorization": f"Bearer {jwt_token}"},
                )

                if response.status_code == 200:
                    auth_data = response.json()
                    print(f"Success: {auth_data['success']}")
                    print(f"Message: {auth_data['message']}")
                    print(f"Device Info: {auth_data['device_info']}")
                    print()

                    # Now poll for token
                    print("Step 4: Polling for token (should succeed immediately)...")
                    response = await client.post(
                        f"{API_BASE_URL}/auth/device/token",
                        json={
                            "device_code": device_code_data["device_code"],
                            "device_info": device_info,
                        },
                    )

                    if response.status_code == 200:
                        token_data = response.json()
                        print(f"Status: {token_data['status']}")
                        if token_data["status"] == "authorized":
                            print(f"Access Token: {token_data['access_token'][:50]}...")
                            print(f"User ID: {token_data['user_id']}")
                            print(f"Email: {token_data['email']}")
                            print(f"Tier: {token_data['tier']}")
                            print()
                            print("=" * 80)
                            print("COMPLETE FLOW TEST SUCCESSFUL!")
                            print("=" * 80)
                    else:
                        print(f"Error: {response.status_code}")
                        print(response.json())
                else:
                    print(f"Error authorizing: {response.status_code}")
                    print(response.json())
            else:
                print(f"Error creating device code: {response.status_code}")
                print(response.json())
        else:
            print(f"Error creating user: {response.status_code}")
            print(response.json())


async def main():
    """Run all tests."""
    # Test 1: Manual flow (requires manual authorization)
    # Uncomment to test manual flow:
    # await test_device_code_flow()

    # Test 2: Automated flow (simulates web app authorization)
    await test_authorize_endpoint_simulation()


if __name__ == "__main__":
    asyncio.run(main())
