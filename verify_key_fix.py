
import sys
import os

# Add parent directory to path so we can import core modules
sys.path.append(os.path.join(os.getcwd(), 'zypheron-ai'))

try:
    from core.secure_config import validate_api_key
    
    # Test cases
    valid_key = "AIzaSyATzo4YGLuOBQNxkeRzsXDBl0ydCMbFviE" # 39 chars
    
    print(f"Testing key: {valid_key} (len: {len(valid_key)})")
    is_valid, error = validate_api_key("google", valid_key)
    
    if is_valid:
        print("SUCCESS: Key accepted (Fix verified)")
    else:
        print(f"FAILURE: Key rejected: {error}")

except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure run this from the project root")
