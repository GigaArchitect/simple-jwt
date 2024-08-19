# simple_jwt

`simple_jwt` is a Python project that implements the HMAC256 algorithm and provides utilities to generate JWT (JSON Web Token) and JWS (JSON Web Signature) tokens in accordance with the RFC 7519 and RFC 7515 standards.

## Features

- **HMAC256 Implementation**: Custom implementation of HMAC256 for signing JWT and JWS tokens.
- **JWT Generation**: Easily create JSON Web Tokens with customizable payloads and headers.
- **JWS Support**: Generate JSON Web Signatures using the HMAC256 algorithm.
- **RFC Compliance**: The generated tokens follow the JSON Web Token (JWT) and JSON Web Signature (JWS) standards as outlined by the IETF.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/simple_jwt.git
    cd simple_jwt
    ```

2. Ensure you have Python 3.x installed. If you don't have it, download and install it from [python.org](https://www.python.org/downloads/).

3. Install any required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

    > **Note**: If there are no external dependencies, you can skip this step.

## Usage

### Generating a JWT

To generate a JWT using `simple_jwt`, follow these steps:

1. Set up your environment variable for the secret key used in HMAC256:
    ```bash
    export HS256="your_secret_key"
    ```

2. Use the `generate_jwt` function to create a token:
    ```python
    from simple_jwt import generate_jwt

    token = generate_jwt("username123", True)
    print(f"Generated JWT: {token}")
    ```

### Example Code

Here's an example of how to generate a JWT in your application:

```python
import os
import base64
import json
from hashlib import sha256

def number_to_repeated_bytes(number, byte_length, byteorder='big', signed=False):
    num_bytes = number.to_bytes(
        (number.bit_length() + 7) // 8 or 1, byteorder=byteorder, signed=signed)
    
    if len(num_bytes) < byte_length:
        repetitions = (byte_length + len(num_bytes) - 1) // len(num_bytes)
        num_bytes = (num_bytes * repetitions)[:byte_length]

    return num_bytes

def hmac(key: str, message: str):
    opad = 0x5c
    ipad = 0x36
    blocksize = 64
    encoded_key = key.encode()
    encoded_opad = number_to_repeated_bytes(opad, blocksize)
    encoded_ipad = number_to_repeated_bytes(ipad, blocksize)

    if len(encoded_key) < blocksize:
        encoded_key = encoded_key.ljust(blocksize, b'\x00')
    if len(encoded_key) > blocksize:
        encoded_key = sha256(encoded_key).digest()

    key_opad = bytes([b1 ^ b2 for b1, b2 in zip(encoded_key, encoded_opad)])
    key_ipad = bytes([b1 ^ b2 for b1, b2 in zip(encoded_key, encoded_ipad)])

    digest = sha256(key_opad + sha256(key_ipad + message.encode()).digest()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode("utf-8")

def generate_jwt(username, admin):
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    payload = {
        "username": username,
        "admin": admin
    }

    encoded_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode('utf-8')).rstrip(b'=').decode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode('utf-8')).rstrip(b'=').decode("utf-8")

    signing_input = f"{encoded_header}.{encoded_payload}"

    key = os.getenv("HS256")
    if key is None:
        raise ValueError("Environment variable 'HS256' not set")

    signature = hmac(key, signing_input)

    jwt_token = f"{encoded_header}.{encoded_payload}.{signature}"
    return jwt_token

# Example usage
if __name__ == "__main__":
    token = generate_jwt("user123", True)
    print(f"Generated JWT: {token}")
