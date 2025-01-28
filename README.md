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
