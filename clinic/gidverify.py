import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError


# GOOGLE_CERTS_URL = 'https://googleapis.com'
GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
GOOGLE_ISSUERS = ['https://google.com', '://google.com']


def verify_google_id_token(id_token: str, client_id: str) -> dict:
    '''
    Validates a Google ID token manually using PyJWT.
    Returns the decoded token payload if valid, or raises an exception.
    '''
    try:
        # 1. Unverify headers first to extract the Key ID ('kid')
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get('kid')
        if not kid:
            raise InvalidTokenError('Missing 'kid' claim in token header.')

        # 2. Fetch Google's current public keys
        # Note: In production, cache this response to avoid HTTP calls on every request.
        response = requests.get(GOOGLE_CERTS_URL, timeout=5)
        response.raise_for_status()
        certs_data = response.json()

        # 3. Find the public key that matches our token's 'kid'
        public_key = None
        for key in certs_data.get('keys', []):
            if key.get('kid') == kid:
                # PyJWT can construct the public key directly from the JWK dict
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break

        if not public_key:
            raise InvalidTokenError('Public key not found for the given 'kid'.')

        # 4. Cryptographically decode and validate the token claims
        payload = jwt.decode(
            id_token,
            public_key,
            algorithms=['RS256'],
            audience=client_id,       # Verifies 'aud' claim matches your Client ID
            issuer=GOOGLE_ISSUERS,    # Verifies 'iss' claim matches Google
            options={'verify_aud': True, 'verify_iss': True, 'verify_exp': True}
        )

        # Token is valid; return user info payload
        return payload

    except ExpiredSignatureError:
        raise ValueError('Token has expired.')
    except InvalidSignatureError:
        raise ValueError('Token signature verification failed.')
    except InvalidTokenError as e:
        raise ValueError(f'Token is invalid: {str(e)}')
    except Exception as e:
        raise ValueError(f'An unexpected error occurred during verification: {str(e)}')

# ==========================================
# Example Usage:
# ==========================================
if __name__ == '__main__':
    MY_CLIENT_ID = 'YOUR_CLIENT_://googleusercontent.com'
    SAMPLE_TOKEN = 'YOUR_RECEIVED_ID_TOKEN'

    try:
        user_info = verify_google_id_token(SAMPLE_TOKEN, MY_CLIENT_ID)
        print('Verification Successful!')
        print(f'User Email: {user_info.get('email')}')
        print(f'Google User ID (sub): {user_info.get('sub')}')
    except ValueError as err:
        print(f'Verification Failed: {err}')

