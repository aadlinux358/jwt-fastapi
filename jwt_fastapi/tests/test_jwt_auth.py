"""Jwt_fastapi auth test module."""
from typing import Optional
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import pytest
import jwt
from jwt.algorithms import get_default_algorithms
from jwt.algorithms import requires_cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

from jwt_fastapi.config import JWTConfig
from jwt_fastapi.jwt_auth import JWTFastAPI
from jwt_fastapi.jwt_auth import EnDec
from jwt_fastapi.models import AccessTokenCreate
from jwt_fastapi.models import RefreshTokenCreate
from jwt_fastapi.models import TokenType
from jwt_fastapi.models import RefreshTokenCreate
from jwt_fastapi.utils import JFAlgorithms

class GeneratRSA:
    def __init__(self, password: Optional[bytes] = None) -> None:
        self.password = password
        self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
                )
        enc = None
        if self.password is None:
            enc = NoEncryption()
        else:
            enc = BestAvailableEncryption(self.password)
        self.private_pem = self.private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=enc)

        self.public_key = self.private_key.public_key()
        self.public_pem = self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
                )

@pytest.fixture(scope="function")
def keys():
    return GeneratRSA()


def test_get_secret_key_for_symmetric_algorithm():
    config = JWTConfig(jf_algorithm="HS256", jf_secret_key="test")
    jf = JWTFastAPI(config=config)

    assert jf.get_secret_key() == "test"

def test_get_secret_key_for_asymmetric_algorithm():
    config = JWTConfig(
        jf_algorithm="RS256",
        jf_private_key='private',
        jf_public_key='public')
    jf = JWTFastAPI(config=config)

    assert jf.get_secret_key(endec=EnDec.ENCODE) == "private"
    assert jf.get_secret_key(endec=EnDec.DECODE) == "public"

def test_create_access_token_with_symmetric_algorithm(algorithms: JFAlgorithms):
    config = JWTConfig(
        jf_secret_key='my secret'
        )
    jf = JWTFastAPI(config=config)
    payload = AccessTokenCreate(
            sub=42,
            user_claims=dict(
                is_superuser=False,
                is_staff_user=True
                ),
            )
    token = jf.create_access_token(payload=payload)

    assert config.jf_secret_key, 'jf_secret_key not set'
    decoded_token = jwt.decode(
            jwt=token,
            key=config.jf_secret_key,
            algorithms=list(algorithms.symmetric)
            )
    assert decoded_token.get('token_type') == TokenType.ACCESS
    assert decoded_token.get('sub') == '42'
    assert decoded_token.get('exp')
    assert decoded_token.get('user_claims').get('is_superuser') is False
    assert decoded_token.get('user_claims').get('is_staff_user') is True


def test_create_access_token_with_asymmetric_algorithm(keys: GeneratRSA):
    config = JWTConfig(
        jf_algorithm='RS256',
        jf_private_key=keys.private_pem.decode(),
        jf_public_key=keys.public_pem.decode()
        )
    jf = JWTFastAPI(config=config)
    payload = AccessTokenCreate(
            sub=42,
            user_claims=dict(
                is_superuser=False,
                is_staff_user=True
                ),
            )
    token = jf.create_access_token(payload=payload)
    assert jf.config.jf_public_key
    decoded_token = jwt.decode(
            jwt=token,
            key=jf.config.jf_public_key,
            algorithms=list(requires_cryptography)
            )


def test_create_refresh_token_for_symmetric_algorithm(algorithms: JFAlgorithms):
    config = JWTConfig(
        jf_secret_key='my secret'
        )
    jf = JWTFastAPI(config=config)
    payload = RefreshTokenCreate(
            sub=42,
            user_claims=dict(
                is_superuser=False,
                is_staff_user=True
                ),
            )
    token = jf.create_refresh_token(payload=payload)

    assert config.jf_secret_key, 'jf_secret_key not set'
    decoded_token = jwt.decode(
            jwt=token,
            key=config.jf_secret_key,
            algorithms=list(algorithms.symmetric)
            )
    assert decoded_token.get('token_type') == TokenType.REFRESH
    assert decoded_token.get('sub') == '42'
    assert decoded_token.get('exp')
    assert decoded_token.get('user_claims').get('is_superuser') is False
    assert decoded_token.get('user_claims').get('is_staff_user') is True

def test_create_refresh_token_with_asymmetric_algorithm(
        keys: GeneratRSA,
        algorithms: JFAlgorithms):
    config = JWTConfig(
        jf_algorithm='RS256',
        jf_private_key=keys.private_pem.decode(),
        jf_public_key=keys.public_pem.decode()
        )
    jf = JWTFastAPI(config=config)
    payload = RefreshTokenCreate(
            sub=42,
            user_claims=dict(
                is_superuser=False,
                is_staff_user=True
                ),
            )
    token = jf.create_refresh_token(payload=payload)
    assert jf.config.jf_public_key
    decoded_token = jwt.decode(
            jwt=token,
            key=jf.config.jf_public_key,
            algorithms=list(algorithms.assymetric)
            )


def test_access_token_expires(algorithms):
    config = JWTConfig(jf_secret_key='my secret')
    jf = JWTFastAPI(config=config)

    payload = AccessTokenCreate(sub=42)
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 900
    token = jf.create_access_token(payload=payload)
    assert jf.config.jf_secret_key
    assert jwt.decode(
            jwt=token,
            key=jf.config.jf_secret_key,
            algorithms=algorithms.symmetric)['exp'] == expires_time
