"""Jwt_fastapi config test module."""
from datetime import datetime
from datetime import timezone
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi import Depends
from fastapi.testclient import TestClient
import jwt
from jwt.algorithms import get_default_algorithms
from pydantic import ValidationError
from pydantic_settings import BaseSettings

from jwt_fastapi.config import TokenLocation, JWTConfig
from jwt_fastapi.jwt_auth import JWTFastAPI
from jwt_fastapi.models import AccessTokenCreate, RefreshTokenCreate
from jwt_fastapi.utils import JFAlgorithms


@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    # @app.get('/protected')
    # def protected(Authorize: AuthJWT = Depends()):
    #     Authorize.jwt_required()

    client = TestClient(app)
    return client


def test_default_config():
    config = JWTConfig(jf_secret_key='secret')
    assert config.jf_token_location == TokenLocation.HEADERS
    assert config.jf_secret_key == 'secret'
    assert config.jf_public_key is None
    assert config.jf_private_key is None
    assert config.jf_algorithm == "HS256"
    # assert config.jf_decode_algorithms is None
    # assert config.jf_decode_leeway == 0
    # assert config.jf_encode_issuer is None
    # assert config.jf_decode_issuer is None
    #  assert config.jf_decode_audience is None
    # assert config.jf_denylist_enabled is False
    # assert config.jf_denylist_token_checks == ('access','refresh')
    # assert config.jf_token_in_denylist_callback is None
    assert config.jf_header_name == "Authorization"
    assert config.jf_header_type == "Bearer"
    assert int(config.jf_access_token_expire_duration.total_seconds())== 900
    assert int(config.jf_refresh_token_expire_duration.total_seconds()) == 2592000

    # # option for create cookies

    # assert config.jf_access_cookie_key == "access_token_cookie"
    # assert config.jf_refresh_cookie_key == "refresh_token_cookie"
    # assert config.jf_access_cookie_path == "/"
    # assert config.jf_refresh_cookie_path == "/"
    # assert config.jf_cookie_max_age is None
    # assert config.jf_cookie_domain is None
    # assert config.jf_cookie_secure is False
    # assert config.jf_cookie_samesite is None

    # # option for double submit csrf protection

    # assert config.jf_cookie_csrf_protect is True
    # assert config.jf_access_csrf_cookie_key == "csrf_access_token"
    # assert config.jf_refresh_csrf_cookie_key == "csrf_refresh_token"
    # assert config.jf_access_csrf_cookie_path == "/"
    # assert config.jf_refresh_csrf_cookie_path == "/"
    # assert config.jf_access_csrf_header_name == "X-CSRF-Token"
    # assert config.jf_refresh_csrf_header_name == "X-CSRF-Token"
    # assert config.jf_csrf_methods == {'POST','PUT','PATCH','DELETE'}


def test_token_should_not_be_expired(algorithms: JFAlgorithms) -> None:
    class TokenNoExpire(BaseSettings):
        jf_secret_key: str = "testing"
        jf_access_token_expire_duration: timedelta = timedelta()  # 0 means no expire
        jf_refresh_token_expire_duration: timedelta = timedelta()

    config = TokenNoExpire()
    app_config = JWTConfig(**config.model_dump())
    jf = JWTFastAPI(config=app_config)

    access_token_data = AccessTokenCreate(sub=42)
    access_token = jf.create_access_token(access_token_data)
    assert "exp" not in jwt.decode(
        jwt=access_token,
        key="testing",
        algorithms=list(algorithms.symmetric)
    )

    refresh_token_data = RefreshTokenCreate(sub=42)

    refresh_token = jf.create_refresh_token(refresh_token_data)
    assert "exp" not in jwt.decode(
        jwt=refresh_token,
        key="testing",
        algorithms=list(algorithms.symmetric),
    )


def test_token_should_expire() -> None:
    class TokenExpire(BaseSettings):
        jf_secret_key: str = "testing"

    config = TokenExpire()
    app_config = JWTConfig(**config.model_dump())
    jf = JWTFastAPI(config=app_config)


    access_token_data = AccessTokenCreate(sub=42)
    access_token = jf.create_access_token(access_token_data)
    assert "exp" in jwt.decode(
        jwt=access_token,
        key="testing",
        algorithms=list(get_default_algorithms().keys()),
    )

    refresh_token_data = RefreshTokenCreate(sub=42)
    refresh_token = jf.create_refresh_token(refresh_token_data)
    assert "exp" in jwt.decode(
        jwt=refresh_token,
        key="testing",
        algorithms=list(get_default_algorithms().keys()),
    )


# def test_no_secret_key():

#     with pytest.raises(ValidationError, match=r"jf_secret_key"):
#         jf = JWTFastAPI(config=JWTConfig())

# def test_no_asymmetric_keys():

#     with pytest.raises(ValidationError) as exp:
#         config = JWTConfig(jf_algorithm='RS256')
#         jf = JWTFastAPI(config=config)
