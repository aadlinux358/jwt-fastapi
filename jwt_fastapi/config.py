"""Jwt_fastapi config module."""
from datetime import timedelta
from typing import Optional
from typing import Any
from typing import TypeAlias
from enum import StrEnum, auto

from jwt.algorithms import get_default_algorithms
from jwt.algorithms import requires_cryptography
from jwt.algorithms import has_crypto
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict
from pydantic import StrictInt, model_validator
from pydantic import StrictBool
from pydantic import StrictStr
from pydantic import Field
from pydantic import FieldValidationInfo
from pydantic import field_validator
from pydantic import field_serializer


class TokenLocation(StrEnum):
    """Token location enum."""

    HEADERS = auto()
    COOKIES = auto()


# ExpireTime: TypeAlias = timedelta | int | float


class JWTConfig(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True,
        str_strip_witespace=True,
        str_min_length=1,
    )
    jf_token_location: TokenLocation = TokenLocation.HEADERS
    jf_algorithm: StrictStr = Field(
        default="HS256", validate_default=True
    )
    jf_private_key: Optional[StrictStr] = Field(
        default=None,
        validate_default=True,
    )
    jf_public_key: Optional[StrictStr] = Field(default=None, validate_default=True)
    jf_secret_key: Optional[StrictStr] = Field(
        default=None, min_length=1, validate_default=True
    )
    # jf_decode_algorithms: Optional[]
    # jf_decode_leeway == 0
    # jf_encode_issuer is None
    # jf_decode_issuer is None
    # jf_decode_audience is None
    # jf_denylist_enabled is False
    # jf_denylist_token_checks == ('access','refresh')
    # jf_token_in_denylist_callback is None
    jf_header_name: Optional[StrictStr] = "Authorization"
    jf_header_type: Optional[StrictStr] = "Bearer"
    jf_access_token_expire_duration: timedelta = Field(
            default=timedelta(minutes=15),
            ge=0,
            validate_default=True,
            )
    jf_refresh_token_expire_duration: timedelta = Field(
            default=timedelta(days=30),
            ge=0,
            validate_default=True,
            )

    jf_access_cookie_key: Optional[StrictStr] = "access_token_cookie"
    jf_refresh_cookie_key: Optional[StrictStr] = "refresh_token_cookie"
    jf_access_cookie_path: Optional[StrictStr] = "/"
    jf_refresh_cookie_path: Optional[StrictStr] = "/"
    jf_cookie_max_age: Optional[StrictInt] = None
    jf_cookie_domain: Optional[StrictStr] = None
    jf_cookie_secure: Optional[StrictBool] = False
    jf_cookie_samesite: Optional[StrictStr] = None

    # # option for double submit csrf protection

    jf_csrf_protect_cookies: Optional[StrictBool] = True
    jf_access_csrf_cookie_key: Optional[StrictStr] = "csrf_access_token"
    jf_refresh_csrf_cookie_key: Optional[StrictStr] = "csrf_refresh_token"
    jf_access_csrf_cookie_path: Optional[StrictStr] = "/"
    jf_refresh_csrf_cookie_path: Optional[StrictStr] = "/"
    jf_access_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    jf_refresh_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    jf_csrf_methods: Optional[set[StrictStr]] = {"POST", "PUT", "PATCH", "DELETE"}

    @field_validator("jf_algorithm", mode="before")
    @classmethod
    def is_valid_algorithm(cls, v: StrictStr, info: FieldValidationInfo) -> StrictStr:
        if v not in get_default_algorithms():
            raise ValueError(f"Algorithm {v} is not supported.")

        if v in requires_cryptography and not has_crypto:  # asymmetric algorithms
            msg = "Missing dependencies for using asymmetric algorithms."
            cmd = "run pip install `jwt_fastapi[asymmetric]`"
            raise ValueError(f"{msg} {cmd}")

        return v

    @field_validator("jf_secret_key", mode="before")
    @classmethod
    def is_valid_secret_key(cls, v: str, info: FieldValidationInfo):
        symmetric_algorithms = set(get_default_algorithms()) - requires_cryptography
        alg = info.data.get("jf_algorithm")
        if alg is None:
            raise ValueError("jf_algorithm not set.")
        if alg in symmetric_algorithms:
            if v is None:
                raise ValueError(
                    f"jf_secret_key must be set when using symetric algorithm `{alg}`"
                )
        return v

    # @field_serializer(
    #         'jf_access_token_expire_duration',
    #         'jf_refresh_token_expire_duration')
    # def serialize_timedeltas(self, td: timedelta, _info):
    #     return int(td.total_seconds())

    # @field_validator(
    #     "jf_access_token_expire_duration",
    #     "jf_refresh_token_expire_duration",
    #     mode="before",
    # )
    # @classmethod
    # def validate_expire_time(cls, v: ExpireTime) -> Optional[int]:
    #     if isinstance(v, timedelta):
    #         t = int(v.total_seconds())
    #         return t or None
    #     return int(timedelta(minutes=v).total_seconds()) or None

    @model_validator(mode='after')
    def check_asymmetric_keys(self) -> 'JWTConfig':
        if self.jf_algorithm in requires_cryptography:
            if not (self.jf_private_key or self.jf_public_key):
                raise ValueError(
        "When using assymetric algorithm, jf_private_key or jf_public_key must be set."
                        )
        return self
